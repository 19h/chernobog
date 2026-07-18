#include "global_const.h"
#include "../analysis/arch_utils.h"
#include "../../common/ida_memory.h"
#include "../../common/warn_off.h"
#include <fixup.hpp>
#include "../../common/warn_on.h"

#include <map>
#include <tuple>

namespace {

using writable_key_t = std::tuple<ssize_t, ea_t, int>;
using writable_object_key_t = std::tuple<ssize_t, ea_t, ea_t>;
std::map<writable_key_t, bool> s_writable_classification;
std::map<writable_object_key_t, bool> s_writable_object_classification;
std::map<writable_key_t, bool> s_write_only_classification;

constexpr asize_t MAX_WRITABLE_OBJECT_SIZE = 4096;
constexpr asize_t MAX_WRITABLE_ANCHOR_DISTANCE = 64;

void global_const_debug(const char *format, ...)
{
    if ( !deobf::debug_enabled() )
        return;
    va_list arguments;
    va_start(arguments, format);
    deobf::debug_vlog("/tmp/chernobog_global_const_debug.log",
                      format, arguments);
    va_end(arguments);
}

int writable_const_mode()
{
    static int cached = -1;
    if ( cached == -1 )
    {
        qstring value;
        cached = 0;
        if ( qgetenv("CHERNOBOG_WRITABLE_CONST", &value) && !value.empty() )
        {
            if ( value[0] == '2' )
                cached = 2;
            else if ( value[0] == '1' )
                cached = 1;
        }
    }
    return cached;
}

bool dead_global_store_mode_enabled()
{
    static int cached = -1;
    if ( cached == -1 )
    {
        qstring value;
        cached = qgetenv("CHERNOBOG_DEAD_GLOBAL_STORES", &value)
              && !value.empty() && value[0] == '1' ? 1 : 0;
    }
    return cached == 1;
}

// Classify the non-register operand that owns a data xref.  On ARM64 this
// distinguishes ADRP/LDR address use (CF_USE2) from STR memory modification
// (CF_CHG2), rather than confusing the LDR destination register with a write
// to the referenced global.
bool xref_instruction_access(ea_t from, bool *reads, bool *writes)
{
    if ( reads )
        *reads = false;
    if ( writes )
        *writes = false;
    if ( !is_code(get_flags(from)) )
        return false;

    insn_t instruction;
    if ( decode_insn(&instruction, from) <= 0 )
        return false;

    const uint32 feature = instruction.get_canon_feature(PH);
    bool found_address_operand = false;
    for ( uint operand_index = 0; operand_index < UA_MAXOP; ++operand_index )
    {
        const op_t &operand = instruction.ops[operand_index];
        if ( operand.type == o_void )
            break;
        if ( operand.type == o_reg )
            continue;

        if ( has_cf_use(feature, operand_index) )
        {
            found_address_operand = true;
            if ( reads )
                *reads = true;
        }
        if ( has_cf_chg(feature, operand_index) )
        {
            found_address_operand = true;
            if ( writes )
                *writes = true;
        }
    }
    return found_address_operand;
}

} // namespace

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool global_const_handler_t::detect(mbl_array_t *mba)
{
    if ( !mba ) 
        return false;

    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk ) 
            continue;

        for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
            global_const_t gc;
            if ( is_global_const_load(ins, &gc) ) {
                return true;
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int global_const_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx ) 
        return 0;

    deobf::log("[global_const] Starting global constant inlining\n");

    int total_changes = 0;

    auto global_consts = find_global_consts(mba);
    deobf::log("[global_const] Found %zu global constants to inline\n", global_consts.size());

    for ( const auto &gc : global_consts ) {
        for ( int i = 0; i < mba->qty; ++i ) {
            mblock_t *blk = mba->get_mblock(i);
            if ( !blk ) 
                continue;

            for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
                if ( ins == gc.insn ) {
                    total_changes += replace_with_constant(blk, ins, gc);
                    deobf::log("[global_const] Inlined constant at %a: 0x%llx\n",
                              gc.gv_addr, (unsigned long long)gc.value);
                    break;
                }
            }
        }
    }

    total_changes += remove_write_only_stores(mba);

    deobf::log("[global_const] Inlined %d constants\n", total_changes);
    return total_changes;
}

//--------------------------------------------------------------------------
// Remove direct stores to closed-world write-only scalar sinks.
//--------------------------------------------------------------------------
int global_const_handler_t::remove_write_only_stores(mbl_array_t *mba)
{
    if ( !mba || !dead_global_store_mode_enabled() )
        return 0;

    int changes = 0;
    for ( int block_index = 0; block_index < mba->qty; ++block_index )
    {
        mblock_t *block = mba->get_mblock(block_index);
        if ( !block )
            continue;
        for ( minsn_t *instruction = block->head;
              instruction;
              instruction = instruction->next )
        {
            ea_t address = BADADDR;
            int size = 0;
            if ( instruction->opcode == m_mov && instruction->d.t == mop_v )
            {
                address = instruction->d.g;
                size = instruction->d.size;
            }
            else if ( instruction->opcode == m_stx
                   && instruction->d.t == mop_v )
            {
                address = instruction->d.g;
                size = instruction->l.size;
            }
            if ( !is_direct_write_only_data(address, size) )
                continue;

            block->make_nop(instruction);
            ++changes;
        }
    }

    if ( changes > 0 )
    {
        deobf::log(
            "[global_const] Removed %d closed-world write-only global stores\n",
            changes);
    }
    return changes;
}

//--------------------------------------------------------------------------
// Instruction-level simplification
//--------------------------------------------------------------------------
int global_const_handler_t::simplify_insn(mblock_t *blk, minsn_t *ins, deobf_ctx_t *ctx) {
    if ( !ins ) 
        return 0;

    global_const_t gc;
    if ( is_global_const_load(ins, &gc) ) {
        return replace_with_constant(blk, ins, gc);
    }

    return simplify_value_instruction(blk, ins, 0);
}

//--------------------------------------------------------------------------
// Recursively inline globals used as scalar values in expression trees.
//--------------------------------------------------------------------------
int global_const_handler_t::simplify_value_operand(
    mblock_t *blk, mop_t *operand, int depth)
{
    if ( !operand || depth > 32 )
        return 0;
    if ( operand->t == mop_d && operand->d )
        return simplify_value_instruction(blk, operand->d, depth + 1);
    if ( operand->t != mop_v || operand->g == BADADDR
      || operand->size <= 0 || operand->size > 8 )
    {
        return 0;
    }

    const ea_t address = operand->g;
    const int size = operand->size;
    if ( is_code(get_flags(address))
      || (!is_const_data(address)
       && !is_write_free_writable_data(address, size)) )
    {
        return 0;
    }
    const std::optional<uint64_t> value = read_global_value(address, size);
    if ( !value || looks_like_pointer(*value, size) )
        return 0;

    operand->make_number(*value, size);
    if ( blk )
        blk->mark_lists_dirty();
    return 1;
}

int global_const_handler_t::simplify_value_instruction(
    mblock_t *blk, minsn_t *ins, int depth)
{
    if ( !ins || depth > 32 )
        return 0;

    global_const_t direct_load;
    if ( is_global_const_load(ins, &direct_load) )
        return replace_with_constant(blk, ins, direct_load);

    if ( ins->opcode == m_stx )
    {
        // l is the stored value; r/d are selector/address operands.
        return simplify_value_operand(blk, &ins->l, depth + 1);
    }

    // Fail closed: recurse only through integer opcodes whose l/r fields are
    // scalar values by Hex-Rays' mcode contract.  Loads, branches, calls,
    // floating-point operations, and extension opcodes are not admitted by
    // an implicit default case.
    switch ( ins->opcode )
    {
        case m_mov:
        case m_neg:
        case m_lnot:
        case m_bnot:
        case m_xds:
        case m_xdu:
        case m_low:
        case m_high:
            return simplify_value_operand(blk, &ins->l, depth + 1);

        case m_add:
        case m_sub:
        case m_mul:
        case m_udiv:
        case m_sdiv:
        case m_umod:
        case m_smod:
        case m_or:
        case m_and:
        case m_xor:
        case m_shl:
        case m_shr:
        case m_sar:
        case m_cfadd:
        case m_ofadd:
        case m_cfshl:
        case m_cfshr:
        case m_sets:
        case m_seto:
        case m_setp:
        case m_setnz:
        case m_setz:
        case m_setae:
        case m_setb:
        case m_seta:
        case m_setbe:
        case m_setg:
        case m_setge:
        case m_setl:
        case m_setle:
            return simplify_value_operand(blk, &ins->l, depth + 1)
                 + simplify_value_operand(blk, &ins->r, depth + 1);

        default:
            return 0;
    }
}

//--------------------------------------------------------------------------
// Find global constants
//--------------------------------------------------------------------------
std::vector<global_const_handler_t::global_const_t>
global_const_handler_t::find_global_consts(mbl_array_t *mba)
{
    std::vector<global_const_t> result;

    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk ) 
            continue;

        for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
            global_const_t gc;
            if ( is_global_const_load(ins, &gc) ) {
                result.push_back(gc);
            }
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Check if instruction loads from a constant global
//--------------------------------------------------------------------------
bool global_const_handler_t::is_global_const_load(minsn_t *ins, global_const_t *out)
{
    if ( !ins ) 
        return false;

    // We're looking for mov instructions that load from a global
    // Pattern: mov dst, gv  (where gv is a global variable)
    if ( ins->opcode != m_mov && ins->opcode != m_ldx ) 
        return false;


    ea_t gv_addr = BADADDR;
    int size = 0;

    // Check for direct global reference in left operand
    if ( ins->opcode == m_mov && ins->l.t == mop_v ) {
        gv_addr = ins->l.g;
        size = ins->l.size;
    }
    // Check for load from global (ldx pattern)
    else if ( ins->opcode == m_ldx ) {
        // ldx dst, seg, addr - check if addr is a global
        if ( ins->r.t == mop_v ) {
            gv_addr = ins->r.g;
            size = ins->d.size;
        }
        // Also check for address-of global: ldx dst, seg, &global
        // At early maturity, globals may be wrapped in mop_a
        else if ( ins->r.t == mop_a && ins->r.a && ins->r.a->t == mop_v ) {
            gv_addr = ins->r.a->g;
            size = ins->d.size;
        }
        // Check for immediate address (mop_n) which might be a global
        else if ( ins->r.t == mop_n && ins->r.nnn ) {
            ea_t addr = (ea_t)ins->r.nnn->value;
            // Verify it's a valid data address
            if ( getseg(addr) != nullptr ) {
                gv_addr = addr;
                size = ins->d.size;
            }
        }
        // Check for computed address (mop_d) - result of add/sub with constants
        // Pattern: ldx dst, seg, (base + offset) where base is a global address
        else if ( ins->r.t == mop_d && ins->r.d ) {
            minsn_t *addr_ins = ins->r.d;
            // Check for add with constant offset: add result, base, offset
            if ( addr_ins->opcode == m_add ) {
                ea_t base_addr = BADADDR;
                uint64_t offset = 0;

                // Check if left is global/number and right is number
                if ( addr_ins->l.t == mop_v ) {
                    base_addr = addr_ins->l.g;
                } else if ( addr_ins->l.t == mop_n && addr_ins->l.nnn ) {
                    base_addr = (ea_t)addr_ins->l.nnn->value;
                } else if ( addr_ins->l.t == mop_a && addr_ins->l.a && addr_ins->l.a->t == mop_v ) {
                    base_addr = addr_ins->l.a->g;
                }

                if ( addr_ins->r.t == mop_n && addr_ins->r.nnn ) {
                    offset = addr_ins->r.nnn->value;
                } else {
                    base_addr = BADADDR;
                }

                if ( base_addr != BADADDR && getseg(base_addr) != nullptr
                  && offset <= uint64_t(BADADDR - base_addr - 1) ) {
                    gv_addr = base_addr + static_cast<ea_t>(offset);
                    size = ins->d.size;
                }
            }
        }
    }

    if ( gv_addr == BADADDR || size <= 0 || size > 8 ) 
        return false;

    // Verify it's a data location, not code
    flags64_t flags = get_flags(gv_addr);
    if ( is_code(flags) ) 
        return false;

    // Writable storage remains excluded by default.  The explicit opt-in is
    // limited to loaded, write-free scalar seeds with no loader fixups.
    if ( !is_const_data(gv_addr)
      && !is_write_free_writable_data(gv_addr, size) )
        return false;

    // Read the value
    const std::optional<uint64_t> value = read_global_value(gv_addr, size);
    if ( !value )
        return false;

    // Skip if value looks like a pointer (we don't want to inline pointers)
    if ( looks_like_pointer(*value, size) )
        return false;

    if ( out ) {
        out->insn = ins;
        out->gv_addr = gv_addr;
        out->value = *value;
        out->size = size;
    }

    return true;
}

//--------------------------------------------------------------------------
// Check if address is in a read-only/const data section
//--------------------------------------------------------------------------
bool global_const_handler_t::is_const_data(ea_t addr)
{
    segment_t *seg = getseg(addr);
    if ( !seg ) 
        return false;

    // Names and the absence of static write xrefs do not prove immutability:
    // another function, the loader, or an indirect store can still mutate a
    // writable segment.  Only inline bytes whose segment permissions are
    // read-only in the loaded database.
    return (seg->perm & SEGPERM_WRITE) == 0;
}

//--------------------------------------------------------------------------
// Check whether a writable scalar is statically read-only in this IDB.
//--------------------------------------------------------------------------
bool global_const_handler_t::is_write_free_writable_data(ea_t addr, int size)
{
    const int mode = writable_const_mode();
    if ( mode == 0 || addr == BADADDR
      || (size != 1 && size != 2 && size != 4 && size != 8)
      || addr % static_cast<ea_t>(size) != 0 )
    {
        return false;
    }

    const writable_key_t key(get_dbctx_id(), addr, size);
    const auto cached = s_writable_classification.find(key);
    if ( cached != s_writable_classification.end() )
        return cached->second;

    bool admitted = false;
    segment_t *segment = getseg(addr);
    if ( segment && (segment->perm & SEGPERM_WRITE) != 0
      && !is_code(get_flags(addr)) && is_loaded(addr) )
    {
        ea_t object_start = addr;
        ea_t object_end = addr + static_cast<ea_t>(size);
        const ea_t item_start = get_item_head(addr);
        const ea_t item_end = get_item_end(addr);
        if ( item_start != BADADDR && item_end > item_start
          && is_data(get_flags(item_start))
          && item_end - item_start <= MAX_WRITABLE_OBJECT_SIZE
          && addr >= item_start
          && static_cast<ea_t>(size) <= item_end - addr )
        {
            object_start = item_start;
            object_end = item_end;
        }

        // Some Mach-O byte arrays are represented by IDA as a named first
        // byte followed by undefined interior bytes. An offset LDRB then has
        // no exact xref at the interior EA. In tier 2, admit a bounded prefix
        // model anchored at the nearest preceding referenced byte. A symbol
        // or fixup without reference evidence terminates the search, and the
        // normal complete-range scan below still rejects a write at any
        // referenced byte between the anchor and the scalar.
        if ( mode >= 2 && size == 1 && object_start == addr
          && object_end == addr + 1 )
        {
            xrefblk_t exact_xref;
            if ( !exact_xref.first_to(addr, XREF_DATA) )
            {
                for ( asize_t distance = 1;
                      distance <= MAX_WRITABLE_ANCHOR_DISTANCE
                   && static_cast<ea_t>(distance) <= addr - segment->start_ea;
                      ++distance )
                {
                    const ea_t candidate = addr - static_cast<ea_t>(distance);
                    const flags64_t flags = get_flags(candidate);
                    if ( !is_loaded(candidate) || is_code(flags)
                      || exists_fixup(candidate) )
                    {
                        break;
                    }

                    xrefblk_t anchor_xref;
                    if ( anchor_xref.first_to(candidate, XREF_DATA) )
                    {
                        object_start = candidate;
                        object_end = addr + 1;
                        break;
                    }
                    if ( has_any_name(flags) )
                        break;
                }
            }
        }

        // Interior array elements depend on base-object xrefs rather than an
        // exact xref at every byte. Keep that stronger model in tier 2 and
        // classify the complete bounded data item so a write to any element
        // rejects every load-time fold from the object.
        const bool object_model = object_start != addr
                               || object_end != addr + static_cast<ea_t>(size);
        if ( object_model && mode < 2 )
        {
            s_writable_classification.emplace(key, false);
            return false;
        }

        // A byte array can contribute one scalar load per element. Cache the
        // whole-item proof separately so classifying N interior elements is
        // O(item_size + xrefs), rather than O(N * item_size).
        const writable_object_key_t object_key(
            get_dbctx_id(), object_start, object_end);
        if ( object_model )
        {
            const auto object_cached =
                s_writable_object_classification.find(object_key);
            if ( object_cached != s_writable_object_classification.end() )
            {
                admitted = object_cached->second;
                s_writable_classification.emplace(key, admitted);
                return admitted;
            }
        }

        bool has_fixup = false;
        for ( ea_t cursor = object_start; cursor < object_end; ++cursor )
        {
            if ( exists_fixup(cursor) )
            {
                has_fixup = true;
                break;
            }
        }

        if ( !has_fixup )
        {
            bool saw_read = false;
            bool saw_write = false;
            bool unclassified_reference = false;
            bool address_taken = object_model;
            for ( ea_t target = object_start;
                  target < object_end && !unclassified_reference && !saw_write;
                  ++target )
            {
                xrefblk_t xref;
                for ( bool ok = xref.first_to(target, XREF_DATA);
                      ok;
                      ok = xref.next_to() )
                {
                    bool reads = false;
                    bool writes = false;
                    if ( is_code(get_flags(xref.from)) )
                    {
                        // IDA emits dr_O for address construction (for
                        // example, ADRP) and dr_R/dr_W for the actual load or
                        // store.  Treating every CF_USE address operand as a
                        // read would accidentally admit an escaped scalar in
                        // tier 1.
                        if ( xref.type == dr_O )
                        {
                            address_taken = true;
                            continue;
                        }
                        if ( xref.type != dr_R && xref.type != dr_W )
                        {
                            unclassified_reference = true;
                            break;
                        }
                        if ( !xref_instruction_access(
                                xref.from, &reads, &writes) )
                        {
                            unclassified_reference = true;
                            break;
                        }
                        if ( (xref.type == dr_R && !reads)
                          || (xref.type == dr_W && !writes) )
                        {
                            unclassified_reference = true;
                            break;
                        }
                        saw_read |= xref.type == dr_R;
                        saw_write |= xref.type == dr_W;
                        if ( saw_write )
                            break;
                        continue;
                    }

                    // A non-code reference materializes the scalar/object's
                    // address in data. Some loaders retain a fixup here and
                    // others expose only the resolved data xref. Tier 1
                    // rejects either escape. Tier 2 admits either encoding
                    // under its explicit no-indirect-mutation assumption.
                    fixup_data_t fixup;
                    if ( mode >= 2
                      || (get_fixup(&fixup, xref.from) && !fixup.is_unused()) )
                    {
                        address_taken = true;
                        continue;
                    }

                    unclassified_reference = true;
                    break;
                }
            }
            if ( address_taken && mode < 2 )
                unclassified_reference = true;
            // The scalar classifier is called only from a decoded load. For
            // an interior object element, IDA commonly records only the base
            // address construction and no dr_R at the element EA; that caller
            // load supplies the missing read evidence in tier 2.
            const bool caller_proves_object_read = mode >= 2 && object_model;
            admitted = (saw_read || caller_proves_object_read)
                    && !saw_write && !unclassified_reference;
            if ( admitted && address_taken )
            {
                deobf::log_verbose(
                    "[global_const] Tier-2 admitted address-taken writable "
                    "object %a..%a for scalar %a (%d bytes)\n",
                    object_start, object_end, addr, size);
            }
        }

        if ( object_model )
            s_writable_object_classification.emplace(object_key, admitted);
    }

    s_writable_classification.emplace(key, admitted);
    if ( admitted )
    {
        deobf::log_verbose(
            "[global_const] Admitted write-free writable scalar at %a (%d bytes)\n",
            addr, size);
    }
    return admitted;
}

//--------------------------------------------------------------------------
// Check whether all exact IDB references classify as direct writes.
//--------------------------------------------------------------------------
bool global_const_handler_t::is_direct_write_only_data(ea_t addr, int size)
{
    if ( !dead_global_store_mode_enabled() || addr == BADADDR
      || (size != 1 && size != 2 && size != 4 && size != 8)
      || addr % static_cast<ea_t>(size) != 0 )
    {
        return false;
    }

    const writable_key_t key(get_dbctx_id(), addr, size);
    const auto cached = s_write_only_classification.find(key);
    if ( cached != s_write_only_classification.end() )
        return cached->second;

    bool admitted = false;
    const segment_t *segment = getseg(addr);
    const flags64_t flags = get_flags(addr);
    global_const_debug(
        "sink candidate=%llX size=%d seg=%p perm=%d code=%d user=%d loaded=%d\n",
        static_cast<unsigned long long>(addr), size,
        static_cast<const void *>(segment), segment ? segment->perm : -1,
        is_code(flags) ? 1 : 0, has_user_name(flags) ? 1 : 0,
        is_loaded(addr) ? 1 : 0);
    if ( segment && (segment->perm & SEGPERM_WRITE) != 0
      && (segment->perm & SEGPERM_EXEC) == 0
      && !is_code(flags) && !has_user_name(flags) && is_loaded(addr) )
    {
        bool has_fixup = false;
        for ( int offset = 0; offset < size; ++offset )
        {
            if ( exists_fixup(addr + static_cast<ea_t>(offset)) )
            {
                has_fixup = true;
                break;
            }
        }

        if ( !has_fixup )
        {
            bool saw_write = false;
            bool rejected = false;
            xrefblk_t xref;
            for ( bool ok = xref.first_to(addr, XREF_DATA);
                  ok;
                  ok = xref.next_to() )
            {
                global_const_debug(
                    "  xref from=%llX type=%d from_code=%d\n",
                    static_cast<unsigned long long>(xref.from), xref.type,
                    is_code(get_flags(xref.from)) ? 1 : 0);
                if ( !is_code(get_flags(xref.from)) )
                {
                    rejected = true;
                    break;
                }
                if ( xref.type == dr_W )
                {
                    saw_write = true;
                    continue;
                }
                if ( xref.type == dr_O )
                {
                    // Address materialization is paired with the exact dr_W
                    // store reference.  Admit only the architecture's proven
                    // effective-address instruction, not an arbitrary decoded
                    // instruction that happens to own an offset xref.
                    insn_t instruction;
                    if ( decode_insn(&instruction, xref.from) <= 0 )
                    {
                        rejected = true;
                        break;
                    }
                    if ( !arch::is_lea_insn(instruction.itype) )
                    {
                        rejected = true;
                        break;
                    }
                    continue;
                }

                // dr_R and every unknown data-reference kind are observable.
                rejected = true;
                break;
            }
            admitted = saw_write && !rejected;
        }
    }

    global_const_debug("  sink result=%d\n", admitted ? 1 : 0);
    s_write_only_classification.emplace(key, admitted);
    return admitted;
}

void global_const_handler_t::clear_cache()
{
    s_writable_classification.clear();
    s_writable_object_classification.clear();
    s_write_only_classification.clear();
}

//--------------------------------------------------------------------------
// Share the exact scalar-admission proof with native pre-lift analysis.
//--------------------------------------------------------------------------
std::optional<uint64_t> global_const_handler_t::read_admitted_scalar(
    ea_t addr, int size)
{
    if ( addr == BADADDR || !chernobog::bitvector::valid_byte_width(size)
      || is_code(get_flags(addr)) )
    {
        return std::nullopt;
    }
    bool has_fixup = false;
    for ( int offset = 0; offset < size && !has_fixup; ++offset )
        has_fixup = exists_fixup(addr + static_cast<ea_t>(offset));
    if ( has_fixup
      || (!is_const_data(addr) && !is_write_free_writable_data(addr, size)) )
    {
        return std::nullopt;
    }
    const std::optional<uint64_t> value = read_global_value(addr, size);
    return value && !looks_like_pointer(*value, size)
        ? value : std::nullopt;
}

//--------------------------------------------------------------------------
// Heuristic to detect pointer values
//--------------------------------------------------------------------------
bool global_const_handler_t::looks_like_pointer(uint64_t val, int size)
{
    if ( size < 4 ) 
        return false;

    // 0 could be NULL pointer but also a valid constant
    if ( val == 0 ) 
        return false;

    // Check if it falls within any segment
    if ( getseg((ea_t)val) != nullptr ) 
        return true;

    // Common pointer patterns for 64-bit
    if ( size == 8 ) {
        // Typical macOS/iOS ASLR range (0x1XXXXXXXXXX)
        if ( (val >> 40) == 0x1 ) 
            return true;
        // Linux typical user-space ranges (0x5XXXXXXXXX, 0x7XXXXXXXXX)
        uint64_t top_nibble = val >> 44;
        if ( top_nibble == 0x5 || top_nibble == 0x7 ) 
            return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Read value from global
//--------------------------------------------------------------------------
std::optional<uint64_t> global_const_handler_t::read_global_value(ea_t addr, int size)
{
    return chernobog::ida_memory::read_integer(addr, size);
}

//--------------------------------------------------------------------------
// Replace load with constant
//--------------------------------------------------------------------------
int global_const_handler_t::replace_with_constant(mblock_t *blk, minsn_t *ins,
    const global_const_t &gc)
    {

    if ( !ins ) 
        return 0;

    // Transform: mov dst, gv  ->  mov dst, immediate
    // Or:        ldx dst, seg, gv -> mov dst, immediate

    ins->opcode = m_mov;
    ins->l.make_number(gc.value, gc.size);
    ins->r.erase();
    if ( blk )
        blk->mark_lists_dirty();

    return 1;
}
