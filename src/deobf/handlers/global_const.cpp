#include "global_const.h"
#include "../../common/ida_memory.h"

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

    deobf::log("[global_const] Inlined %d constants\n", total_changes);
    return total_changes;
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

    return 0;
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

    // Check if it's in a const data section
    if ( !is_const_data(gv_addr) ) 
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
