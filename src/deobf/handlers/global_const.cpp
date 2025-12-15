#include "global_const.h"

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool global_const_handler_t::detect(mbl_array_t *mba) {
    if (!mba)
        return false;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            global_const_t gc;
            if (is_global_const_load(ins, &gc)) {
                return true;
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int global_const_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    deobf::log("[global_const] Starting global constant inlining\n");

    int total_changes = 0;

    auto global_consts = find_global_consts(mba);
    deobf::log("[global_const] Found %zu global constants to inline\n", global_consts.size());

    for (const auto &gc : global_consts) {
        for (int i = 0; i < mba->qty; i++) {
            mblock_t *blk = mba->get_mblock(i);
            if (!blk)
                continue;

            for (minsn_t *ins = blk->head; ins; ins = ins->next) {
                if (ins == gc.insn) {
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
    if (!ins)
        return 0;

    global_const_t gc;
    if (is_global_const_load(ins, &gc)) {
        return replace_with_constant(blk, ins, gc);
    }

    return 0;
}

//--------------------------------------------------------------------------
// Find global constants
//--------------------------------------------------------------------------
std::vector<global_const_handler_t::global_const_t>
global_const_handler_t::find_global_consts(mbl_array_t *mba) {
    std::vector<global_const_t> result;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            global_const_t gc;
            if (is_global_const_load(ins, &gc)) {
                result.push_back(gc);
            }
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Check if instruction loads from a constant global
//--------------------------------------------------------------------------
bool global_const_handler_t::is_global_const_load(minsn_t *ins, global_const_t *out) {
    if (!ins)
        return false;

    // We're looking for mov instructions that load from a global
    // Pattern: mov dst, gv  (where gv is a global variable)
    if (ins->opcode != m_mov && ins->opcode != m_ldx)
        return false;

    ea_t gv_addr = BADADDR;
    int size = 0;
    mop_t *gv_mop = nullptr;

    // Check for direct global reference in left operand
    if (ins->l.t == mop_v) {
        gv_addr = ins->l.g;
        size = ins->l.size;
        gv_mop = &ins->l;
    }
    // Check for load from global (ldx pattern)
    else if (ins->opcode == m_ldx) {
        // ldx dst, seg, addr - check if addr is a global
        if (ins->r.t == mop_v) {
            gv_addr = ins->r.g;
            size = ins->d.size;
            gv_mop = &ins->r;
        }
    }

    if (gv_addr == BADADDR || size <= 0 || size > 8)
        return false;

    // Verify it's a data location, not code
    flags64_t flags = get_flags(gv_addr);
    if (is_code(flags))
        return false;

    // Check if it's in a const data section
    if (!is_const_data(gv_addr))
        return false;

    // Read the value
    uint64_t value = read_global_value(gv_addr, size);

    // Skip if value looks like a pointer (we don't want to inline pointers)
    if (looks_like_pointer(value, size))
        return false;

    if (out) {
        out->insn = ins;
        out->gv_mop = gv_mop;
        out->gv_addr = gv_addr;
        out->value = value;
        out->size = size;
    }

    return true;
}

//--------------------------------------------------------------------------
// Check if address is in a read-only/const data section
//--------------------------------------------------------------------------
bool global_const_handler_t::is_const_data(ea_t addr) {
    segment_t *seg = getseg(addr);
    if (!seg)
        return false;

    // Check segment name for common const data patterns
    qstring seg_name;
    get_segm_name(&seg_name, seg);

    // Common read-only section names
    if (seg_name == "__const" ||
        seg_name == ".rodata" ||
        seg_name == ".rdata" ||
        seg_name == "__DATA_CONST" ||
        seg_name == "__cstring" ||
        seg_name == "__cfstring") {
        return true;
    }

    // Also accept __data and .data for now - constants can be there too
    // But be more conservative
    if (seg_name == "__data" || seg_name == ".data") {
        // Check if the value has xrefs that suggest it's not modified
        xrefblk_t xb;
        bool has_write_xref = false;
        for (bool ok = xb.first_to(addr, XREF_ALL); ok; ok = xb.next_to()) {
            if (xb.type == dr_W) {
                has_write_xref = true;
                break;
            }
        }
        return !has_write_xref;
    }

    // Check segment permissions if available
    if ((seg->perm & SEGPERM_WRITE) == 0) {
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Heuristic to detect pointer values
//--------------------------------------------------------------------------
bool global_const_handler_t::looks_like_pointer(uint64_t val, int size) {
    if (size < 4)
        return false;

    // 0 could be NULL pointer but also a valid constant
    if (val == 0)
        return false;

    // Check if it falls within any segment
    if (getseg((ea_t)val) != nullptr)
        return true;

    // Common pointer patterns for 64-bit
    if (size == 8) {
        // Typical macOS/iOS ASLR range (0x1XXXXXXXXXX)
        if ((val >> 40) == 0x1)
            return true;
        // Linux typical user-space ranges (0x5XXXXXXXXX, 0x7XXXXXXXXX)
        uint64_t top_nibble = val >> 44;
        if (top_nibble == 0x5 || top_nibble == 0x7)
            return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Read value from global
//--------------------------------------------------------------------------
uint64_t global_const_handler_t::read_global_value(ea_t addr, int size) {
    uint64_t val = 0;

    switch (size) {
        case 1:
            val = get_byte(addr);
            break;
        case 2:
            val = get_word(addr);
            break;
        case 4:
            val = get_dword(addr);
            break;
        case 8:
            val = get_qword(addr);
            break;
        default:
            get_bytes(&val, size, addr);
            break;
    }

    return val;
}

//--------------------------------------------------------------------------
// Replace load with constant
//--------------------------------------------------------------------------
int global_const_handler_t::replace_with_constant(mblock_t *blk, minsn_t *ins,
    const global_const_t &gc) {

    if (!ins)
        return 0;

    // Transform: mov dst, gv  ->  mov dst, immediate
    // Or:        ldx dst, seg, gv -> mov dst, immediate

    ins->opcode = m_mov;
    ins->l.make_number(gc.value, gc.size);
    ins->r.erase();

    return 1;
}
