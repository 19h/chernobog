#include "const_decrypt.h"

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool const_decrypt_handler_t::detect(mbl_array_t *mba) {
    if (!mba)
        return false;

    // Look for XOR instructions with global variable operands
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            encrypted_const_t ec;
            if (is_const_encryption_pattern(ins, &ec)) {
                return true;
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int const_decrypt_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    deobf::log("[const_decrypt] Starting constant decryption\n");

    int total_changes = 0;

    // Find all encrypted constant patterns
    auto encrypted_consts = find_encrypted_consts(mba);
    deobf::log("[const_decrypt] Found %zu encrypted constants\n", encrypted_consts.size());

    // Replace each with the decrypted value
    for (const auto &ec : encrypted_consts) {
        // Find the block containing this instruction
        for (int i = 0; i < mba->qty; i++) {
            mblock_t *blk = mba->get_mblock(i);
            if (!blk)
                continue;

            for (minsn_t *ins = blk->head; ins; ins = ins->next) {
                if (ins == ec.xor_insn) {
                    total_changes += replace_with_constant(blk, ins, ec);
                    ctx->decrypted_consts[ec.gv_addr] = ec.decrypted_val;
                    ctx->consts_decrypted++;

                    deobf::log("[const_decrypt] Decrypted constant at %a: 0x%llx -> 0x%llx\n",
                              ec.gv_addr,
                              (unsigned long long)ec.encrypted_val,
                              (unsigned long long)ec.decrypted_val);
                    break;
                }
            }
        }
    }

    deobf::log("[const_decrypt] Decrypted %d constants\n", ctx->consts_decrypted);
    return total_changes;
}

//--------------------------------------------------------------------------
// Instruction-level simplification
//--------------------------------------------------------------------------
int const_decrypt_handler_t::simplify_insn(mblock_t *blk, minsn_t *ins, deobf_ctx_t *ctx) {
    if (!ins)
        return 0;

    encrypted_const_t ec;
    if (is_const_encryption_pattern(ins, &ec)) {
        return replace_with_constant(blk, ins, ec);
    }

    return 0;
}

//--------------------------------------------------------------------------
// Find encrypted constants
//--------------------------------------------------------------------------
std::vector<const_decrypt_handler_t::encrypted_const_t>
const_decrypt_handler_t::find_encrypted_consts(mbl_array_t *mba) {

    std::vector<encrypted_const_t> result;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            encrypted_const_t ec;
            if (is_const_encryption_pattern(ins, &ec)) {
                result.push_back(ec);
            }
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Check if instruction matches encrypted constant pattern
//--------------------------------------------------------------------------
bool const_decrypt_handler_t::is_const_encryption_pattern(minsn_t *ins, encrypted_const_t *out) {
    if (!ins || ins->opcode != m_xor)
        return false;

    // Pattern: xor reg, gv_load, immediate
    //      or: xor reg, immediate, gv_load

    ea_t gv_addr = BADADDR;
    uint64_t key = 0;
    int size = 0;

    // Check both operand orderings
    if (ins->l.t == mop_v && ins->r.t == mop_n) {
        // Left is global, right is immediate
        gv_addr = ins->l.g;
        key = ins->r.nnn->value;
        size = ins->l.size;
    } else if (ins->r.t == mop_v && ins->l.t == mop_n) {
        // Right is global, left is immediate
        gv_addr = ins->r.g;
        key = ins->l.nnn->value;
        size = ins->r.size;
    } else {
        // Also check for nested load
        // Pattern: xor(ldx(gv), immediate)
        mop_t *gv_mop = nullptr;
        mop_t *key_mop = nullptr;

        if (ins->l.t == mop_d && ins->l.d && ins->l.d->opcode == m_ldx) {
            minsn_t *load = ins->l.d;
            if (load->l.t == mop_v) {
                gv_mop = &load->l;
                if (ins->r.t == mop_n)
                    key_mop = &ins->r;
            }
        } else if (ins->r.t == mop_d && ins->r.d && ins->r.d->opcode == m_ldx) {
            minsn_t *load = ins->r.d;
            if (load->l.t == mop_v) {
                gv_mop = &load->l;
                if (ins->l.t == mop_n)
                    key_mop = &ins->l;
            }
        }

        if (gv_mop && key_mop) {
            gv_addr = gv_mop->g;
            key = key_mop->nnn->value;
            size = gv_mop->size;
        }
    }

    if (gv_addr == BADADDR || size <= 0 || size > 8)
        return false;

    // Verify it's a data location (not code)
    flags64_t flags = get_flags(gv_addr);
    if (is_code(flags))
        return false;

    // Read the encrypted value
    uint64_t encrypted = read_global_value(gv_addr, size);

    // Compute decrypted value
    uint64_t decrypted = encrypted ^ key;

    if (out) {
        out->xor_insn = ins;
        out->gv_addr = gv_addr;
        out->xor_key = key;
        out->encrypted_val = encrypted;
        out->decrypted_val = decrypted;
        out->size = size;
    }

    return true;
}

//--------------------------------------------------------------------------
// Replace XOR with constant
//--------------------------------------------------------------------------
int const_decrypt_handler_t::replace_with_constant(mblock_t *blk, minsn_t *ins,
    const encrypted_const_t &ec) {

    if (!ins)
        return 0;

    // Transform: xor dst, gv, key  ->  mov dst, decrypted_value

    ins->opcode = m_mov;
    ins->l.make_number(ec.decrypted_val, ec.size);
    ins->r.erase();

    return 1;
}

//--------------------------------------------------------------------------
// Read value from global
//--------------------------------------------------------------------------
uint64_t const_decrypt_handler_t::read_global_value(ea_t addr, int size) {
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
