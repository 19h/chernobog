#include "pattern_match.h"
#include "expr_simplify.h"

namespace pattern_match {

//--------------------------------------------------------------------------
// Opaque predicate analysis
//--------------------------------------------------------------------------
opaque_pred_t analyze_predicate(mblock_t *blk, minsn_t *jcc_insn, deobf_ctx_t *ctx) {
    opaque_pred_t result;
    result.type = opaque_pred_t::OPAQUE_UNKNOWN;
    result.cond_insn = jcc_insn;
    result.true_block = -1;
    result.false_block = -1;

    if (!jcc_insn || !deobf::is_jcc(jcc_insn->opcode))
        return result;

    // Get branch targets
    if (jcc_insn->d.t == mop_b) {
        result.true_block = jcc_insn->d.b;
    }

    // Check if the condition can be evaluated statically
    sym_expr_ptr cond = deobf::mop_to_sym(jcc_insn->l, ctx);
    if (cond) {
        cond = deobf::simplify_expr(cond);
        auto val = deobf::eval_const_expr(cond);
        if (val.has_value()) {
            if (*val != 0)
                result.type = opaque_pred_t::OPAQUE_ALWAYS_TRUE;
            else
                result.type = opaque_pred_t::OPAQUE_ALWAYS_FALSE;
        }
    }

    // Check for common Hikari opaque predicate patterns:
    // Pattern 1: (x * (x + 1)) % 2 == 0  (always true for any x)
    // Pattern 2: y < 10 || y >= 10       (always true)
    // Pattern 3: Comparison of two constants

    if (jcc_insn->l.t == mop_d && jcc_insn->l.d) {
        minsn_t *nested = jcc_insn->l.d;

        // Check for setXX instructions with constant operands
        if (nested->opcode >= m_setz && nested->opcode <= m_setle) {
            if (nested->l.t == mop_n && nested->r.t == mop_n) {
                // Both operands are constants - evaluate
                int64_t l = nested->l.nnn->value;
                int64_t r = nested->r.nnn->value;
                bool cond_true = false;

                switch (nested->opcode) {
                    case m_setz:  cond_true = (l == r); break;
                    case m_setnz: cond_true = (l != r); break;
                    case m_setae: cond_true = ((uint64_t)l >= (uint64_t)r); break;
                    case m_setb:  cond_true = ((uint64_t)l < (uint64_t)r); break;
                    case m_seta:  cond_true = ((uint64_t)l > (uint64_t)r); break;
                    case m_setbe: cond_true = ((uint64_t)l <= (uint64_t)r); break;
                    case m_setg:  cond_true = (l > r); break;
                    case m_setge: cond_true = (l >= r); break;
                    case m_setl:  cond_true = (l < r); break;
                    case m_setle: cond_true = (l <= r); break;
                    default: break;
                }

                result.type = cond_true ? opaque_pred_t::OPAQUE_ALWAYS_TRUE
                                       : opaque_pred_t::OPAQUE_ALWAYS_FALSE;
            }
        }
    }

    return result;
}

bool is_always_true(minsn_t *insn) {
    if (!insn)
        return false;

    // Immediate non-zero value
    if (insn->l.t == mop_n && insn->l.nnn->value != 0)
        return true;

    return false;
}

bool is_always_false(minsn_t *insn) {
    if (!insn)
        return false;

    // Immediate zero value
    if (insn->l.t == mop_n && insn->l.nnn->value == 0)
        return true;

    return false;
}

//--------------------------------------------------------------------------
// Control flow flattening detection
//--------------------------------------------------------------------------
bool detect_flatten_pattern(mbl_array_t *mba, flatten_info_t *out) {
    if (!mba || mba->qty < 4)
        return false;

    // Look for the dispatcher pattern:
    // 1. A block that loads a state variable
    // 2. A switch/jump table based on that variable
    // 3. Multiple case blocks that update the state variable

    int dispatcher = -1;
    mop_t state_var;

    // Find blocks with switch-like behavior (jtbl instruction)
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        // Look for jtbl (jump table) instruction
        minsn_t *tail = blk->tail;
        if (tail && tail->opcode == m_jtbl) {
            dispatcher = i;
            // The operand being switched on is our state variable
            state_var = tail->l;
            break;
        }

        // Also check for cascading conditional jumps
        // (another form of switch implementation)
        int jcc_count = 0;
        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            if (deobf::is_jcc(ins->opcode))
                jcc_count++;
        }

        // Many conditional jumps in one block suggests a switch
        if (jcc_count >= 3) {
            dispatcher = i;
            break;
        }
    }

    if (dispatcher < 0)
        return false;

    // Look for loop structure: a block that jumps back to dispatcher
    int loop_end = -1;
    for (int i = 0; i < mba->qty; i++) {
        if (i == dispatcher)
            continue;

        mblock_t *blk = mba->get_mblock(i);
        if (!blk || !blk->tail)
            continue;

        // Check if this block jumps to dispatcher
        if (blk->tail->opcode == m_goto && blk->tail->l.t == mop_b) {
            if (blk->tail->l.b == dispatcher) {
                loop_end = i;
                break;
            }
        }
    }

    // Look for state variable updates in case blocks
    std::map<uint64_t, int> state_map;
    for (int i = 0; i < mba->qty; i++) {
        if (i == dispatcher || i == loop_end)
            continue;

        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        // Look for store to state variable
        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            if (ins->opcode == m_mov || ins->opcode == m_stx) {
                // Check if storing a constant to state variable location
                if (ins->l.t == mop_n && ins->d.t == state_var.t) {
                    uint64_t state_val = ins->l.nnn->value;
                    state_map[state_val] = i;
                }
            }
        }
    }

    // Need at least a few state mappings to confirm flattening
    if (state_map.size() < 2)
        return false;

    if (out) {
        out->dispatcher_block = dispatcher;
        out->loop_end_block = loop_end;
        out->state_var = state_var;
        out->state_to_block = state_map;
    }

    return true;
}

//--------------------------------------------------------------------------
// String encryption detection
//--------------------------------------------------------------------------
bool detect_string_encryption(mbl_array_t *mba, ea_t func_ea, std::vector<string_enc_info_t> *out) {
    if (!mba)
        return false;

    bool found = false;

    // Look for XOR loops decrypting global data
    // Hikari pattern: load byte, XOR with key, store to workspace

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        // Look for XOR instructions with global variable operands
        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            if (ins->opcode != m_xor)
                continue;

            // Check if one operand is a global load
            ea_t enc_addr = BADADDR;
            uint64_t xor_key = 0;

            if (ins->l.t == mop_v && ins->r.t == mop_n) {
                enc_addr = ins->l.g;
                xor_key = ins->r.nnn->value;
            } else if (ins->r.t == mop_v && ins->l.t == mop_n) {
                enc_addr = ins->r.g;
                xor_key = ins->l.nnn->value;
            }

            if (enc_addr != BADADDR) {
                // Check if this looks like string data
                flags64_t flags = get_flags(enc_addr);
                if (is_data(flags)) {
                    string_enc_info_t info;
                    info.encrypted_addr = enc_addr;
                    info.decrypt_space_addr = BADADDR;
                    info.key_addr = BADADDR;
                    info.keys.push_back((uint8_t)xor_key);
                    info.element_size = ins->l.size;
                    info.num_elements = 1;

                    if (out)
                        out->push_back(info);
                    found = true;
                }
            }
        }
    }

    // Also check for Hikari-specific global variable names
    // "EncryptedString", "DecryptSpace", "StringEncryptionEncStatus"
    segment_t *seg = get_first_seg();
    while (seg) {
        if (seg->type == SEG_DATA) {
            ea_t ea = seg->start_ea;
            while (ea < seg->end_ea) {
                qstring name;
                if (get_name(&name, ea) > 0) {
                    if (name.find("EncryptedString") != qstring::npos ||
                        name.find("DecryptSpace") != qstring::npos) {
                        found = true;
                    }
                }
                ea = next_head(ea, seg->end_ea);
                if (ea == BADADDR)
                    break;
            }
        }
        seg = get_next_seg(seg->start_ea);
    }

    return found;
}

//--------------------------------------------------------------------------
// Constant encryption detection
//--------------------------------------------------------------------------
bool detect_const_encryption(mblock_t *blk, std::vector<const_enc_info_t> *out) {
    if (!blk)
        return false;

    bool found = false;

    // Look for pattern: load global, XOR with constant
    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        if (ins->opcode != m_xor)
            continue;

        ea_t gv_addr = BADADDR;
        uint64_t key = 0;

        // Check both operand orderings
        if (ins->l.t == mop_v && ins->r.t == mop_n) {
            gv_addr = ins->l.g;
            key = ins->r.nnn->value;
        } else if (ins->r.t == mop_v && ins->l.t == mop_n) {
            gv_addr = ins->r.g;
            key = ins->l.nnn->value;
        }

        if (gv_addr != BADADDR) {
            // Read the encrypted value from the global
            uint64_t enc_val = 0;
            size_t size = ins->l.size;
            if (size <= 8) {
                get_bytes(&enc_val, size, gv_addr);
                uint64_t decrypted = enc_val ^ key;

                const_enc_info_t info;
                info.const_gv_addr = gv_addr;
                info.xor_key = key;
                info.decrypted_value = decrypted;

                if (out)
                    out->push_back(info);
                found = true;
            }
        }
    }

    return found;
}

//--------------------------------------------------------------------------
// Indirect branch detection
//--------------------------------------------------------------------------
bool detect_indirect_branch(mblock_t *blk, indirect_br_info_t *out) {
    if (!blk || !blk->tail)
        return false;

    // Look for ijmp (indirect jump) instruction
    if (blk->tail->opcode != m_ijmp)
        return false;

    // The jump target comes from some computation
    // Hikari stores targets in a jump table global variable

    // Check for GEP-like pattern loading from array
    mop_t *jump_target = &blk->tail->d;

    // Look backwards for the load instruction that provides the target
    ea_t table_addr = BADADDR;
    for (minsn_t *ins = blk->tail->prev; ins; ins = ins->prev) {
        if (ins->opcode == m_ldx) {
            // Memory load - check if from global
            if (ins->l.t == mop_v) {
                table_addr = ins->l.g;
                break;
            }
        }
    }

    if (table_addr != BADADDR) {
        if (out) {
            out->jump_table_addr = table_addr;
            out->is_encrypted = false;
            out->enc_key = 0;

            // Try to read targets from jump table
            ea_t ptr = table_addr;
            for (int i = 0; i < 64; i++) {  // Limit search
                ea_t target = BADADDR;
                if (get_bytes(&target, sizeof(ea_t), ptr) == sizeof(ea_t)) {
                    if (target == 0 || target == BADADDR)
                        break;
                    // Validate it's a code address
                    if (is_code(get_flags(target))) {
                        out->targets.push_back(target);
                    }
                }
                ptr += sizeof(ea_t);
            }
        }
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Substitution pattern matching
//--------------------------------------------------------------------------
bool match_substitution_pattern(minsn_t *insn, substitution_info_t *out) {
    if (!insn)
        return false;

    // Try to match known Hikari substitution patterns

    // Pattern: a - ~b - 1 = a + b (ADD substitution)
    // x - NOT(y) - 1
    if (insn->opcode == m_sub) {
        if (insn->r.t == mop_n && insn->r.nnn->value == 1) {
            // Check if left is also a subtraction with NOT
            if (insn->l.t == mop_d && insn->l.d->opcode == m_sub) {
                minsn_t *inner = insn->l.d;
                if (inner->r.t == mop_d && inner->r.d->opcode == m_bnot) {
                    // Found: a - ~b - 1
                    if (out) {
                        out->original_op = substitution_info_t::SUBST_ADD;
                        out->complex_insn = insn;
                        out->operand1 = inner->l;
                        out->operand2 = inner->r.d->l;
                    }
                    return true;
                }
            }
        }
    }

    // Pattern: (a | b) + (a & b) = a + b (ADD substitution 2)
    if (insn->opcode == m_add) {
        if (insn->l.t == mop_d && insn->r.t == mop_d) {
            minsn_t *left = insn->l.d;
            minsn_t *right = insn->r.d;
            if (left->opcode == m_or && right->opcode == m_and) {
                // Check if operands match
                // left = a | b, right = a & b
                if (out) {
                    out->original_op = substitution_info_t::SUBST_ADD;
                    out->complex_insn = insn;
                    out->operand1 = left->l;
                    out->operand2 = left->r;
                }
                return true;
            }
        }
    }

    // Pattern: (a ^ b) + 2*(a & b) = a + b (ADD substitution 3)
    if (insn->opcode == m_add) {
        if (insn->l.t == mop_d && insn->r.t == mop_d) {
            minsn_t *left = insn->l.d;
            minsn_t *right = insn->r.d;
            if (left->opcode == m_xor && right->opcode == m_mul) {
                // Check for 2 * (a & b)
                if (right->l.t == mop_n && right->l.nnn->value == 2) {
                    if (out) {
                        out->original_op = substitution_info_t::SUBST_ADD;
                        out->complex_insn = insn;
                        out->operand1 = left->l;
                        out->operand2 = left->r;
                    }
                    return true;
                }
            }
        }
    }

    // Pattern: a + ~b + 1 = a - b (SUB substitution)
    if (insn->opcode == m_add) {
        if (insn->r.t == mop_n && insn->r.nnn->value == 1) {
            if (insn->l.t == mop_d && insn->l.d->opcode == m_add) {
                minsn_t *inner = insn->l.d;
                if (inner->r.t == mop_d && inner->r.d->opcode == m_bnot) {
                    // Found: a + ~b + 1 = a - b
                    if (out) {
                        out->original_op = substitution_info_t::SUBST_SUB;
                        out->complex_insn = insn;
                        out->operand1 = inner->l;
                        out->operand2 = inner->r.d->l;
                    }
                    return true;
                }
            }
        }
    }

    // Pattern: (a ^ ~b) & a = a & b (AND substitution)
    if (insn->opcode == m_and) {
        if (insn->l.t == mop_d && insn->l.d->opcode == m_xor) {
            minsn_t *xor_insn = insn->l.d;
            if (xor_insn->r.t == mop_d && xor_insn->r.d->opcode == m_bnot) {
                // Check if right operand of AND matches left of XOR
                if (out) {
                    out->original_op = substitution_info_t::SUBST_AND;
                    out->complex_insn = insn;
                    out->operand1 = xor_insn->l;
                    out->operand2 = xor_insn->r.d->l;
                }
                return true;
            }
        }
    }

    // Pattern: (a & b) | (a ^ b) = a | b (OR substitution)
    if (insn->opcode == m_or) {
        if (insn->l.t == mop_d && insn->r.t == mop_d) {
            minsn_t *left = insn->l.d;
            minsn_t *right = insn->r.d;
            if (left->opcode == m_and && right->opcode == m_xor) {
                if (out) {
                    out->original_op = substitution_info_t::SUBST_OR;
                    out->complex_insn = insn;
                    out->operand1 = left->l;
                    out->operand2 = left->r;
                }
                return true;
            }
        }
    }

    // Pattern: (~a & b) | (a & ~b) = a ^ b (XOR substitution)
    if (insn->opcode == m_or) {
        if (insn->l.t == mop_d && insn->r.t == mop_d) {
            minsn_t *left = insn->l.d;
            minsn_t *right = insn->r.d;
            if (left->opcode == m_and && right->opcode == m_and) {
                // Check for (~a & b) | (a & ~b) pattern
                if (out) {
                    out->original_op = substitution_info_t::SUBST_XOR;
                    out->complex_insn = insn;
                    // Need deeper analysis to extract operands
                }
                return true;
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Split block detection
//--------------------------------------------------------------------------
bool detect_split_blocks(mbl_array_t *mba, std::vector<split_block_info_t> *out) {
    if (!mba)
        return false;

    bool found = false;

    // Look for chains of blocks with single unconditional jumps
    std::vector<bool> visited(mba->qty, false);

    for (int i = 0; i < mba->qty; i++) {
        if (visited[i])
            continue;

        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        // Count instructions in block
        int insn_count = 0;
        for (minsn_t *ins = blk->head; ins; ins = ins->next)
            insn_count++;

        // Small block with single successor might be a split
        if (insn_count <= 2 && blk->nsucc() == 1) {
            // Follow the chain
            split_block_info_t chain;
            chain.mergeable_blocks.push_back(i);
            visited[i] = true;

            int curr = blk->succ(0);
            while (curr >= 0 && curr < mba->qty && !visited[curr]) {
                mblock_t *next_blk = mba->get_mblock(curr);
                if (!next_blk)
                    break;

                // Check if this block is also small with single successor
                int next_count = 0;
                for (minsn_t *ins = next_blk->head; ins; ins = ins->next)
                    next_count++;

                if (next_count > 2 || next_blk->nsucc() != 1)
                    break;

                chain.mergeable_blocks.push_back(curr);
                visited[curr] = true;
                curr = next_blk->succ(0);
            }

            // Only report if we found a chain of 3+ blocks
            if (chain.mergeable_blocks.size() >= 3) {
                if (out)
                    out->push_back(chain);
                found = true;
            }
        }
    }

    return found;
}

} // namespace pattern_match
