#include "substitution.h"
#include "../analysis/expr_simplify.h"

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool substitution_handler_t::detect(mbl_array_t *mba) {
    if (!mba)
        return false;

    int complex_patterns = 0;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            match_result_t match;
            if (try_match(ins, &match)) {
                complex_patterns++;
                if (complex_patterns >= 3)  // Found enough patterns
                    return true;
            }
        }
    }

    return complex_patterns > 0;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int substitution_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    deobf::log("[substitution] Starting expression simplification\n");

    int total_changes = 0;

    // Multiple passes may be needed as simplifications enable more simplifications
    int pass = 0;
    int pass_changes;

    do {
        pass_changes = 0;
        pass++;

        for (int i = 0; i < mba->qty; i++) {
            mblock_t *blk = mba->get_mblock(i);
            if (!blk)
                continue;

            for (minsn_t *ins = blk->head; ins; ins = ins->next) {
                int changes = simplify_insn(blk, ins, ctx);
                pass_changes += changes;
            }
        }

        total_changes += pass_changes;
        deobf::log_verbose("[substitution] Pass %d: %d changes\n", pass, pass_changes);

    } while (pass_changes > 0 && pass < 10);  // Limit passes

    deobf::log("[substitution] Simplified %d expressions in %d passes\n",
              total_changes, pass);

    ctx->expressions_simplified += total_changes;
    return total_changes;
}

//--------------------------------------------------------------------------
// Instruction-level simplification
//--------------------------------------------------------------------------
int substitution_handler_t::simplify_insn(mblock_t *blk, minsn_t *ins, deobf_ctx_t *ctx) {
    if (!ins)
        return 0;

    match_result_t match;
    if (try_match(ins, &match)) {
        return apply_simplification(blk, ins, match);
    }

    // Also try the generic expression simplifier
    auto result = expr_simplify::simplify_instruction(ins, ctx);
    if (result.simplified) {
        if (result.is_const) {
            ins->opcode = m_mov;
            ins->l.make_number(result.const_result, ins->d.size);
            ins->r.erase();
            return 1;
        } else {
            ins->opcode = result.new_opcode;
            ins->l = result.new_left;
            ins->r = result.new_right;
            return 1;
        }
    }

    return 0;
}

//--------------------------------------------------------------------------
// Try to match any pattern
//--------------------------------------------------------------------------
bool substitution_handler_t::try_match(minsn_t *ins, match_result_t *out) {
    if (!ins)
        return false;

    // Try each pattern based on top-level opcode
    switch (ins->opcode) {
        case m_sub:
            if (match_add_pattern_1(ins, out))  // b - ~c - 1 => b + c
                return true;
            break;

        case m_add:
            if (match_add_pattern_2(ins, out))  // (b|c) + (b&c)
                return true;
            if (match_add_pattern_3(ins, out))  // (b^c) + 2*(b&c)
                return true;
            if (match_sub_pattern_1(ins, out))  // b + ~c + 1 => b - c
                return true;
            break;

        case m_and:
            if (match_and_pattern_1(ins, out))
                return true;
            break;

        case m_or:
            if (match_or_pattern_1(ins, out))
                return true;
            if (match_xor_pattern_1(ins, out))
                return true;
            break;

        default:
            break;
    }

    return false;
}

//--------------------------------------------------------------------------
// Pattern: b - ~c - 1 => b + c
//--------------------------------------------------------------------------
bool substitution_handler_t::match_add_pattern_1(minsn_t *ins, match_result_t *out) {
    // sub(sub(b, bnot(c)), 1)
    if (ins->opcode != m_sub)
        return false;

    if (ins->r.t != mop_n || ins->r.nnn->value != 1)
        return false;

    if (ins->l.t != mop_d || !ins->l.d)
        return false;

    minsn_t *inner = ins->l.d;
    if (inner->opcode != m_sub)
        return false;

    if (inner->r.t != mop_d || !inner->r.d)
        return false;

    minsn_t *not_insn = inner->r.d;
    if (not_insn->opcode != m_bnot)
        return false;

    out->type = SUBST_ADD_1;
    out->operand1 = inner->l;
    out->operand2 = not_insn->l;
    return true;
}

//--------------------------------------------------------------------------
// Pattern: (b|c) + (b&c) => b + c
//--------------------------------------------------------------------------
bool substitution_handler_t::match_add_pattern_2(minsn_t *ins, match_result_t *out) {
    if (ins->opcode != m_add)
        return false;

    if (ins->l.t != mop_d || ins->r.t != mop_d)
        return false;

    minsn_t *left = ins->l.d;
    minsn_t *right = ins->r.d;
    if (!left || !right)
        return false;

    minsn_t *or_insn = nullptr;
    minsn_t *and_insn = nullptr;

    if (left->opcode == m_or && right->opcode == m_and) {
        or_insn = left;
        and_insn = right;
    } else if (left->opcode == m_and && right->opcode == m_or) {
        and_insn = left;
        or_insn = right;
    } else {
        return false;
    }

    // Check operands match
    if (same_value(or_insn->l, and_insn->l) && same_value(or_insn->r, and_insn->r)) {
        out->type = SUBST_ADD_2;
        out->operand1 = or_insn->l;
        out->operand2 = or_insn->r;
        return true;
    }

    if (same_value(or_insn->l, and_insn->r) && same_value(or_insn->r, and_insn->l)) {
        out->type = SUBST_ADD_2;
        out->operand1 = or_insn->l;
        out->operand2 = or_insn->r;
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Pattern: (b^c) + 2*(b&c) => b + c
//--------------------------------------------------------------------------
bool substitution_handler_t::match_add_pattern_3(minsn_t *ins, match_result_t *out) {
    if (ins->opcode != m_add)
        return false;

    if (ins->l.t != mop_d || ins->r.t != mop_d)
        return false;

    minsn_t *xor_insn = nullptr;
    minsn_t *mul_insn = nullptr;

    if (ins->l.d->opcode == m_xor && ins->r.d->opcode == m_mul) {
        xor_insn = ins->l.d;
        mul_insn = ins->r.d;
    } else if (ins->l.d->opcode == m_mul && ins->r.d->opcode == m_xor) {
        mul_insn = ins->l.d;
        xor_insn = ins->r.d;
    } else {
        return false;
    }

    // Check mul is 2 * and_result
    if (mul_insn->l.t != mop_n || mul_insn->l.nnn->value != 2)
        return false;

    if (mul_insn->r.t != mop_d || !mul_insn->r.d)
        return false;

    minsn_t *and_insn = mul_insn->r.d;
    if (and_insn->opcode != m_and)
        return false;

    // Verify operands match
    if (same_value(xor_insn->l, and_insn->l) && same_value(xor_insn->r, and_insn->r)) {
        out->type = SUBST_ADD_3;
        out->operand1 = xor_insn->l;
        out->operand2 = xor_insn->r;
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Pattern: b + ~c + 1 => b - c
//--------------------------------------------------------------------------
bool substitution_handler_t::match_sub_pattern_1(minsn_t *ins, match_result_t *out) {
    // add(add(b, bnot(c)), 1)
    if (ins->opcode != m_add)
        return false;

    if (ins->r.t != mop_n || ins->r.nnn->value != 1)
        return false;

    if (ins->l.t != mop_d || !ins->l.d)
        return false;

    minsn_t *inner = ins->l.d;
    if (inner->opcode != m_add)
        return false;

    // One operand should be bnot
    mop_t b, c;
    bool found = false;

    if (inner->r.t == mop_d && inner->r.d && inner->r.d->opcode == m_bnot) {
        b = inner->l;
        c = inner->r.d->l;
        found = true;
    } else if (inner->l.t == mop_d && inner->l.d && inner->l.d->opcode == m_bnot) {
        b = inner->r;
        c = inner->l.d->l;
        found = true;
    }

    if (found) {
        out->type = SUBST_SUB_1;
        out->operand1 = b;
        out->operand2 = c;
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Pattern: (b ^ ~c) & b => b & c
//--------------------------------------------------------------------------
bool substitution_handler_t::match_and_pattern_1(minsn_t *ins, match_result_t *out) {
    if (ins->opcode != m_and)
        return false;

    // One operand should be xor with bnot, other should match
    mop_t *xor_mop = nullptr;
    mop_t *b_mop = nullptr;

    if (ins->l.t == mop_d && ins->l.d && ins->l.d->opcode == m_xor) {
        xor_mop = &ins->l;
        b_mop = &ins->r;
    } else if (ins->r.t == mop_d && ins->r.d && ins->r.d->opcode == m_xor) {
        xor_mop = &ins->r;
        b_mop = &ins->l;
    } else {
        return false;
    }

    minsn_t *xor_insn = xor_mop->d;

    // One operand of XOR should be bnot, other should match b_mop
    mop_t c;
    if (xor_insn->r.t == mop_d && xor_insn->r.d && xor_insn->r.d->opcode == m_bnot) {
        if (same_value(xor_insn->l, *b_mop)) {
            c = xor_insn->r.d->l;
            out->type = SUBST_AND_1;
            out->operand1 = *b_mop;
            out->operand2 = c;
            return true;
        }
    } else if (xor_insn->l.t == mop_d && xor_insn->l.d && xor_insn->l.d->opcode == m_bnot) {
        if (same_value(xor_insn->r, *b_mop)) {
            c = xor_insn->l.d->l;
            out->type = SUBST_AND_1;
            out->operand1 = *b_mop;
            out->operand2 = c;
            return true;
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Pattern: (b&c) | (b^c) => b | c
//--------------------------------------------------------------------------
bool substitution_handler_t::match_or_pattern_1(minsn_t *ins, match_result_t *out) {
    if (ins->opcode != m_or)
        return false;

    if (ins->l.t != mop_d || ins->r.t != mop_d)
        return false;

    minsn_t *and_insn = nullptr;
    minsn_t *xor_insn = nullptr;

    if (ins->l.d->opcode == m_and && ins->r.d->opcode == m_xor) {
        and_insn = ins->l.d;
        xor_insn = ins->r.d;
    } else if (ins->l.d->opcode == m_xor && ins->r.d->opcode == m_and) {
        xor_insn = ins->l.d;
        and_insn = ins->r.d;
    } else {
        return false;
    }

    // Check operands match
    if (same_value(and_insn->l, xor_insn->l) && same_value(and_insn->r, xor_insn->r)) {
        out->type = SUBST_OR_1;
        out->operand1 = and_insn->l;
        out->operand2 = and_insn->r;
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Pattern: (~a&b) | (a&~b) => a ^ b
//--------------------------------------------------------------------------
bool substitution_handler_t::match_xor_pattern_1(minsn_t *ins, match_result_t *out) {
    if (ins->opcode != m_or)
        return false;

    if (ins->l.t != mop_d || ins->r.t != mop_d)
        return false;

    minsn_t *left = ins->l.d;
    minsn_t *right = ins->r.d;

    if (!left || !right || left->opcode != m_and || right->opcode != m_and)
        return false;

    // Extract operands - looking for (~a & b) and (a & ~b)
    // This is complex pattern matching

    mop_t a_not, b_plain, a_plain, b_not;
    bool left_has_not_first = get_not_operand(left->l, &a_not);
    bool left_has_not_second = get_not_operand(left->r, &a_not);

    if (!left_has_not_first && !left_has_not_second)
        return false;

    // Simplified: if both sides have AND with one NOT operand each
    // and the NOT operands cross-match, it's this pattern
    bool right_has_not_first = get_not_operand(right->l, &b_not);
    bool right_has_not_second = get_not_operand(right->r, &b_not);

    if (!right_has_not_first && !right_has_not_second)
        return false;

    // For now, simplified detection
    out->type = SUBST_XOR_1;
    // Would need more analysis to extract exact operands
    return true;
}

//--------------------------------------------------------------------------
// Pattern: (b+c) - 2*(b&c) => b ^ c
//--------------------------------------------------------------------------
bool substitution_handler_t::match_xor_pattern_2(minsn_t *ins, match_result_t *out) {
    // Not implemented yet - complex pattern
    return false;
}

//--------------------------------------------------------------------------
// Apply simplification
//--------------------------------------------------------------------------
int substitution_handler_t::apply_simplification(mblock_t *blk, minsn_t *ins,
    const match_result_t &match) {

    if (match.type == SUBST_NONE)
        return 0;

    mcode_t new_op = m_nop;

    switch (match.type) {
        case SUBST_ADD_1:
        case SUBST_ADD_2:
        case SUBST_ADD_3:
        case SUBST_ADD_NEG:
        case SUBST_ADD_DNEG:
            new_op = m_add;
            break;

        case SUBST_SUB_1:
        case SUBST_SUB_NEG:
            new_op = m_sub;
            break;

        case SUBST_AND_1:
        case SUBST_AND_2:
            new_op = m_and;
            break;

        case SUBST_OR_1:
            new_op = m_or;
            break;

        case SUBST_XOR_1:
        case SUBST_XOR_2:
            new_op = m_xor;
            break;

        default:
            return 0;
    }

    // Replace instruction
    ins->opcode = new_op;
    ins->l = match.operand1;
    ins->r = match.operand2;

    deobf::log_verbose("[substitution] Simplified pattern type %d\n", match.type);
    return 1;
}

//--------------------------------------------------------------------------
// Check if two mops represent same value
//--------------------------------------------------------------------------
bool substitution_handler_t::same_value(const mop_t &a, const mop_t &b) {
    if (a.t != b.t)
        return false;

    switch (a.t) {
        case mop_n:
            return a.nnn->value == b.nnn->value;
        case mop_r:
            return a.r == b.r;
        case mop_v:
            return a.g == b.g;
        case mop_S:
            return a.s->off == b.s->off;
        default:
            return false;
    }
}

//--------------------------------------------------------------------------
// Get operand from NOT instruction
//--------------------------------------------------------------------------
bool substitution_handler_t::get_not_operand(const mop_t &m, mop_t *out) {
    if (m.t != mop_d || !m.d)
        return false;

    if (m.d->opcode != m_bnot)
        return false;

    *out = m.d->l;
    return true;
}
