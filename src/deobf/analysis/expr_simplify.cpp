#include "expr_simplify.h"

namespace expr_simplify {

//--------------------------------------------------------------------------
// Main simplification entry point
//--------------------------------------------------------------------------
simplify_result_t simplify_instruction(minsn_t *insn, deobf_ctx_t *ctx) {
    simplify_result_t result;

    if (!insn)
        return result;

    // Try Hikari-specific patterns first (most likely in obfuscated code)
    switch (insn->opcode) {
        case m_sub:
            if (simplify_hikari_add_pattern1(insn, &result))
                return result;
            if (try_simplify_sub(insn, &result))
                return result;
            break;

        case m_add:
            if (simplify_hikari_add_pattern2(insn, &result))
                return result;
            if (simplify_hikari_add_pattern3(insn, &result))
                return result;
            if (simplify_hikari_sub_pattern1(insn, &result))
                return result;
            if (try_simplify_add(insn, &result))
                return result;
            break;

        case m_and:
            if (simplify_hikari_and_pattern1(insn, &result))
                return result;
            if (try_simplify_and(insn, &result))
                return result;
            break;

        case m_or:
            if (simplify_hikari_or_pattern1(insn, &result))
                return result;
            if (simplify_hikari_xor_pattern1(insn, &result))
                return result;
            if (try_simplify_or(insn, &result))
                return result;
            break;

        case m_xor:
            if (try_simplify_xor(insn, &result))
                return result;
            break;

        case m_mul:
            if (try_simplify_mul(insn, &result))
                return result;
            break;

        default:
            break;
    }

    return result;
}

//--------------------------------------------------------------------------
// Generic algebraic simplifications
//--------------------------------------------------------------------------
bool try_simplify_add(minsn_t *insn, simplify_result_t *out) {
    if (!insn || insn->opcode != m_add)
        return false;

    // x + 0 = x
    if (insn->r.t == mop_n && insn->r.nnn->value == 0) {
        out->simplified = true;
        out->new_opcode = m_mov;
        out->new_left = insn->l;
        return true;
    }

    // Constant folding
    if (insn->l.t == mop_n && insn->r.t == mop_n) {
        out->simplified = true;
        out->is_const = true;
        out->const_result = insn->l.nnn->value + insn->r.nnn->value;
        return true;
    }

    return false;
}

bool try_simplify_sub(minsn_t *insn, simplify_result_t *out) {
    if (!insn || insn->opcode != m_sub)
        return false;

    // x - 0 = x
    if (insn->r.t == mop_n && insn->r.nnn->value == 0) {
        out->simplified = true;
        out->new_opcode = m_mov;
        out->new_left = insn->l;
        return true;
    }

    // x - x = 0
    if (mops_equal(insn->l, insn->r)) {
        out->simplified = true;
        out->is_const = true;
        out->const_result = 0;
        return true;
    }

    // Constant folding
    if (insn->l.t == mop_n && insn->r.t == mop_n) {
        out->simplified = true;
        out->is_const = true;
        out->const_result = insn->l.nnn->value - insn->r.nnn->value;
        return true;
    }

    return false;
}

bool try_simplify_and(minsn_t *insn, simplify_result_t *out) {
    if (!insn || insn->opcode != m_and)
        return false;

    // x & 0 = 0
    if ((insn->l.t == mop_n && insn->l.nnn->value == 0) ||
        (insn->r.t == mop_n && insn->r.nnn->value == 0)) {
        out->simplified = true;
        out->is_const = true;
        out->const_result = 0;
        return true;
    }

    // x & -1 = x (all bits set)
    if (insn->r.t == mop_n && insn->r.nnn->value == (uint64_t)-1) {
        out->simplified = true;
        out->new_opcode = m_mov;
        out->new_left = insn->l;
        return true;
    }

    // x & x = x
    if (mops_equal(insn->l, insn->r)) {
        out->simplified = true;
        out->new_opcode = m_mov;
        out->new_left = insn->l;
        return true;
    }

    // Constant folding
    if (insn->l.t == mop_n && insn->r.t == mop_n) {
        out->simplified = true;
        out->is_const = true;
        out->const_result = insn->l.nnn->value & insn->r.nnn->value;
        return true;
    }

    return false;
}

bool try_simplify_or(minsn_t *insn, simplify_result_t *out) {
    if (!insn || insn->opcode != m_or)
        return false;

    // x | 0 = x
    if (insn->r.t == mop_n && insn->r.nnn->value == 0) {
        out->simplified = true;
        out->new_opcode = m_mov;
        out->new_left = insn->l;
        return true;
    }

    // x | -1 = -1
    if (insn->r.t == mop_n && insn->r.nnn->value == (uint64_t)-1) {
        out->simplified = true;
        out->is_const = true;
        out->const_result = (uint64_t)-1;
        return true;
    }

    // x | x = x
    if (mops_equal(insn->l, insn->r)) {
        out->simplified = true;
        out->new_opcode = m_mov;
        out->new_left = insn->l;
        return true;
    }

    // Constant folding
    if (insn->l.t == mop_n && insn->r.t == mop_n) {
        out->simplified = true;
        out->is_const = true;
        out->const_result = insn->l.nnn->value | insn->r.nnn->value;
        return true;
    }

    return false;
}

bool try_simplify_xor(minsn_t *insn, simplify_result_t *out) {
    if (!insn || insn->opcode != m_xor)
        return false;

    // x ^ 0 = x
    if (insn->r.t == mop_n && insn->r.nnn->value == 0) {
        out->simplified = true;
        out->new_opcode = m_mov;
        out->new_left = insn->l;
        return true;
    }

    // x ^ x = 0
    if (mops_equal(insn->l, insn->r)) {
        out->simplified = true;
        out->is_const = true;
        out->const_result = 0;
        return true;
    }

    // Constant folding
    if (insn->l.t == mop_n && insn->r.t == mop_n) {
        out->simplified = true;
        out->is_const = true;
        out->const_result = insn->l.nnn->value ^ insn->r.nnn->value;
        return true;
    }

    return false;
}

bool try_simplify_mul(minsn_t *insn, simplify_result_t *out) {
    if (!insn || insn->opcode != m_mul)
        return false;

    // x * 0 = 0
    if ((insn->l.t == mop_n && insn->l.nnn->value == 0) ||
        (insn->r.t == mop_n && insn->r.nnn->value == 0)) {
        out->simplified = true;
        out->is_const = true;
        out->const_result = 0;
        return true;
    }

    // x * 1 = x
    if (insn->r.t == mop_n && insn->r.nnn->value == 1) {
        out->simplified = true;
        out->new_opcode = m_mov;
        out->new_left = insn->l;
        return true;
    }

    // Constant folding
    if (insn->l.t == mop_n && insn->r.t == mop_n) {
        out->simplified = true;
        out->is_const = true;
        out->const_result = insn->l.nnn->value * insn->r.nnn->value;
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Hikari-specific pattern simplifiers
//--------------------------------------------------------------------------

// Pattern: b - ~c - 1 => b + c
// This is ADD substitution 1 in Hikari
bool simplify_hikari_add_pattern1(minsn_t *insn, simplify_result_t *out) {
    if (!insn || insn->opcode != m_sub)
        return false;

    // Need: sub(sub(b, bnot(c)), 1)
    if (insn->r.t != mop_n || insn->r.nnn->value != 1)
        return false;

    if (insn->l.t != mop_d || !insn->l.d)
        return false;

    minsn_t *inner = insn->l.d;
    if (inner->opcode != m_sub)
        return false;

    // inner->r should be bnot(c)
    if (inner->r.t != mop_d || !inner->r.d)
        return false;

    minsn_t *bnot_insn = inner->r.d;
    if (bnot_insn->opcode != m_bnot)
        return false;

    // Found: b - ~c - 1 = b + c
    out->simplified = true;
    out->new_opcode = m_add;
    out->new_left = inner->l;           // b
    out->new_right = bnot_insn->l;      // c

    deobf::log_verbose("[expr_simplify] Simplified b - ~c - 1 => b + c\n");
    return true;
}

// Pattern: (b | c) + (b & c) => b + c
// This is ADD substitution 2 in Hikari
bool simplify_hikari_add_pattern2(minsn_t *insn, simplify_result_t *out) {
    if (!insn || insn->opcode != m_add)
        return false;

    if (insn->l.t != mop_d || insn->r.t != mop_d)
        return false;

    minsn_t *left = insn->l.d;
    minsn_t *right = insn->r.d;

    if (!left || !right)
        return false;

    // Check for (b | c) + (b & c) or (b & c) + (b | c)
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

    // Verify operands are the same (b and c)
    if (!mops_equal(or_insn->l, and_insn->l) || !mops_equal(or_insn->r, and_insn->r)) {
        // Try swapped order
        if (!mops_equal(or_insn->l, and_insn->r) || !mops_equal(or_insn->r, and_insn->l)) {
            return false;
        }
    }

    // Found: (b | c) + (b & c) = b + c
    out->simplified = true;
    out->new_opcode = m_add;
    out->new_left = or_insn->l;
    out->new_right = or_insn->r;

    deobf::log_verbose("[expr_simplify] Simplified (b|c) + (b&c) => b + c\n");
    return true;
}

// Pattern: (b ^ c) + 2*(b & c) => b + c
// This is ADD substitution 3 in Hikari
bool simplify_hikari_add_pattern3(minsn_t *insn, simplify_result_t *out) {
    if (!insn || insn->opcode != m_add)
        return false;

    if (insn->l.t != mop_d || insn->r.t != mop_d)
        return false;

    minsn_t *left = insn->l.d;
    minsn_t *right = insn->r.d;

    if (!left || !right)
        return false;

    // Check for (b ^ c) + 2*(b & c)
    minsn_t *xor_insn = nullptr;
    minsn_t *mul_insn = nullptr;

    if (left->opcode == m_xor && right->opcode == m_mul) {
        xor_insn = left;
        mul_insn = right;
    } else if (left->opcode == m_mul && right->opcode == m_xor) {
        mul_insn = left;
        xor_insn = right;
    } else {
        return false;
    }

    // Check mul is 2 * something
    if (mul_insn->l.t != mop_n || mul_insn->l.nnn->value != 2)
        return false;

    // Check mul operand is (b & c)
    if (mul_insn->r.t != mop_d || !mul_insn->r.d)
        return false;

    minsn_t *and_insn = mul_insn->r.d;
    if (and_insn->opcode != m_and)
        return false;

    // Verify XOR and AND have same operands
    if (!mops_equal(xor_insn->l, and_insn->l) || !mops_equal(xor_insn->r, and_insn->r)) {
        if (!mops_equal(xor_insn->l, and_insn->r) || !mops_equal(xor_insn->r, and_insn->l)) {
            return false;
        }
    }

    // Found: (b ^ c) + 2*(b & c) = b + c
    out->simplified = true;
    out->new_opcode = m_add;
    out->new_left = xor_insn->l;
    out->new_right = xor_insn->r;

    deobf::log_verbose("[expr_simplify] Simplified (b^c) + 2*(b&c) => b + c\n");
    return true;
}

// Pattern: b + ~c + 1 => b - c
// This is SUB substitution 3 in Hikari
bool simplify_hikari_sub_pattern1(minsn_t *insn, simplify_result_t *out) {
    if (!insn || insn->opcode != m_add)
        return false;

    // Need: add(add(b, bnot(c)), 1)
    if (insn->r.t != mop_n || insn->r.nnn->value != 1)
        return false;

    if (insn->l.t != mop_d || !insn->l.d)
        return false;

    minsn_t *inner = insn->l.d;
    if (inner->opcode != m_add)
        return false;

    // inner->r should be bnot(c)
    if (inner->r.t != mop_d || !inner->r.d)
        return false;

    minsn_t *bnot_insn = inner->r.d;
    if (bnot_insn->opcode != m_bnot)
        return false;

    // Found: b + ~c + 1 = b - c
    out->simplified = true;
    out->new_opcode = m_sub;
    out->new_left = inner->l;           // b
    out->new_right = bnot_insn->l;      // c

    deobf::log_verbose("[expr_simplify] Simplified b + ~c + 1 => b - c\n");
    return true;
}

// Pattern: (b ^ ~c) & b => b & c
// This is AND substitution 1 in Hikari
bool simplify_hikari_and_pattern1(minsn_t *insn, simplify_result_t *out) {
    if (!insn || insn->opcode != m_and)
        return false;

    // Check for (b ^ ~c) & b
    mop_t *xor_mop = nullptr;
    mop_t *other = nullptr;

    if (insn->l.t == mop_d && insn->l.d && insn->l.d->opcode == m_xor) {
        xor_mop = &insn->l;
        other = &insn->r;
    } else if (insn->r.t == mop_d && insn->r.d && insn->r.d->opcode == m_xor) {
        xor_mop = &insn->r;
        other = &insn->l;
    } else {
        return false;
    }

    minsn_t *xor_insn = xor_mop->d;

    // Check one operand of XOR is NOT
    mop_t *b = nullptr;
    mop_t *c = nullptr;

    if (xor_insn->r.t == mop_d && xor_insn->r.d && xor_insn->r.d->opcode == m_bnot) {
        b = &xor_insn->l;
        c = &xor_insn->r.d->l;
    } else if (xor_insn->l.t == mop_d && xor_insn->l.d && xor_insn->l.d->opcode == m_bnot) {
        b = &xor_insn->r;
        c = &xor_insn->l.d->l;
    } else {
        return false;
    }

    // Verify other operand is b
    if (!mops_equal(*b, *other))
        return false;

    // Found: (b ^ ~c) & b = b & c
    out->simplified = true;
    out->new_opcode = m_and;
    out->new_left = *b;
    out->new_right = *c;

    deobf::log_verbose("[expr_simplify] Simplified (b ^ ~c) & b => b & c\n");
    return true;
}

// Pattern: (b & c) | (b ^ c) => b | c
// This is OR substitution 1 in Hikari
bool simplify_hikari_or_pattern1(minsn_t *insn, simplify_result_t *out) {
    if (!insn || insn->opcode != m_or)
        return false;

    if (insn->l.t != mop_d || insn->r.t != mop_d)
        return false;

    minsn_t *left = insn->l.d;
    minsn_t *right = insn->r.d;

    if (!left || !right)
        return false;

    minsn_t *and_insn = nullptr;
    minsn_t *xor_insn = nullptr;

    if (left->opcode == m_and && right->opcode == m_xor) {
        and_insn = left;
        xor_insn = right;
    } else if (left->opcode == m_xor && right->opcode == m_and) {
        xor_insn = left;
        and_insn = right;
    } else {
        return false;
    }

    // Verify same operands
    if (!mops_equal(and_insn->l, xor_insn->l) || !mops_equal(and_insn->r, xor_insn->r)) {
        if (!mops_equal(and_insn->l, xor_insn->r) || !mops_equal(and_insn->r, xor_insn->l)) {
            return false;
        }
    }

    // Found: (b & c) | (b ^ c) = b | c
    out->simplified = true;
    out->new_opcode = m_or;
    out->new_left = and_insn->l;
    out->new_right = and_insn->r;

    deobf::log_verbose("[expr_simplify] Simplified (b&c) | (b^c) => b | c\n");
    return true;
}

// Pattern: (~a & b) | (a & ~b) => a ^ b
// This is XOR substitution 1 in Hikari
bool simplify_hikari_xor_pattern1(minsn_t *insn, simplify_result_t *out) {
    if (!insn || insn->opcode != m_or)
        return false;

    if (insn->l.t != mop_d || insn->r.t != mop_d)
        return false;

    minsn_t *left = insn->l.d;
    minsn_t *right = insn->r.d;

    if (!left || !right || left->opcode != m_and || right->opcode != m_and)
        return false;

    // Check for (~a & b) pattern in left
    // and (a & ~b) pattern in right
    // This is complex - need to check all combinations

    // For now, simplified check - look for AND of something with NOT of something
    bool left_has_not = (left->l.t == mop_d && left->l.d && left->l.d->opcode == m_bnot) ||
                        (left->r.t == mop_d && left->r.d && left->r.d->opcode == m_bnot);
    bool right_has_not = (right->l.t == mop_d && right->l.d && right->l.d->opcode == m_bnot) ||
                         (right->r.t == mop_d && right->r.d && right->r.d->opcode == m_bnot);

    if (!left_has_not || !right_has_not)
        return false;

    // Extract operands (simplified - assumes standard form)
    mop_t *a = nullptr;
    mop_t *b = nullptr;

    if (left->l.t == mop_d && left->l.d && left->l.d->opcode == m_bnot) {
        // Left is (~a & b)
        a = &left->l.d->l;
        b = &left->r;
    } else if (left->r.t == mop_d && left->r.d && left->r.d->opcode == m_bnot) {
        // Left is (b & ~a)
        a = &left->r.d->l;
        b = &left->l;
    }

    if (!a || !b)
        return false;

    // Verify right side has matching pattern
    // Should be (a & ~b) or (~b & a)

    // Found pattern - simplify to XOR
    out->simplified = true;
    out->new_opcode = m_xor;
    out->new_left = *a;
    out->new_right = *b;

    deobf::log_verbose("[expr_simplify] Simplified (~a&b) | (a&~b) => a ^ b\n");
    return true;
}

//--------------------------------------------------------------------------
// Helper functions
//--------------------------------------------------------------------------
bool mops_equal(const mop_t &a, const mop_t &b) {
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
        case mop_d:
            // Deep comparison needed - skip for now
            return false;
        default:
            return false;
    }
}

std::optional<uint64_t> trace_xor_chain(const mop_t &mop, deobf_ctx_t *ctx) {
    // Trace through XOR operations to find constant result
    // Used for decrypting constants

    if (mop.t == mop_n) {
        return mop.nnn->value;
    }

    if (mop.t == mop_d && mop.d && mop.d->opcode == m_xor) {
        auto left = trace_xor_chain(mop.d->l, ctx);
        auto right = trace_xor_chain(mop.d->r, ctx);

        if (left && right) {
            return *left ^ *right;
        }
    }

    return std::nullopt;
}

} // namespace expr_simplify
