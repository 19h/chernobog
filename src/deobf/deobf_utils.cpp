#include "deobf_types.h"
#include <stdarg.h>

namespace deobf {

static bool g_verbose = false;

void set_verbose(bool v) {
    g_verbose = v;
}

void log(const char *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    vmsg(fmt, va);
    va_end(va);
}

void log_verbose(const char *fmt, ...) {
    if (!g_verbose)
        return;
    va_list va;
    va_start(va, fmt);
    vmsg(fmt, va);
    va_end(va);
}

//--------------------------------------------------------------------------
// Microcode helpers
//--------------------------------------------------------------------------
minsn_t *find_insn_by_opcode(mblock_t *blk, mcode_t op) {
    if (!blk)
        return nullptr;

    for (minsn_t *insn = blk->head; insn; insn = insn->next) {
        if (insn->opcode == op)
            return insn;
    }
    return nullptr;
}

bool is_jcc(mcode_t op) {
    return op >= m_jcnd && op <= m_jle;
}

bool is_unconditional_jmp(mcode_t op) {
    return op == m_goto || op == m_ijmp;
}

const char *mcode_name(mcode_t op) {
    static const char *names[] = {
        "m_nop", "m_stx", "m_ldx", "m_ldc", "m_mov", "m_neg", "m_lnot", "m_bnot",
        "m_xds", "m_xdu", "m_low", "m_high", "m_add", "m_sub", "m_mul", "m_udiv",
        "m_sdiv", "m_umod", "m_smod", "m_or", "m_and", "m_xor", "m_shl", "m_shr",
        "m_sar", "m_cfadd", "m_ofadd", "m_cfshl", "m_cfshr", "m_sets", "m_seto",
        "m_setp", "m_setnz", "m_setz", "m_setae", "m_setb", "m_seta", "m_setbe",
        "m_setg", "m_setge", "m_setl", "m_setle", "m_jcnd", "m_jnz", "m_jz",
        "m_jae", "m_jb", "m_ja", "m_jbe", "m_jg", "m_jge", "m_jl", "m_jle",
        "m_jtbl", "m_ijmp", "m_goto", "m_call", "m_icall", "m_ret", "m_push",
        "m_pop", "m_und", "m_ext", "m_f2i", "m_f2u", "m_i2f", "m_u2f", "m_f2f",
        "m_fneg", "m_fadd", "m_fsub", "m_fmul", "m_fdiv"
    };

    if (op < sizeof(names)/sizeof(names[0]))
        return names[op];
    return "m_unknown";
}

//--------------------------------------------------------------------------
// Pattern matching helpers
//--------------------------------------------------------------------------
bool match_xor_pattern(minsn_t *insn, mop_t **out_left, mop_t **out_right) {
    if (!insn || insn->opcode != m_xor)
        return false;

    if (out_left)
        *out_left = &insn->l;
    if (out_right)
        *out_right = &insn->r;

    return true;
}

bool match_load_xor_pattern(mblock_t *blk, ea_t *out_enc_addr, uint64_t *out_key) {
    // Look for pattern:
    //   load tmp, [gvar1]
    //   xor result, tmp, const  (or xor result, tmp, [gvar2])

    for (minsn_t *insn = blk->head; insn; insn = insn->next) {
        if (insn->opcode != m_xor)
            continue;

        // Check if one operand is a global variable load
        mop_t *load_op = nullptr;
        mop_t *key_op = nullptr;

        if (insn->l.t == mop_v) {  // Left is a kreg that may have been loaded
            // Need to trace back to find the load
        }

        if (insn->r.t == mop_n) {  // Right is immediate
            key_op = &insn->r;
            load_op = &insn->l;
        } else if (insn->l.t == mop_n) {  // Left is immediate
            key_op = &insn->l;
            load_op = &insn->r;
        }

        if (key_op && load_op && key_op->t == mop_n) {
            if (out_key)
                *out_key = key_op->nnn->value;

            // Try to find the source address
            if (load_op->t == mop_v) {
                // It's a global variable
                if (out_enc_addr)
                    *out_enc_addr = load_op->g;
                return true;
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Expression analysis
//--------------------------------------------------------------------------
sym_expr_ptr mop_to_sym(const mop_t &mop, deobf_ctx_t *ctx) {
    switch (mop.t) {
        case mop_n:  // Immediate number
            return sym_expr_t::make_const(mop.nnn->value, mop.size * 8);

        case mop_r:  // Register
            return sym_expr_t::make_var(mop.r, mop.size * 8);

        case mop_v:  // Global variable
            return sym_expr_t::make_var(0x10000 + (int)(mop.g & 0xFFFF), mop.size * 8);

        case mop_S:  // Stack variable
            return sym_expr_t::make_var(0x20000 + mop.s->off, mop.size * 8);

        case mop_d: { // Nested instruction result
            if (!mop.d)
                return nullptr;

            minsn_t *nested = mop.d;
            sym_expr_ptr left = mop_to_sym(nested->l, ctx);
            sym_expr_ptr right = mop_to_sym(nested->r, ctx);

            sym_expr_t::op_t op;
            switch (nested->opcode) {
                case m_add: op = sym_expr_t::OP_ADD; break;
                case m_sub: op = sym_expr_t::OP_SUB; break;
                case m_mul: op = sym_expr_t::OP_MUL; break;
                case m_and: op = sym_expr_t::OP_AND; break;
                case m_or:  op = sym_expr_t::OP_OR;  break;
                case m_xor: op = sym_expr_t::OP_XOR; break;
                case m_shl: op = sym_expr_t::OP_SHL; break;
                case m_shr: op = sym_expr_t::OP_SHR; break;
                case m_sar: op = sym_expr_t::OP_SAR; break;
                case m_neg: op = sym_expr_t::OP_NEG; break;
                case m_bnot: op = sym_expr_t::OP_NOT; break;
                default: return nullptr;
            }

            if (op == sym_expr_t::OP_NEG || op == sym_expr_t::OP_NOT)
                return sym_expr_t::make_unop(op, left);
            else
                return sym_expr_t::make_binop(op, left, right);
        }

        default:
            return nullptr;
    }
}

sym_expr_ptr simplify_expr(sym_expr_ptr expr) {
    if (!expr)
        return nullptr;

    // Recursively simplify children first
    if (expr->left)
        expr->left = simplify_expr(expr->left);
    if (expr->right)
        expr->right = simplify_expr(expr->right);

    // Constant folding
    if (expr->left && expr->left->is_const() &&
        expr->right && expr->right->is_const()) {

        uint64_t l = expr->left->const_val;
        uint64_t r = expr->right->const_val;
        uint64_t result = 0;

        switch (expr->op) {
            case sym_expr_t::OP_ADD: result = l + r; break;
            case sym_expr_t::OP_SUB: result = l - r; break;
            case sym_expr_t::OP_MUL: result = l * r; break;
            case sym_expr_t::OP_AND: result = l & r; break;
            case sym_expr_t::OP_OR:  result = l | r; break;
            case sym_expr_t::OP_XOR: result = l ^ r; break;
            case sym_expr_t::OP_SHL: result = l << r; break;
            case sym_expr_t::OP_SHR: result = l >> r; break;
            default: return expr;
        }

        return sym_expr_t::make_const(result, expr->bit_size);
    }

    // Unary constant folding
    if (expr->left && expr->left->is_const() && !expr->right) {
        uint64_t v = expr->left->const_val;
        uint64_t result = 0;

        switch (expr->op) {
            case sym_expr_t::OP_NEG: result = -v; break;
            case sym_expr_t::OP_NOT: result = ~v; break;
            default: return expr;
        }

        return sym_expr_t::make_const(result, expr->bit_size);
    }

    // Algebraic simplifications
    // x XOR x = 0
    if (expr->op == sym_expr_t::OP_XOR &&
        expr->left && expr->right &&
        expr->left->is_var() && expr->right->is_var() &&
        expr->left->var_idx == expr->right->var_idx) {
        return sym_expr_t::make_const(0, expr->bit_size);
    }

    // x XOR 0 = x
    if (expr->op == sym_expr_t::OP_XOR && expr->right && expr->right->is_const() &&
        expr->right->const_val == 0) {
        return expr->left;
    }

    // x AND 0 = 0
    if (expr->op == sym_expr_t::OP_AND && expr->right && expr->right->is_const() &&
        expr->right->const_val == 0) {
        return sym_expr_t::make_const(0, expr->bit_size);
    }

    // x OR 0 = x
    if (expr->op == sym_expr_t::OP_OR && expr->right && expr->right->is_const() &&
        expr->right->const_val == 0) {
        return expr->left;
    }

    // x + 0 = x
    if (expr->op == sym_expr_t::OP_ADD && expr->right && expr->right->is_const() &&
        expr->right->const_val == 0) {
        return expr->left;
    }

    // x - 0 = x
    if (expr->op == sym_expr_t::OP_SUB && expr->right && expr->right->is_const() &&
        expr->right->const_val == 0) {
        return expr->left;
    }

    // NOT(NOT(x)) = x
    if (expr->op == sym_expr_t::OP_NOT && expr->left &&
        expr->left->op == sym_expr_t::OP_NOT) {
        return expr->left->left;
    }

    // NEG(NEG(x)) = x
    if (expr->op == sym_expr_t::OP_NEG && expr->left &&
        expr->left->op == sym_expr_t::OP_NEG) {
        return expr->left->left;
    }

    return expr;
}

std::optional<uint64_t> eval_const_expr(sym_expr_ptr expr) {
    sym_expr_ptr simplified = simplify_expr(expr);
    if (simplified && simplified->is_const())
        return simplified->const_val;
    return std::nullopt;
}

bool exprs_equivalent(sym_expr_ptr a, sym_expr_ptr b) {
    if (!a || !b)
        return a == b;

    if (a->op != b->op)
        return false;

    if (a->is_const() && b->is_const())
        return a->const_val == b->const_val;

    if (a->is_var() && b->is_var())
        return a->var_idx == b->var_idx;

    return exprs_equivalent(a->left, b->left) &&
           exprs_equivalent(a->right, b->right);
}

} // namespace deobf
