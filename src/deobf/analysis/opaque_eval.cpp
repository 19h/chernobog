#include "opaque_eval.h"

// Static members
std::map<ea_t, uint64_t> opaque_eval_t::s_global_cache;

//--------------------------------------------------------------------------
// Clear cache
//--------------------------------------------------------------------------
void opaque_eval_t::clear_cache() {
    s_global_cache.clear();
}

//--------------------------------------------------------------------------
// Evaluate a condition to determine if it's always true/false
//--------------------------------------------------------------------------
bool opaque_eval_t::evaluate_condition(minsn_t *cond, bool *out_result) {
    if (!cond || !out_result)
        return false;

    eval_state_t state;
    state.depth = 0;

    // Handle conditional jumps
    if (cond->opcode == m_jnz || cond->opcode == m_jz ||
        cond->opcode == m_jg || cond->opcode == m_jge ||
        cond->opcode == m_jl || cond->opcode == m_jle ||
        cond->opcode == m_ja || cond->opcode == m_jae ||
        cond->opcode == m_jb || cond->opcode == m_jbe) {

        // Evaluate the left operand (condition value)
        auto left_val = eval_mop(cond->l, state);
        if (!left_val.has_value())
            return false;

        auto right_val = eval_mop(cond->r, state);
        if (!right_val.has_value())
            return false;

        uint64_t l = *left_val;
        uint64_t r = *right_val;
        int64_t sl = sign_extend(l, cond->l.size);
        int64_t sr = sign_extend(r, cond->r.size);

        bool result = false;
        switch (cond->opcode) {
            case m_jnz:  result = (l != r); break;
            case m_jz:   result = (l == r); break;
            case m_jg:   result = (sl > sr); break;
            case m_jge:  result = (sl >= sr); break;
            case m_jl:   result = (sl < sr); break;
            case m_jle:  result = (sl <= sr); break;
            case m_ja:   result = (l > r); break;
            case m_jae:  result = (l >= r); break;
            case m_jb:   result = (l < r); break;
            case m_jbe:  result = (l <= r); break;
            default: return false;
        }

        *out_result = result;
        return true;
    }

    // Handle setX instructions
    if (cond->opcode == m_setnz || cond->opcode == m_setz ||
        cond->opcode == m_setg || cond->opcode == m_setge ||
        cond->opcode == m_setl || cond->opcode == m_setle ||
        cond->opcode == m_seta || cond->opcode == m_setae ||
        cond->opcode == m_setb || cond->opcode == m_setbe) {

        auto left_val = eval_mop(cond->l, state);
        auto right_val = eval_mop(cond->r, state);

        if (!left_val.has_value() || !right_val.has_value())
            return false;

        uint64_t l = *left_val;
        uint64_t r = *right_val;
        int64_t sl = sign_extend(l, cond->l.size);
        int64_t sr = sign_extend(r, cond->r.size);

        bool result = false;
        switch (cond->opcode) {
            case m_setnz: result = (l != r); break;
            case m_setz:  result = (l == r); break;
            case m_setg:  result = (sl > sr); break;
            case m_setge: result = (sl >= sr); break;
            case m_setl:  result = (sl < sr); break;
            case m_setle: result = (sl <= sr); break;
            case m_seta:  result = (l > r); break;
            case m_setae: result = (l >= r); break;
            case m_setb:  result = (l < r); break;
            case m_setbe: result = (l <= r); break;
            default: return false;
        }

        *out_result = result;
        return true;
    }

    // Try to evaluate as a general expression
    auto val = eval_insn(cond, state);
    if (val.has_value()) {
        *out_result = (*val != 0);
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Evaluate expression to constant
//--------------------------------------------------------------------------
std::optional<uint64_t> opaque_eval_t::evaluate_expr(minsn_t *expr) {
    if (!expr)
        return std::nullopt;

    eval_state_t state;
    state.depth = 0;
    return eval_insn(expr, state);
}

std::optional<uint64_t> opaque_eval_t::evaluate_operand(const mop_t &op) {
    eval_state_t state;
    state.depth = 0;
    return eval_mop(op, state);
}

//--------------------------------------------------------------------------
// Read global from binary
//--------------------------------------------------------------------------
std::optional<uint64_t> opaque_eval_t::read_global(ea_t addr, int size) {
    // Check cache
    auto it = s_global_cache.find(addr);
    if (it != s_global_cache.end()) {
        return mask_by_size(it->second, size);
    }

    // Read from binary
    uint64_t val = 0;
    int bytes_to_read = (size > 0) ? size : (inf_is_64bit() ? 8 : 4);

    if (bytes_to_read > 8)
        bytes_to_read = 8;

    if (get_bytes(&val, bytes_to_read, addr) != bytes_to_read) {
        return std::nullopt;
    }

    // Cache and return
    s_global_cache[addr] = val;
    return mask_by_size(val, size);
}

//--------------------------------------------------------------------------
// Core instruction evaluation
//--------------------------------------------------------------------------
std::optional<uint64_t> opaque_eval_t::eval_insn(minsn_t *ins, eval_state_t &state) {
    if (!ins || state.depth > MAX_EVAL_DEPTH)
        return std::nullopt;

    state.depth++;

    std::optional<uint64_t> result;
    int size = ins->d.size > 0 ? ins->d.size : 4;

    // Get operand values
    auto l_val = eval_mop(ins->l, state);
    auto r_val = eval_mop(ins->r, state);

    switch (ins->opcode) {
        case m_mov:
        case m_ldx:
            result = l_val;
            break;

        case m_add:
            if (l_val && r_val)
                result = eval_add(*l_val, *r_val, size);
            break;

        case m_sub:
            if (l_val && r_val)
                result = eval_sub(*l_val, *r_val, size);
            break;

        case m_mul:
            if (l_val && r_val)
                result = eval_mul(*l_val, *r_val, size);
            break;

        case m_udiv:
            if (l_val && r_val && *r_val != 0)
                result = eval_udiv(*l_val, *r_val, size);
            break;

        case m_sdiv:
            if (l_val && r_val && *r_val != 0)
                result = eval_sdiv(sign_extend(*l_val, size), sign_extend(*r_val, size), size);
            break;

        case m_umod:
            if (l_val && r_val && *r_val != 0)
                result = eval_umod(*l_val, *r_val, size);
            break;

        case m_smod:
            if (l_val && r_val && *r_val != 0)
                result = eval_smod(sign_extend(*l_val, size), sign_extend(*r_val, size), size);
            break;

        case m_and:
            if (l_val && r_val)
                result = eval_and(*l_val, *r_val, size);
            break;

        case m_or:
            if (l_val && r_val)
                result = eval_or(*l_val, *r_val, size);
            break;

        case m_xor:
            if (l_val && r_val)
                result = eval_xor(*l_val, *r_val, size);
            break;

        case m_bnot:
        case m_lnot:
            if (l_val)
                result = eval_not(*l_val, size);
            break;

        case m_neg:
            if (l_val)
                result = eval_neg(*l_val, size);
            break;

        case m_shl:
            if (l_val && r_val)
                result = eval_shl(*l_val, *r_val, size);
            break;

        case m_shr:
            if (l_val && r_val)
                result = eval_shr(*l_val, *r_val, size);
            break;

        case m_sar:
            if (l_val && r_val)
                result = eval_sar(sign_extend(*l_val, size), *r_val, size);
            break;

        // Set operations (return 0 or 1)
        case m_setz:
            if (l_val && r_val) {
                auto b = eval_setz(*l_val - *r_val);
                if (b) result = *b ? 1 : 0;
            }
            break;

        case m_setnz:
            if (l_val && r_val) {
                auto b = eval_setnz(*l_val - *r_val);
                if (b) result = *b ? 1 : 0;
            }
            break;

        case m_setl:
            if (l_val && r_val) {
                auto b = eval_setl(sign_extend(*l_val, size), sign_extend(*r_val, size));
                if (b) result = *b ? 1 : 0;
            }
            break;

        case m_setle:
            if (l_val && r_val) {
                auto b = eval_setle(sign_extend(*l_val, size), sign_extend(*r_val, size));
                if (b) result = *b ? 1 : 0;
            }
            break;

        case m_setg:
            if (l_val && r_val) {
                auto b = eval_setg(sign_extend(*l_val, size), sign_extend(*r_val, size));
                if (b) result = *b ? 1 : 0;
            }
            break;

        case m_setge:
            if (l_val && r_val) {
                auto b = eval_setge(sign_extend(*l_val, size), sign_extend(*r_val, size));
                if (b) result = *b ? 1 : 0;
            }
            break;

        case m_setb:
            if (l_val && r_val) {
                auto b = eval_setb(*l_val, *r_val);
                if (b) result = *b ? 1 : 0;
            }
            break;

        case m_setbe:
            if (l_val && r_val) {
                auto b = eval_setbe(*l_val, *r_val);
                if (b) result = *b ? 1 : 0;
            }
            break;

        case m_seta:
            if (l_val && r_val) {
                auto b = eval_seta(*l_val, *r_val);
                if (b) result = *b ? 1 : 0;
            }
            break;

        case m_setae:
            if (l_val && r_val) {
                auto b = eval_setae(*l_val, *r_val);
                if (b) result = *b ? 1 : 0;
            }
            break;

        default:
            // Unknown operation
            break;
    }

    state.depth--;
    return result;
}

//--------------------------------------------------------------------------
// Operand evaluation
//--------------------------------------------------------------------------
std::optional<uint64_t> opaque_eval_t::eval_mop(const mop_t &op, eval_state_t &state) {
    switch (op.t) {
        case mop_n:
            // Immediate value
            return mask_by_size(op.nnn->value, op.size);

        case mop_v:
            // Global variable - read from binary
            return read_global(op.g, op.size);

        case mop_d:
            // Sub-instruction result
            if (op.d)
                return eval_insn(op.d, state);
            break;

        case mop_r:
            // Register - check if we have a cached value
            if (state.temps.count(op.r))
                return state.temps[op.r];
            break;

        case mop_z:
            // Zero
            return 0;

        case mop_a:
            // Address - mop_addr_t inherits from mop_t
            // The actual address is in the contained operand
            if (op.a) {
                // If pointing to a global, return the global address
                if (op.a->t == mop_v)
                    return op.a->g;
            }
            break;

        case mop_l:
            // Local variable - generally can't evaluate statically
            break;

        case mop_S:
            // Stack variable - generally can't evaluate statically
            break;

        default:
            break;
    }

    return std::nullopt;
}

//--------------------------------------------------------------------------
// Arithmetic operations
//--------------------------------------------------------------------------
std::optional<uint64_t> opaque_eval_t::eval_add(uint64_t a, uint64_t b, int size) {
    return mask_by_size(a + b, size);
}

std::optional<uint64_t> opaque_eval_t::eval_sub(uint64_t a, uint64_t b, int size) {
    return mask_by_size(a - b, size);
}

std::optional<uint64_t> opaque_eval_t::eval_mul(uint64_t a, uint64_t b, int size) {
    return mask_by_size(a * b, size);
}

std::optional<uint64_t> opaque_eval_t::eval_udiv(uint64_t a, uint64_t b, int size) {
    if (b == 0) return std::nullopt;
    return mask_by_size(a / b, size);
}

std::optional<uint64_t> opaque_eval_t::eval_sdiv(int64_t a, int64_t b, int size) {
    if (b == 0) return std::nullopt;
    return mask_by_size((uint64_t)(a / b), size);
}

std::optional<uint64_t> opaque_eval_t::eval_umod(uint64_t a, uint64_t b, int size) {
    if (b == 0) return std::nullopt;
    return mask_by_size(a % b, size);
}

std::optional<uint64_t> opaque_eval_t::eval_smod(int64_t a, int64_t b, int size) {
    if (b == 0) return std::nullopt;
    return mask_by_size((uint64_t)(a % b), size);
}

//--------------------------------------------------------------------------
// Bitwise operations
//--------------------------------------------------------------------------
std::optional<uint64_t> opaque_eval_t::eval_and(uint64_t a, uint64_t b, int size) {
    return mask_by_size(a & b, size);
}

std::optional<uint64_t> opaque_eval_t::eval_or(uint64_t a, uint64_t b, int size) {
    return mask_by_size(a | b, size);
}

std::optional<uint64_t> opaque_eval_t::eval_xor(uint64_t a, uint64_t b, int size) {
    return mask_by_size(a ^ b, size);
}

std::optional<uint64_t> opaque_eval_t::eval_not(uint64_t a, int size) {
    return mask_by_size(~a, size);
}

std::optional<uint64_t> opaque_eval_t::eval_neg(uint64_t a, int size) {
    return mask_by_size((uint64_t)(-(int64_t)a), size);
}

//--------------------------------------------------------------------------
// Shift operations
//--------------------------------------------------------------------------
std::optional<uint64_t> opaque_eval_t::eval_shl(uint64_t a, uint64_t b, int size) {
    if (b >= 64) return 0;
    return mask_by_size(a << b, size);
}

std::optional<uint64_t> opaque_eval_t::eval_shr(uint64_t a, uint64_t b, int size) {
    if (b >= 64) return 0;
    return mask_by_size(a >> b, size);
}

std::optional<uint64_t> opaque_eval_t::eval_sar(int64_t a, uint64_t b, int size) {
    if (b >= 64) return (a < 0) ? mask_by_size(-1, size) : 0;
    return mask_by_size((uint64_t)(a >> b), size);
}

//--------------------------------------------------------------------------
// Comparison operations
//--------------------------------------------------------------------------
std::optional<bool> opaque_eval_t::eval_setz(uint64_t a) {
    return a == 0;
}

std::optional<bool> opaque_eval_t::eval_setnz(uint64_t a) {
    return a != 0;
}

std::optional<bool> opaque_eval_t::eval_setl(int64_t a, int64_t b) {
    return a < b;
}

std::optional<bool> opaque_eval_t::eval_setle(int64_t a, int64_t b) {
    return a <= b;
}

std::optional<bool> opaque_eval_t::eval_setg(int64_t a, int64_t b) {
    return a > b;
}

std::optional<bool> opaque_eval_t::eval_setge(int64_t a, int64_t b) {
    return a >= b;
}

std::optional<bool> opaque_eval_t::eval_setb(uint64_t a, uint64_t b) {
    return a < b;
}

std::optional<bool> opaque_eval_t::eval_setbe(uint64_t a, uint64_t b) {
    return a <= b;
}

std::optional<bool> opaque_eval_t::eval_seta(uint64_t a, uint64_t b) {
    return a > b;
}

std::optional<bool> opaque_eval_t::eval_setae(uint64_t a, uint64_t b) {
    return a >= b;
}

//--------------------------------------------------------------------------
// Helper functions
//--------------------------------------------------------------------------
uint64_t opaque_eval_t::mask_by_size(uint64_t val, int size) {
    switch (size) {
        case 1: return val & 0xFF;
        case 2: return val & 0xFFFF;
        case 4: return val & 0xFFFFFFFF;
        case 8:
        default: return val;
    }
}

int64_t opaque_eval_t::sign_extend(uint64_t val, int size) {
    switch (size) {
        case 1: return (int64_t)(int8_t)(val & 0xFF);
        case 2: return (int64_t)(int16_t)(val & 0xFFFF);
        case 4: return (int64_t)(int32_t)(val & 0xFFFFFFFF);
        case 8:
        default: return (int64_t)val;
    }
}
