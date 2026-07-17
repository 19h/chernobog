#include "opaque_eval.h"
#include "z3_solver.h"
#include "../../common/bitvector.h"
#include "../../common/ida_memory.h"

// Static members
std::map<std::pair<ea_t, int>, uint64_t> opaque_eval_t::s_global_cache;
static constexpr unsigned OPAQUE_Z3_TIMEOUT_MS = 1000;

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
    if (!cond || !out_result || cond->is_fpinsn())
        return false;

    eval_state_t state;
    state.depth = 0;

    // Handle conditional jumps
    if (cond->opcode == m_jcnd) {
        auto value = eval_mop(cond->l, state);
        if (!value.has_value())
            return false;
        *out_result = *value != 0;
        return true;
    }

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
    if (!expr || expr->is_fpinsn())
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
    const int bytes_to_read = size > 0 ? size : (inf_is_64bit() ? 8 : 4);
    if (!chernobog::bitvector::valid_byte_width(bytes_to_read)) {
        return std::nullopt;
    }

    // A value from writable storage is an initial database value, not an
    // invariant. Folding it into an opaque-predicate proof could delete a
    // branch whose value changes at runtime.
    segment_t *segment = getseg(addr);
    if (!segment || (segment->perm & SEGPERM_WRITE) != 0) {
        return std::nullopt;
    }

    // Check cache
    const auto cache_key = std::make_pair(addr, bytes_to_read);
    auto it = s_global_cache.find(cache_key);
    if (it != s_global_cache.end()) {
        return it->second;
    }

    // Read from binary
    auto value = chernobog::ida_memory::read_integer(addr, bytes_to_read);
    if (!value) {
        return std::nullopt;
    }

    // Cache and return
    uint64_t val = mask_by_size(*value, bytes_to_read);
    s_global_cache[cache_key] = val;
    return val;
}

//--------------------------------------------------------------------------
// Core instruction evaluation
//--------------------------------------------------------------------------
std::optional<uint64_t> opaque_eval_t::eval_insn(minsn_t *ins, eval_state_t &state) {
    if (!ins || ins->is_fpinsn() || state.depth > MAX_EVAL_DEPTH)
        return std::nullopt;

    state.depth++;

    std::optional<uint64_t> result;
    int size = ins->d.size > 0 ? ins->d.size : 4;

    // Get operand values
    auto l_val = eval_mop(ins->l, state);
    auto r_val = eval_mop(ins->r, state);

    switch (ins->opcode) {
        case m_mov:
            result = l_val;
            break;

        case m_ldx: {
            // Hex-Rays defines l as the segment selector and r as the memory
            // offset. Never treat the selector as the loaded value.
            ea_t address = BADADDR;
            if (ins->r.t == mop_v) {
                address = ins->r.g;
            } else if (ins->r.t == mop_a && ins->r.a && ins->r.a->t == mop_v) {
                address = ins->r.a->g;
            } else if (ins->r.t == mop_n && ins->r.nnn) {
                address = static_cast<ea_t>(ins->r.nnn->value);
            }
            if (address != BADADDR) {
                result = read_global(address, size);
            }
            break;
        }

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
            if (l_val)
                result = eval_not(*l_val, size);
            break;

        case m_lnot:
            if (l_val)
                result = chernobog::bitvector::logical_not(*l_val);
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
                auto b = eval_setl(sign_extend(*l_val, ins->l.size),
                                   sign_extend(*r_val, ins->r.size));
                if (b) result = *b ? 1 : 0;
            }
            break;

        case m_setle:
            if (l_val && r_val) {
                auto b = eval_setle(sign_extend(*l_val, ins->l.size),
                                    sign_extend(*r_val, ins->r.size));
                if (b) result = *b ? 1 : 0;
            }
            break;

        case m_setg:
            if (l_val && r_val) {
                auto b = eval_setg(sign_extend(*l_val, ins->l.size),
                                   sign_extend(*r_val, ins->r.size));
                if (b) result = *b ? 1 : 0;
            }
            break;

        case m_setge:
            if (l_val && r_val) {
                auto b = eval_setge(sign_extend(*l_val, ins->l.size),
                                    sign_extend(*r_val, ins->r.size));
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
    if (a == chernobog::bitvector::signed_min(size) && b == -1)
        return std::nullopt;
    return mask_by_size((uint64_t)(a / b), size);
}

std::optional<uint64_t> opaque_eval_t::eval_umod(uint64_t a, uint64_t b, int size) {
    if (b == 0) return std::nullopt;
    return mask_by_size(a % b, size);
}

std::optional<uint64_t> opaque_eval_t::eval_smod(int64_t a, int64_t b, int size) {
    if (b == 0) return std::nullopt;
    if (a == chernobog::bitvector::signed_min(size) && b == -1)
        return std::nullopt;
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
    return chernobog::bitvector::negate(a, size);
}

//--------------------------------------------------------------------------
// Shift operations
//--------------------------------------------------------------------------
std::optional<uint64_t> opaque_eval_t::eval_shl(uint64_t a, uint64_t b, int size) {
    return chernobog::bitvector::shift_left(a, b, size);
}

std::optional<uint64_t> opaque_eval_t::eval_shr(uint64_t a, uint64_t b, int size) {
    return chernobog::bitvector::shift_right_logical(a, b, size);
}

std::optional<uint64_t> opaque_eval_t::eval_sar(int64_t a, uint64_t b, int size) {
    return chernobog::bitvector::shift_right_arithmetic(
        static_cast<uint64_t>(a), b, size);
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
    return chernobog::bitvector::truncate(val, size);
}

int64_t opaque_eval_t::sign_extend(uint64_t val, int size) {
    return chernobog::bitvector::sign_extend(val, size);
}

//--------------------------------------------------------------------------
// Check if condition is an opaque predicate using Z3
//--------------------------------------------------------------------------
opaque_eval_t::opaque_result_t opaque_eval_t::check_opaque_predicate(minsn_t *cond) {
    if (!cond)
        return OPAQUE_UNKNOWN;
    if (cond->is_fpinsn())
        return OPAQUE_UNKNOWN;

    // First try simple evaluation
    bool result;
    if (evaluate_condition(cond, &result)) {
        return result ? OPAQUE_ALWAYS_TRUE : OPAQUE_ALWAYS_FALSE;
    }

    // Use Z3 for complex predicates
    try {
        z3_solver::set_global_timeout(OPAQUE_Z3_TIMEOUT_MS);
        z3_solver::opaque_predicate_solver_t solver(z3_solver::get_global_context());
        auto z3_result = solver.analyze_condition(cond);

        switch (z3_result) {
            case z3_solver::opaque_predicate_solver_t::PRED_ALWAYS_TRUE:
                return OPAQUE_ALWAYS_TRUE;
            case z3_solver::opaque_predicate_solver_t::PRED_ALWAYS_FALSE:
                return OPAQUE_ALWAYS_FALSE;
            case z3_solver::opaque_predicate_solver_t::PRED_DEPENDS_ON_INPUT:
                return OPAQUE_NOT_OPAQUE;
            default:
                return OPAQUE_UNKNOWN;
        }
    } catch (...) {
        return OPAQUE_UNKNOWN;
    }
}
