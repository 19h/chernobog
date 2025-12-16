#include "z3_solver.h"
#include "opaque_eval.h"

namespace z3_solver {

//--------------------------------------------------------------------------
// Global context management
//--------------------------------------------------------------------------
static std::unique_ptr<z3_context_t> g_context;
static unsigned g_timeout_ms = 5000;  // Default 5 second timeout

z3_context_t& get_global_context() {
    if (!g_context) {
        g_context = std::make_unique<z3_context_t>();
        g_context->set_timeout(g_timeout_ms);
    }
    return *g_context;
}

void reset_global_context() {
    if (g_context) {
        g_context->reset();
    }
}

void set_global_timeout(unsigned ms) {
    g_timeout_ms = ms;
    if (g_context) {
        g_context->set_timeout(ms);
    }
}

//--------------------------------------------------------------------------
// z3_context_t implementation
//--------------------------------------------------------------------------
z3_context_t::z3_context_t() : m_ctx(), m_solver(m_ctx) {
}

z3_context_t::~z3_context_t() {
}

void z3_context_t::reset() {
    m_solver.reset();
}

void z3_context_t::set_timeout(unsigned ms) {
    if (ms > 0) {
        z3::params p(m_ctx);
        p.set(":timeout", ms);
        m_solver.set(p);
    }
}

//--------------------------------------------------------------------------
// mcode_translator_t implementation
//--------------------------------------------------------------------------
mcode_translator_t::mcode_translator_t(z3_context_t& ctx)
    : m_ctx(ctx), m_fresh_counter(0) {
}

void mcode_translator_t::reset() {
    m_var_cache.clear();
    m_known_values.clear();
    m_fresh_counter = 0;
}

symbolic_var_t mcode_translator_t::mop_to_var(const mop_t& op) {
    switch (op.t) {
        case mop_r:
            return symbolic_var_t(symbolic_var_t::VAR_REGISTER, op.r, op.size);

        case mop_S:
            if (op.s) {
                return symbolic_var_t(symbolic_var_t::VAR_STACK, op.s->off, op.size);
            }
            break;

        case mop_v:
            return symbolic_var_t(symbolic_var_t::VAR_GLOBAL, op.g, op.size);

        case mop_l:
            if (op.l) {
                return symbolic_var_t(symbolic_var_t::VAR_LOCAL, op.l->idx, op.size);
            }
            break;

        default:
            break;
    }
    return symbolic_var_t(symbolic_var_t::VAR_TEMP, m_fresh_counter++, op.size);
}

z3::expr mcode_translator_t::make_const(uint64_t value, int bits) {
    return m_ctx.ctx().bv_val(value, bits);
}

z3::expr mcode_translator_t::make_symbolic(const symbolic_var_t& var) {
    // Check if we have a known value for this variable
    auto it = m_known_values.find(var);
    if (it != m_known_values.end()) {
        return make_const(it->second, var.size() * 8);
    }

    // Check cache
    auto cache_it = m_var_cache.find(var);
    if (cache_it != m_var_cache.end()) {
        return *cache_it->second;
    }

    // Create fresh symbolic variable
    int bits = var.size() * 8;
    if (bits <= 0) bits = 32;  // Default to 32-bit

    std::string name;
    switch (var.kind()) {
        case symbolic_var_t::VAR_REGISTER:
            name = "r" + std::to_string(var.id());
            break;
        case symbolic_var_t::VAR_STACK:
            name = "stk_" + std::to_string((int64_t)var.id());
            break;
        case symbolic_var_t::VAR_GLOBAL:
            name = "g_" + std::to_string(var.id());
            break;
        case symbolic_var_t::VAR_LOCAL:
            name = "l" + std::to_string(var.id());
            break;
        default:
            name = "tmp_" + std::to_string(m_fresh_counter++);
            break;
    }

    z3::expr e = m_ctx.ctx().bv_const(name.c_str(), bits);
    m_var_cache[var] = std::make_shared<z3::expr>(e);
    return e;
}

z3::expr mcode_translator_t::make_symbolic(const mop_t& op) {
    return make_symbolic(mop_to_var(op));
}

z3::expr mcode_translator_t::get_or_create_var(const mop_t& op) {
    symbolic_var_t var = mop_to_var(op);
    return make_symbolic(var);
}

void mcode_translator_t::set_known_value(const symbolic_var_t& var, uint64_t value) {
    m_known_values[var] = value;
    // Update cache to constant
    m_var_cache[var] = std::make_shared<z3::expr>(make_const(value, var.size() * 8));
}

void mcode_translator_t::set_known_value(const mop_t& op, uint64_t value) {
    set_known_value(mop_to_var(op), value);
}

z3::expr mcode_translator_t::zero_extend(const z3::expr& e, int to_bits) {
    int from_bits = e.get_sort().bv_size();
    if (from_bits >= to_bits) {
        return e;
    }
    return z3::zext(e, to_bits - from_bits);
}

z3::expr mcode_translator_t::sign_extend(const z3::expr& e, int to_bits) {
    int from_bits = e.get_sort().bv_size();
    if (from_bits >= to_bits) {
        return e;
    }
    return z3::sext(e, to_bits - from_bits);
}

z3::expr mcode_translator_t::extract(const z3::expr& e, int high, int low) {
    return e.extract(high, low);
}

z3::expr mcode_translator_t::resize(const z3::expr& e, int to_bits, bool sign_ext) {
    int from_bits = e.get_sort().bv_size();
    if (from_bits == to_bits) {
        return e;
    }
    if (from_bits > to_bits) {
        return extract(e, to_bits - 1, 0);
    }
    return sign_ext ? sign_extend(e, to_bits) : zero_extend(e, to_bits);
}

z3::expr mcode_translator_t::translate_operand(const mop_t& op, int default_size) {
    int bits = (op.size > 0 ? op.size : default_size) * 8;
    if (bits <= 0) bits = 32;

    switch (op.t) {
        case mop_n:
            // Immediate constant
            return make_const(op.nnn->value, bits);

        case mop_r:
        case mop_S:
        case mop_v:
        case mop_l:
            return make_symbolic(op);

        case mop_d:
            // Sub-instruction - translate recursively
            if (op.d) {
                return translate_insn(op.d);
            }
            break;

        case mop_z:
            // Zero
            return make_const(0, bits);

        case mop_a:
            // Address operand
            if (op.a && op.a->t == mop_v) {
                return make_const(op.a->g, bits);
            }
            break;

        case mop_b:
            // Block number - return as constant
            return make_const(op.b, bits);

        default:
            break;
    }

    // Fallback: create fresh symbolic variable
    return m_ctx.ctx().bv_const(("unk_" + std::to_string(m_fresh_counter++)).c_str(), bits);
}

z3::expr mcode_translator_t::translate_insn(const minsn_t* ins) {
    if (!ins) {
        return m_ctx.ctx().bv_val(0, 32);
    }

    int bits = ins->d.size > 0 ? ins->d.size * 8 : 32;

    // Translate operands
    z3::expr l = translate_operand(ins->l, bits / 8);
    z3::expr r = translate_operand(ins->r, bits / 8);

    // Ensure operands have matching bit widths for binary operations
    if (l.get_sort().bv_size() != r.get_sort().bv_size()) {
        int max_bits = std::max((int)l.get_sort().bv_size(), (int)r.get_sort().bv_size());
        l = resize(l, max_bits);
        r = resize(r, max_bits);
        bits = max_bits;
    }

    z3::expr result = m_ctx.ctx().bv_val(0, bits);

    switch (ins->opcode) {
        // Data movement
        case m_mov:
        case m_ldx:
            result = l;
            break;

        // Arithmetic
        case m_add:
            result = l + r;
            break;

        case m_sub:
            result = l - r;
            break;

        case m_mul:
            result = l * r;
            break;

        case m_udiv:
            result = z3::udiv(l, r);
            break;

        case m_sdiv:
            result = l / r;  // Z3's default division is signed
            break;

        case m_umod:
            result = z3::urem(l, r);
            break;

        case m_smod:
            result = z3::srem(l, r);
            break;

        // Bitwise
        case m_and:
            result = l & r;
            break;

        case m_or:
            result = l | r;
            break;

        case m_xor:
            result = l ^ r;
            break;

        case m_bnot:
            result = ~l;
            break;

        case m_lnot:
            result = z3::ite(l == 0, m_ctx.ctx().bv_val(1, bits), m_ctx.ctx().bv_val(0, bits));
            break;

        case m_neg:
            result = -l;
            break;

        // Shifts
        case m_shl:
            result = z3::shl(l, r);
            break;

        case m_shr:
            result = z3::lshr(l, r);
            break;

        case m_sar:
            result = z3::ashr(l, r);
            break;

        // Comparisons (return 1 or 0)
        case m_setz:
            result = z3::ite(l == r, m_ctx.ctx().bv_val(1, bits), m_ctx.ctx().bv_val(0, bits));
            break;

        case m_setnz:
            result = z3::ite(l != r, m_ctx.ctx().bv_val(1, bits), m_ctx.ctx().bv_val(0, bits));
            break;

        case m_setl:
            result = z3::ite(l < r, m_ctx.ctx().bv_val(1, bits), m_ctx.ctx().bv_val(0, bits));
            break;

        case m_setle:
            result = z3::ite(l <= r, m_ctx.ctx().bv_val(1, bits), m_ctx.ctx().bv_val(0, bits));
            break;

        case m_setg:
            result = z3::ite(l > r, m_ctx.ctx().bv_val(1, bits), m_ctx.ctx().bv_val(0, bits));
            break;

        case m_setge:
            result = z3::ite(l >= r, m_ctx.ctx().bv_val(1, bits), m_ctx.ctx().bv_val(0, bits));
            break;

        case m_setb:
            result = z3::ite(z3::ult(l, r), m_ctx.ctx().bv_val(1, bits), m_ctx.ctx().bv_val(0, bits));
            break;

        case m_setbe:
            result = z3::ite(z3::ule(l, r), m_ctx.ctx().bv_val(1, bits), m_ctx.ctx().bv_val(0, bits));
            break;

        case m_seta:
            result = z3::ite(z3::ugt(l, r), m_ctx.ctx().bv_val(1, bits), m_ctx.ctx().bv_val(0, bits));
            break;

        case m_setae:
            result = z3::ite(z3::uge(l, r), m_ctx.ctx().bv_val(1, bits), m_ctx.ctx().bv_val(0, bits));
            break;

        // Sign extension
        case m_xds:
            result = sign_extend(l, bits);
            break;

        // Zero extension
        case m_xdu:
            result = zero_extend(l, bits);
            break;

        // Low/high byte operations
        case m_low:
            if (l.get_sort().bv_size() >= bits) {
                result = extract(l, bits - 1, 0);
            } else {
                result = l;
            }
            break;

        case m_high:
            {
                int src_bits = l.get_sort().bv_size();
                if (src_bits > bits) {
                    result = extract(l, src_bits - 1, src_bits - bits);
                } else {
                    result = make_const(0, bits);
                }
            }
            break;

        default:
            // Unknown operation - return fresh variable
            deobf::log_verbose("[z3] Unknown opcode %d in translate_insn\n", ins->opcode);
            result = m_ctx.ctx().bv_const(("insn_" + std::to_string(m_fresh_counter++)).c_str(), bits);
            break;
    }

    return resize(result, bits);
}

z3::expr mcode_translator_t::translate_comparison(const minsn_t* ins) {
    if (!ins) {
        return m_ctx.ctx().bool_val(false);
    }

    z3::expr l = translate_operand(ins->l);
    z3::expr r = translate_operand(ins->r);

    // Ensure matching bit widths
    if (l.get_sort().bv_size() != r.get_sort().bv_size()) {
        int max_bits = std::max((int)l.get_sort().bv_size(), (int)r.get_sort().bv_size());
        l = resize(l, max_bits);
        r = resize(r, max_bits);
    }

    switch (ins->opcode) {
        case m_setz:
            return l == r;
        case m_setnz:
            return l != r;
        case m_setl:
            return l < r;
        case m_setle:
            return l <= r;
        case m_setg:
            return l > r;
        case m_setge:
            return l >= r;
        case m_setb:
            return z3::ult(l, r);
        case m_setbe:
            return z3::ule(l, r);
        case m_seta:
            return z3::ugt(l, r);
        case m_setae:
            return z3::uge(l, r);
        default:
            break;
    }

    // For non-comparison instructions, check if result is non-zero
    z3::expr result = translate_insn(ins);
    return result != 0;
}

z3::expr mcode_translator_t::translate_jcc_condition(const minsn_t* jcc) {
    if (!jcc) {
        return m_ctx.ctx().bool_val(false);
    }

    // For conditional jumps, the condition is typically in the left operand
    z3::expr cond = translate_operand(jcc->l);

    // Handle nested comparison instruction
    if (jcc->l.t == mop_d && jcc->l.d) {
        cond = translate_comparison(jcc->l.d);

        // The jcc type modifies the interpretation
        switch (jcc->opcode) {
            case m_jz:
                return !cond;
            case m_jnz:
                return cond;
            default:
                break;
        }
    }

    // For direct conditions (cond != 0)
    if (cond.is_bv()) {
        switch (jcc->opcode) {
            case m_jz:
                return cond == 0;
            case m_jnz:
                return cond != 0;
            default:
                break;
        }
        return cond != 0;
    }

    return cond;
}

//--------------------------------------------------------------------------
// symbolic_executor_t implementation
//--------------------------------------------------------------------------
symbolic_executor_t::symbolic_executor_t(z3_context_t& ctx)
    : m_ctx(ctx), m_translator(ctx) {
}

void symbolic_executor_t::reset() {
    m_state.clear();
    m_constraints.clear();
    m_translator.reset();
}

std::unique_ptr<symbolic_executor_t> symbolic_executor_t::clone() const {
    auto copy = std::make_unique<symbolic_executor_t>(m_ctx);
    copy->m_state = m_state;
    copy->m_constraints = m_constraints;
    return copy;
}

void symbolic_executor_t::execute_insn(const minsn_t* ins) {
    if (!ins) return;

    switch (ins->opcode) {
        case m_mov:
        case m_ldx:
            handle_assignment(ins);
            break;

        case m_stx:
            handle_store(ins);
            break;

        default:
            // For other instructions, check if they have a destination
            if (ins->d.t != mop_z && ins->d.t != mop_b) {
                handle_assignment(ins);
            }
            break;
    }
}

void symbolic_executor_t::handle_assignment(const minsn_t* ins) {
    if (!ins) return;

    // Translate the instruction to get result expression
    z3::expr value = m_translator.translate_insn(ins);

    // Get destination variable
    if (ins->d.t == mop_r || ins->d.t == mop_S || ins->d.t == mop_v || ins->d.t == mop_l) {
        symbolic_var_t dst_var = symbolic_var_t(
            ins->d.t == mop_r ? symbolic_var_t::VAR_REGISTER :
            ins->d.t == mop_S ? symbolic_var_t::VAR_STACK :
            ins->d.t == mop_v ? symbolic_var_t::VAR_GLOBAL :
            symbolic_var_t::VAR_LOCAL,
            ins->d.t == mop_r ? ins->d.r :
            ins->d.t == mop_S && ins->d.s ? ins->d.s->off :
            ins->d.t == mop_v ? ins->d.g :
            ins->d.l ? ins->d.l->idx : 0,
            ins->d.size
        );
        m_state[dst_var] = std::make_shared<z3::expr>(value);
    }
}

void symbolic_executor_t::handle_load(const minsn_t* ins) {
    // For now, treat loads as fresh symbolic values unless from known locations
    handle_assignment(ins);
}

void symbolic_executor_t::handle_store(const minsn_t* ins) {
    // Store instruction: store value to memory
    // For symbolic execution, we track this in our state
    if (!ins) return;

    if (ins->d.t == mop_S || ins->d.t == mop_v) {
        z3::expr value = m_translator.translate_operand(ins->l);
        symbolic_var_t dst_var = symbolic_var_t(
            ins->d.t == mop_S ? symbolic_var_t::VAR_STACK : symbolic_var_t::VAR_GLOBAL,
            ins->d.t == mop_S && ins->d.s ? ins->d.s->off : ins->d.g,
            ins->d.size
        );
        m_state[dst_var] = std::make_shared<z3::expr>(value);
    }
}

void symbolic_executor_t::execute_block(const mblock_t* blk) {
    if (!blk) return;

    for (const minsn_t* ins = blk->head; ins; ins = ins->next) {
        execute_insn(ins);
    }
}

std::optional<z3::expr> symbolic_executor_t::get_value(const symbolic_var_t& var) {
    auto it = m_state.find(var);
    if (it != m_state.end() && it->second) {
        return *it->second;
    }
    return std::nullopt;
}

std::optional<z3::expr> symbolic_executor_t::get_value(const mop_t& op) {
    symbolic_var_t var(
        op.t == mop_r ? symbolic_var_t::VAR_REGISTER :
        op.t == mop_S ? symbolic_var_t::VAR_STACK :
        op.t == mop_v ? symbolic_var_t::VAR_GLOBAL :
        symbolic_var_t::VAR_LOCAL,
        op.t == mop_r ? op.r :
        op.t == mop_S && op.s ? op.s->off :
        op.t == mop_v ? op.g :
        op.l ? op.l->idx : 0,
        op.size
    );
    return get_value(var);
}

void symbolic_executor_t::add_constraint(const z3::expr& constraint) {
    m_constraints.push_back(std::make_shared<z3::expr>(constraint));
}

sat_result_t symbolic_executor_t::check_path_feasibility() {
    m_ctx.solver().reset();

    for (const auto& c : m_constraints) {
        if (c) m_ctx.solver().add(*c);
    }

    switch (m_ctx.solver().check()) {
        case z3::sat:
            return sat_result_t::SAT;
        case z3::unsat:
            return sat_result_t::UNSAT;
        default:
            return sat_result_t::UNKNOWN;
    }
}

std::optional<uint64_t> symbolic_executor_t::solve_for_value(const z3::expr& expr) {
    m_ctx.solver().reset();

    for (const auto& c : m_constraints) {
        if (c) m_ctx.solver().add(*c);
    }

    if (m_ctx.solver().check() == z3::sat) {
        z3::model m = m_ctx.solver().get_model();
        z3::expr val = m.eval(expr, true);
        if (val.is_numeral()) {
            return val.get_numeral_uint64();
        }
    }
    return std::nullopt;
}

std::optional<uint64_t> symbolic_executor_t::solve_for_value(const mop_t& op) {
    z3::expr e = m_translator.translate_operand(op);
    return solve_for_value(e);
}

std::vector<uint64_t> symbolic_executor_t::enumerate_values(const mop_t& op, int max_count) {
    std::vector<uint64_t> values;
    z3::expr e = m_translator.translate_operand(op);

    m_ctx.solver().reset();
    for (const auto& c : m_constraints) {
        if (c) m_ctx.solver().add(*c);
    }

    while ((int)values.size() < max_count) {
        if (m_ctx.solver().check() != z3::sat) {
            break;
        }

        z3::model m = m_ctx.solver().get_model();
        z3::expr val = m.eval(e, true);
        if (!val.is_numeral()) {
            break;
        }

        uint64_t v = val.get_numeral_uint64();
        values.push_back(v);

        // Exclude this value for next iteration
        m_ctx.solver().add(e != m_ctx.ctx().bv_val(v, e.get_sort().bv_size()));
    }

    return values;
}

//--------------------------------------------------------------------------
// state_machine_solver_t implementation
//--------------------------------------------------------------------------
state_machine_solver_t::state_machine_solver_t(z3_context_t& ctx)
    : m_ctx(ctx), m_translator(ctx) {
}

// Helper: Check if a value looks like a Hikari state constant
static bool is_hikari_state_const(uint64_t val) {
    if (val < 0x10000000 || val > 0xFFFFFFFF)
        return false;

    uint32_t high = (val >> 16) & 0xFFFF;
    if (high == 0)
        return false;

    switch (high) {
        case 0xAAAA: case 0xABCD: case 0xBBBB: case 0xCCCC: case 0xDDDD:
        case 0xBEEF: case 0xCAFE: case 0xDEAD:
        case 0x1111: case 0x2222: case 0x3333: case 0x4444:
        case 0x5555: case 0x6666: case 0x7777: case 0x8888: case 0x9999:
        case 0xFEED: case 0xFACE: case 0xBABE: case 0xC0DE: case 0xF00D:
            return true;
        default:
            return false;
    }
}

std::set<uint64_t> state_machine_solver_t::find_state_constants(const mblock_t* blk) {
    std::set<uint64_t> constants;
    if (!blk) return constants;

    for (const minsn_t* ins = blk->head; ins; ins = ins->next) {
        // Check all operands for Hikari constants
        if (ins->l.t == mop_n && is_hikari_state_const(ins->l.nnn->value)) {
            constants.insert(ins->l.nnn->value);
        }
        if (ins->r.t == mop_n && is_hikari_state_const(ins->r.nnn->value)) {
            constants.insert(ins->r.nnn->value);
        }

        // Check nested instructions
        if (ins->l.t == mop_d && ins->l.d) {
            const minsn_t* nested = ins->l.d;
            if (nested->l.t == mop_n && is_hikari_state_const(nested->l.nnn->value)) {
                constants.insert(nested->l.nnn->value);
            }
            if (nested->r.t == mop_n && is_hikari_state_const(nested->r.nnn->value)) {
                constants.insert(nested->r.nnn->value);
            }
        }
    }

    return constants;
}

//--------------------------------------------------------------------------
// Helper: Extract state comparison info from a single block
// Returns true if a state comparison (jcc with setXX against Hikari const) is found
//--------------------------------------------------------------------------
static bool extract_state_comparison(mbl_array_t* mba, int block_idx,
                                      mop_t* out_var, uint64_t* out_state, int* out_target) {
    if (!mba || block_idx < 0 || block_idx >= mba->qty)
        return false;

    mblock_t* blk = mba->get_mblock(block_idx);
    if (!blk)
        return false;

    // Log block instructions for debugging (only for blocks with state constants)
    static bool debug_logged = false;
    if (!debug_logged && block_idx >= 2 && block_idx <= 13) {
        deobf::log("[z3] Block %d instructions:\n", block_idx);
        for (const minsn_t* ins = blk->head; ins; ins = ins->next) {
            deobf::log("[z3]   opcode=%d l.t=%d r.t=%d d.t=%d\n",
                      ins->opcode, ins->l.t, ins->r.t, ins->d.t);
            if (ins->l.t == mop_n) {
                deobf::log("[z3]     l.n=0x%llx\n", (unsigned long long)ins->l.nnn->value);
            }
            if (ins->r.t == mop_n) {
                deobf::log("[z3]     r.n=0x%llx\n", (unsigned long long)ins->r.nnn->value);
            }
        }
        if (block_idx == 13) debug_logged = true;
    }

    // Track which registers hold state constants (for flattened microcode)
    std::map<mreg_t, uint64_t> reg_to_const;

    for (const minsn_t* ins = blk->head; ins; ins = ins->next) {
        // Track mov of constants to registers
        // mop_n=2, mop_r=1 in IDA microcode
        if (ins->opcode == m_mov && ins->l.t == mop_n && ins->d.t == mop_r) {
            uint64_t val = ins->l.nnn->value;
            if (is_hikari_state_const(val)) {
                deobf::log("[z3] Block %d: tracking reg %d <- 0x%llx\n",
                          block_idx, ins->d.r, (unsigned long long)val);
                reg_to_const[ins->d.r] = val;
            }
        }

        // Also log setXX instructions for debugging
        if (is_mcode_set(ins->opcode) && block_idx >= 2 && block_idx <= 5) {
            deobf::log("[z3] Block %d: setXX opcode=%d l.t=%d l.r=%d r.t=%d r.r=%d\n",
                      block_idx, ins->opcode, ins->l.t, ins->l.t == mop_r ? ins->l.r : -1,
                      ins->r.t, ins->r.t == mop_r ? ins->r.r : -1);
        }

        // Method 1: Check setXX instructions where one operand is a register holding a state constant
        if (is_mcode_set(ins->opcode)) {
            uint64_t state_val = 0;
            mop_t var;
            bool found = false;

            if (block_idx >= 2 && block_idx <= 5) {
                deobf::log("[z3] Block %d: checking setXX - l.t=%d l.r=%d (have=%d) r.t=%d r.r=%d (have=%d)\n",
                          block_idx, ins->l.t, ins->l.t == mop_r ? (int)ins->l.r : -1,
                          ins->l.t == mop_r ? (int)reg_to_const.count(ins->l.r) : 0,
                          ins->r.t, ins->r.t == mop_r ? (int)ins->r.r : -1,
                          ins->r.t == mop_r ? (int)reg_to_const.count(ins->r.r) : 0);
            }

            // Check if left operand is a register with known constant
            if (ins->l.t == mop_r && reg_to_const.count(ins->l.r)) {
                state_val = reg_to_const[ins->l.r];
                var = ins->r;
                found = true;
            }
            // Check if right operand is a register with known constant
            else if (ins->r.t == mop_r && reg_to_const.count(ins->r.r)) {
                state_val = reg_to_const[ins->r.r];
                var = ins->l;
                found = true;
            }
            // Also check for direct number operands
            else if (ins->l.t == mop_n && is_hikari_state_const(ins->l.nnn->value)) {
                state_val = ins->l.nnn->value;
                var = ins->r;
                found = true;
            }
            else if (ins->r.t == mop_n && is_hikari_state_const(ins->r.nnn->value)) {
                state_val = ins->r.nnn->value;
                var = ins->l;
                found = true;
            }

            if (found) {
                if (block_idx >= 2 && block_idx <= 5) {
                    deobf::log("[z3] Block %d: found=true, state=0x%llx, searching for jcc...\n",
                              block_idx, (unsigned long long)state_val);
                }
                // Find the jcnd that uses this comparison result
                for (const minsn_t* jcc = ins->next; jcc; jcc = jcc->next) {
                    if (deobf::is_jcc(jcc->opcode)) {
                        int target_block = -1;

                        // d.t can be mop_b (block number) or mop_v (address)
                        if (jcc->d.t == mop_b) {
                            target_block = jcc->d.b;
                        } else if (jcc->d.t == mop_v) {
                            // mop_v: d.g is the target address, need to find which block it's in
                            ea_t target_addr = jcc->d.g;

                            // Search for the block containing this address
                            for (int bi = 0; bi < mba->qty; bi++) {
                                mblock_t* tblk = mba->get_mblock(bi);
                                if (tblk && tblk->start <= target_addr && target_addr < tblk->end) {
                                    target_block = bi;
                                    break;
                                }
                            }

                            if (target_block < 0) {
                                // Fallback: find block whose start matches the address
                                for (int bi = 0; bi < mba->qty; bi++) {
                                    mblock_t* tblk = mba->get_mblock(bi);
                                    if (tblk && tblk->start == target_addr) {
                                        target_block = bi;
                                        break;
                                    }
                                }
                            }

                            if (target_block >= 0) {
                                deobf::log("[z3] Block %d: found setXX(%d) state cmp 0x%llx -> block %d (addr 0x%llx)\n",
                                          block_idx, ins->opcode, (unsigned long long)state_val,
                                          target_block, (unsigned long long)target_addr);
                            } else {
                                deobf::log("[z3] Block %d: found setXX(%d) state cmp 0x%llx -> unresolved addr 0x%llx\n",
                                          block_idx, ins->opcode, (unsigned long long)state_val,
                                          (unsigned long long)target_addr);
                            }
                        }

                        if (target_block >= 0) {
                            deobf::log("[z3] Block %d: found setXX(%d) state cmp 0x%llx -> block %d\n",
                                      block_idx, ins->opcode, (unsigned long long)state_val, target_block);
                            if (out_var) *out_var = var;
                            if (out_state) *out_state = state_val;
                            if (out_target) *out_target = target_block;
                            return true;
                        }
                    }
                }
            }
        }

        // Method 2: jcc with nested setXX (for earlier optimization stages)
        if (deobf::is_jcc(ins->opcode)) {
            if (ins->l.t == mop_d && ins->l.d) {
                const minsn_t* cmp = ins->l.d;
                if (is_mcode_set(cmp->opcode)) {
                    uint64_t state_val = 0;
                    mop_t var;
                    bool found = false;

                    if (cmp->l.t == mop_n && is_hikari_state_const(cmp->l.nnn->value)) {
                        state_val = cmp->l.nnn->value;
                        var = cmp->r;
                        found = true;
                    } else if (cmp->r.t == mop_n && is_hikari_state_const(cmp->r.nnn->value)) {
                        state_val = cmp->r.nnn->value;
                        var = cmp->l;
                        found = true;
                    }

                    if (found && ins->d.t == mop_b) {
                        deobf::log("[z3] Block %d: found nested setXX state cmp 0x%llx -> block %d\n",
                                  block_idx, (unsigned long long)state_val, ins->d.b);
                        if (out_var) *out_var = var;
                        if (out_state) *out_state = state_val;
                        if (out_target) *out_target = ins->d.b;
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

state_machine_solver_t::dispatcher_analysis_t
state_machine_solver_t::analyze_dispatcher(mbl_array_t* mba, int block_idx) {
    dispatcher_analysis_t result;
    result.is_dispatcher = false;
    result.block_idx = block_idx;

    if (!mba || block_idx < 0 || block_idx >= mba->qty)
        return result;

    // Check cache
    auto cache_it = m_dispatcher_cache.find(block_idx);
    if (cache_it != m_dispatcher_cache.end()) {
        return cache_it->second;
    }

    mblock_t* blk = mba->get_mblock(block_idx);
    if (!blk)
        return result;

    // Find Hikari state constants in this block
    std::set<uint64_t> state_consts = find_state_constants(blk);

    mop_t potential_state_var;
    bool found_state_var = false;
    std::map<uint64_t, int> state_to_target;

    // First, try to find comparisons in this single block
    for (const minsn_t* ins = blk->head; ins; ins = ins->next) {
        if (!deobf::is_jcc(ins->opcode))
            continue;

        if (ins->l.t == mop_d && ins->l.d) {
            const minsn_t* cmp = ins->l.d;
            if (is_mcode_set(cmp->opcode)) {
                uint64_t state_val = 0;
                bool found_const = false;
                mop_t var;

                if (cmp->l.t == mop_n && is_hikari_state_const(cmp->l.nnn->value)) {
                    state_val = cmp->l.nnn->value;
                    var = cmp->r;
                    found_const = true;
                } else if (cmp->r.t == mop_n && is_hikari_state_const(cmp->r.nnn->value)) {
                    state_val = cmp->r.nnn->value;
                    var = cmp->l;
                    found_const = true;
                }

                if (found_const && ins->d.t == mop_b) {
                    if (!found_state_var) {
                        potential_state_var = var;
                        found_state_var = true;
                    }
                    state_to_target[state_val] = ins->d.b;
                }
            }
        }
    }

    // If we found enough comparisons in this block, we're done
    if (state_to_target.size() >= 2 && found_state_var) {
        result.is_dispatcher = true;
        result.state_to_block = state_to_target;

        if (potential_state_var.t == mop_S && potential_state_var.s) {
            result.state_var = symbolic_var_t(symbolic_var_t::VAR_STACK,
                                               potential_state_var.s->off,
                                               potential_state_var.size);
        } else if (potential_state_var.t == mop_r) {
            result.state_var = symbolic_var_t(symbolic_var_t::VAR_REGISTER,
                                               potential_state_var.r,
                                               potential_state_var.size);
        } else if (potential_state_var.t == mop_v) {
            result.state_var = symbolic_var_t(symbolic_var_t::VAR_GLOBAL,
                                               potential_state_var.g,
                                               potential_state_var.size);
        }

        deobf::log("[z3] Found dispatcher at block %d with %zu state mappings\n",
                  block_idx, state_to_target.size());
        m_dispatcher_cache[block_idx] = result;
        return result;
    }

    // CASCADING DISPATCHER DETECTION:
    // Since successor information may not be available, we scan all blocks
    // with state constants and group them if they compare against the same variable type

    // First, check if this block actually has a state comparison
    mop_t first_var;
    uint64_t first_state = 0;
    int first_target = -1;
    bool has_comparison = extract_state_comparison(mba, block_idx, &first_var, &first_state, &first_target);

    if (has_comparison) {
        // Check if any earlier block already created a dispatcher that covers this block
        for (int earlier = 0; earlier < block_idx; earlier++) {
            auto earlier_it = m_dispatcher_cache.find(earlier);
            if (earlier_it != m_dispatcher_cache.end() && earlier_it->second.is_dispatcher) {
                // An earlier block already created a dispatcher
                // Mark this block as part of that dispatcher (not a new one)
                deobf::log("[z3] Block %d: part of earlier dispatcher starting at block %d\n", block_idx, earlier);
                m_dispatcher_cache[block_idx] = result;  // result.is_dispatcher = false
                return result;
            }
        }

        deobf::log("[z3] Block %d: has state comparison, scanning all blocks for dispatcher\n", block_idx);

        // Scan ALL blocks with state constants starting from block 0 to capture all
        for (int scan_blk = 0; scan_blk < mba->qty; scan_blk++) {
            mop_t var;
            uint64_t state_val = 0;
            int target = -1;

            if (extract_state_comparison(mba, scan_blk, &var, &state_val, &target) && target >= 0) {
                // Only add unique state values (skip ja/jb type comparisons that go to fallback)
                // The equality comparison (state_val -> case block) is what we want
                if (state_to_target.find(state_val) == state_to_target.end()) {
                    state_to_target[state_val] = target;

                    if (!found_state_var) {
                        potential_state_var = var;
                        found_state_var = true;
                    }

                    deobf::log("[z3] Scan: block %d added state 0x%llx -> block %d (map size=%zu)\n",
                              scan_blk, (unsigned long long)state_val, target, state_to_target.size());
                }
            }
        }

        // If we accumulated enough comparisons via the chain, this is a cascading dispatcher
        if (state_to_target.size() >= 2 && found_state_var) {
            result.is_dispatcher = true;
            result.state_to_block = state_to_target;

            if (potential_state_var.t == mop_S && potential_state_var.s) {
                result.state_var = symbolic_var_t(symbolic_var_t::VAR_STACK,
                                                   potential_state_var.s->off,
                                                   potential_state_var.size);
            } else if (potential_state_var.t == mop_r) {
                result.state_var = symbolic_var_t(symbolic_var_t::VAR_REGISTER,
                                                   potential_state_var.r,
                                                   potential_state_var.size);
            } else if (potential_state_var.t == mop_v) {
                result.state_var = symbolic_var_t(symbolic_var_t::VAR_GLOBAL,
                                                   potential_state_var.g,
                                                   potential_state_var.size);
            }

            deobf::log("[z3] Found CASCADING dispatcher starting at block %d with %zu state mappings\n",
                      block_idx, state_to_target.size());
        }
    }

    m_dispatcher_cache[block_idx] = result;
    return result;
}

std::optional<uint64_t>
state_machine_solver_t::determine_written_state(mbl_array_t* mba, int block_idx,
                                                  const symbolic_var_t& state_var) {
    if (!mba || block_idx < 0 || block_idx >= mba->qty)
        return std::nullopt;

    mblock_t* blk = mba->get_mblock(block_idx);
    if (!blk)
        return std::nullopt;

    // Use symbolic execution to determine final state value
    symbolic_executor_t executor(m_ctx);

    // Execute the block
    executor.execute_block(blk);

    // Get the value of the state variable after execution
    auto value = executor.get_value(state_var);
    if (value.has_value()) {
        // Try to solve for a concrete value
        auto concrete = executor.solve_for_value(value.value());
        if (concrete.has_value() && is_hikari_state_const(*concrete)) {
            return concrete;
        }
    }

    // Fallback: scan for direct constant assignments to state var
    for (const minsn_t* ins = blk->head; ins; ins = ins->next) {
        if (ins->opcode != m_mov)
            continue;

        if (ins->l.t != mop_n || !is_hikari_state_const(ins->l.nnn->value))
            continue;

        // Check if destination matches state variable
        bool matches = false;
        if (ins->d.t == mop_S && state_var.kind() == symbolic_var_t::VAR_STACK) {
            if (ins->d.s && ins->d.s->off == (sval_t)state_var.id())
                matches = true;
        } else if (ins->d.t == mop_r && state_var.kind() == symbolic_var_t::VAR_REGISTER) {
            if (ins->d.r == (mreg_t)state_var.id())
                matches = true;
        } else if (ins->d.t == mop_v && state_var.kind() == symbolic_var_t::VAR_GLOBAL) {
            if (ins->d.g == (ea_t)state_var.id())
                matches = true;
        }

        if (matches) {
            return ins->l.nnn->value;
        }
    }

    return std::nullopt;
}

state_machine_solver_t::block_transition_t
state_machine_solver_t::analyze_block_transition(mbl_array_t* mba, int block_idx,
                                                   const symbolic_var_t& state_var) {
    block_transition_t result;
    result.from_block = block_idx;
    result.to_block = -1;
    result.to_block_true = -1;
    result.to_block_false = -1;
    result.next_state = 0;
    result.is_conditional = false;
    result.solved = false;

    if (!mba || block_idx < 0 || block_idx >= mba->qty)
        return result;

    mblock_t* blk = mba->get_mblock(block_idx);
    if (!blk)
        return result;

    // Determine what state value this block writes
    auto written_state = determine_written_state(mba, block_idx, state_var);
    if (written_state.has_value()) {
        result.next_state = *written_state;
        result.solved = true;

        deobf::log_verbose("[z3] Block %d writes state 0x%llx\n",
                  block_idx, (unsigned long long)*written_state);
    }

    // Check for conditional transitions
    if (blk->tail && deobf::is_jcc(blk->tail->opcode)) {
        result.is_conditional = true;
        result.condition = std::make_shared<z3::expr>(m_translator.translate_jcc_condition(blk->tail));

        if (blk->tail->d.t == mop_b) {
            result.to_block_true = blk->tail->d.b;
        }
        // Fall-through target would be next block
        if (blk->nsucc() >= 2) {
            for (int i = 0; i < blk->nsucc(); i++) {
                int succ = blk->succ(i);
                if (succ != result.to_block_true) {
                    result.to_block_false = succ;
                    break;
                }
            }
        }
    } else if (blk->tail && blk->tail->opcode == m_goto) {
        if (blk->tail->d.t == mop_b) {
            result.to_block = blk->tail->d.b;
        }
    }

    return result;
}

state_machine_solver_t::state_machine_t
state_machine_solver_t::solve_state_machine(mbl_array_t* mba) {
    state_machine_t machine;
    machine.solved = false;

    if (!mba)
        return machine;

    deobf::log("[z3] Solving state machine for function with %d blocks\n", mba->qty);
    deobf::log("[z3] Starting block scan...\n");

    // First pass: identify blocks with state constants
    std::vector<int> blocks_with_state_consts;
    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk) {
            deobf::log("[z3]   Block %d: NULL\n", i);
            continue;
        }
        auto consts = find_state_constants(blk);
        if (!consts.empty()) {
            blocks_with_state_consts.push_back(i);
            deobf::log("[z3]   Block %d has %zu state constants:", i, consts.size());
            for (uint64_t c : consts) {
                deobf::log(" 0x%llx", (unsigned long long)c);
            }
            deobf::log("\n");
        }
    }
    deobf::log("[z3] Block scan complete. Found %zu blocks with state constants\n", blocks_with_state_consts.size());

    // Step 1: Find all dispatchers (try blocks with state constants first)
    for (int i : blocks_with_state_consts) {
        auto disp = analyze_dispatcher(mba, i);
        if (disp.is_dispatcher) {
            machine.dispatchers.push_back(disp);
        }
    }

    // Also try all blocks if we haven't found any
    if (machine.dispatchers.empty()) {
        for (int i = 0; i < mba->qty; i++) {
            auto disp = analyze_dispatcher(mba, i);
            if (disp.is_dispatcher) {
                machine.dispatchers.push_back(disp);
            }
        }
    }

    if (machine.dispatchers.empty()) {
        deobf::log("[z3] No dispatchers found\n");
        return machine;
    }

    deobf::log("[z3] Found %zu dispatchers\n", machine.dispatchers.size());

    // Step 2: For each dispatcher, analyze case blocks
    for (const auto& disp : machine.dispatchers) {
        // Collect all blocks that belong to this dispatcher
        std::set<int> case_blocks;
        for (const auto& kv : disp.state_to_block) {
            case_blocks.insert(kv.second);
        }

        // Analyze each case block's transitions
        for (int case_blk : case_blocks) {
            auto trans = analyze_block_transition(mba, case_blk, disp.state_var);
            if (trans.solved) {
                machine.transitions.push_back(trans);
            }
        }
    }

    // Step 3: Build state-to-block mapping and determine original CFG
    // For each state value written by a block, find which block handles that state
    std::map<uint64_t, int> state_handlers;  // state -> block that handles it

    for (const auto& disp : machine.dispatchers) {
        for (const auto& kv : disp.state_to_block) {
            state_handlers[kv.first] = kv.second;
        }
    }

    // For each transition, determine the actual target block
    for (auto& trans : machine.transitions) {
        if (trans.solved && trans.next_state != 0) {
            auto it = state_handlers.find(trans.next_state);
            if (it != state_handlers.end()) {
                if (!trans.is_conditional) {
                    trans.to_block = it->second;
                }
                machine.block_successors[trans.from_block].push_back(it->second);
            }
        }
    }

    // Mark as solved if we found any dispatchers (even without full transition analysis)
    machine.solved = !machine.dispatchers.empty();

    deobf::log("[z3] State machine analysis complete: %zu dispatchers, %zu transitions, %s\n",
              machine.dispatchers.size(), machine.transitions.size(),
              machine.solved ? "SOLVED" : "UNSOLVED");

    m_machine = machine;
    return machine;
}

std::optional<int> state_machine_solver_t::resolve_state_to_block(uint64_t state_value) {
    if (!m_machine.has_value() || !m_machine->solved)
        return std::nullopt;

    for (const auto& disp : m_machine->dispatchers) {
        auto it = disp.state_to_block.find(state_value);
        if (it != disp.state_to_block.end()) {
            return it->second;
        }
    }
    return std::nullopt;
}

//--------------------------------------------------------------------------
// opaque_predicate_solver_t implementation
//--------------------------------------------------------------------------
opaque_predicate_solver_t::opaque_predicate_solver_t(z3_context_t& ctx)
    : m_ctx(ctx), m_translator(ctx) {
}

opaque_predicate_solver_t::predicate_result_t
opaque_predicate_solver_t::analyze_condition(const minsn_t* cond) {
    if (!cond)
        return PRED_UNKNOWN;

    // First, try simple constant evaluation
    bool result;
    if (opaque_eval_t::evaluate_condition(const_cast<minsn_t*>(cond), &result)) {
        return result ? PRED_ALWAYS_TRUE : PRED_ALWAYS_FALSE;
    }

    // Use Z3 for more complex analysis
    try {
        z3::expr condition = m_translator.translate_jcc_condition(cond);

        // Check if condition is always true (negation is unsatisfiable)
        m_ctx.solver().reset();
        m_ctx.solver().add(!condition);
        if (m_ctx.solver().check() == z3::unsat) {
            return PRED_ALWAYS_TRUE;
        }

        // Check if condition is always false (condition itself is unsatisfiable)
        m_ctx.solver().reset();
        m_ctx.solver().add(condition);
        if (m_ctx.solver().check() == z3::unsat) {
            return PRED_ALWAYS_FALSE;
        }

        // Both are satisfiable - condition depends on input
        return PRED_DEPENDS_ON_INPUT;

    } catch (z3::exception& e) {
        deobf::log_verbose("[z3] Exception in analyze_condition: %s\n", e.msg());
        return PRED_UNKNOWN;
    }
}

opaque_predicate_solver_t::analysis_result_t
opaque_predicate_solver_t::analyze_detailed(const minsn_t* cond) {
    analysis_result_t result;
    result.result = analyze_condition(cond);

    try {
        z3::expr condition = m_translator.translate_jcc_condition(cond);
        result.simplified = std::make_shared<z3::expr>(condition.simplify());

        switch (result.result) {
            case PRED_ALWAYS_TRUE:
                result.proof_hint = "Condition is a tautology";
                break;
            case PRED_ALWAYS_FALSE:
                result.proof_hint = "Condition is a contradiction";
                break;
            case PRED_DEPENDS_ON_INPUT:
                result.proof_hint = "Condition depends on symbolic values";
                break;
            default:
                result.proof_hint = "Analysis inconclusive";
                break;
        }
    } catch (z3::exception&) {
        result.proof_hint = "Z3 exception during analysis";
    }

    return result;
}

bool opaque_predicate_solver_t::is_xy_even_pattern(const minsn_t* ins) {
    // Pattern: x * (x + 1) % 2 == 0 is always true
    if (!ins)
        return false;

    try {
        z3::expr e = m_translator.translate_insn(ins);

        // Create symbolic x
        z3::expr x = m_ctx.ctx().bv_const("x", 32);

        // x * (x + 1) % 2
        z3::expr pattern = z3::urem(x * (x + 1), 2);

        // Check if result == 0 for all x
        m_ctx.solver().reset();
        m_ctx.solver().add(pattern != 0);

        return m_ctx.solver().check() == z3::unsat;
    } catch (z3::exception&) {
        return false;
    }
}

bool opaque_predicate_solver_t::is_tautology_pattern(const minsn_t* ins) {
    // Pattern: x < C || x >= C (or similar) is always true
    if (!ins || ins->opcode != m_or)
        return false;

    try {
        z3::expr condition = m_translator.translate_insn(ins);

        // Check if condition is always non-zero
        m_ctx.solver().reset();
        m_ctx.solver().add(condition == 0);

        return m_ctx.solver().check() == z3::unsat;
    } catch (z3::exception&) {
        return false;
    }
}

bool opaque_predicate_solver_t::is_modular_pattern(const minsn_t* ins) {
    // Various modular arithmetic patterns that are constant
    // E.g., (x^2 - 1) % 8 when x is odd gives 0

    if (!ins)
        return false;

    // Check if expression contains modulo operation
    if (ins->opcode != m_umod && ins->opcode != m_smod)
        return false;

    try {
        z3::expr e = m_translator.translate_insn(ins);
        z3::expr simplified = e.simplify();

        // If simplified to a constant, it's a modular pattern
        if (simplified.is_numeral()) {
            return true;
        }
    } catch (z3::exception&) {
    }

    return false;
}

//--------------------------------------------------------------------------
// expression_simplifier_t implementation
//--------------------------------------------------------------------------
expression_simplifier_t::expression_simplifier_t(z3_context_t& ctx)
    : m_ctx(ctx), m_translator(ctx) {
}

z3::expr expression_simplifier_t::simplify(const z3::expr& expr) {
    return expr.simplify();
}

eval_result_t expression_simplifier_t::evaluate_constant(const minsn_t* ins) {
    if (!ins)
        return eval_result_t::unknown();

    // First try simple evaluation
    auto simple_result = opaque_eval_t::evaluate_expr(const_cast<minsn_t*>(ins));
    if (simple_result.has_value()) {
        return eval_result_t::constant(*simple_result, ins->d.size * 8);
    }

    // Use Z3 for complex expressions
    try {
        z3::expr e = m_translator.translate_insn(ins);
        z3::expr simplified = e.simplify();

        if (simplified.is_numeral()) {
            uint64_t val = simplified.get_numeral_uint64();
            return eval_result_t::constant(val, simplified.get_sort().bv_size());
        }
    } catch (z3::exception&) {
    }

    return eval_result_t::unknown();
}

eval_result_t expression_simplifier_t::evaluate_constant(const mop_t& op) {
    // Handle immediate constants directly
    if (op.t == mop_n) {
        return eval_result_t::constant(op.nnn->value, op.size * 8);
    }

    // Handle global variables by reading from binary
    if (op.t == mop_v) {
        auto val = opaque_eval_t::read_global(op.g, op.size);
        if (val.has_value()) {
            return eval_result_t::constant(*val, op.size * 8);
        }
    }

    // Handle sub-instructions
    if (op.t == mop_d && op.d) {
        return evaluate_constant(op.d);
    }

    return eval_result_t::unknown();
}

bool expression_simplifier_t::are_equivalent(const z3::expr& a, const z3::expr& b) {
    try {
        m_ctx.solver().reset();
        m_ctx.solver().add(a != b);
        return m_ctx.solver().check() == z3::unsat;
    } catch (z3::exception&) {
        return false;
    }
}

bool expression_simplifier_t::are_equivalent(const minsn_t* a, const minsn_t* b) {
    if (!a || !b)
        return false;

    try {
        z3::expr ea = m_translator.translate_insn(a);
        z3::expr eb = m_translator.translate_insn(b);
        return are_equivalent(ea, eb);
    } catch (z3::exception&) {
        return false;
    }
}

//--------------------------------------------------------------------------
// Convenience functions
//--------------------------------------------------------------------------
std::optional<bool> is_condition_constant(const minsn_t* cond) {
    opaque_predicate_solver_t solver(get_global_context());
    auto result = solver.analyze_condition(cond);

    switch (result) {
        case opaque_predicate_solver_t::PRED_ALWAYS_TRUE:
            return true;
        case opaque_predicate_solver_t::PRED_ALWAYS_FALSE:
            return false;
        default:
            return std::nullopt;
    }
}

eval_result_t evaluate_to_constant(const minsn_t* ins) {
    expression_simplifier_t simplifier(get_global_context());
    return simplifier.evaluate_constant(ins);
}

eval_result_t evaluate_to_constant(const mop_t& op) {
    expression_simplifier_t simplifier(get_global_context());
    return simplifier.evaluate_constant(op);
}

bool instructions_equivalent(const minsn_t* a, const minsn_t* b) {
    expression_simplifier_t simplifier(get_global_context());
    return simplifier.are_equivalent(a, b);
}

//--------------------------------------------------------------------------
// constant_optimizer_t implementation
//--------------------------------------------------------------------------
constant_optimizer_t::constant_optimizer_t(z3_context_t& ctx)
    : m_ctx(ctx), m_translator(ctx) {
}

void constant_optimizer_t::count_complexity(const mop_t& op, complexity_t& out) {
    if (op.t == mop_n) {
        out.const_count++;
        return;
    }

    if (op.t == mop_r || op.t == mop_S || op.t == mop_v || op.t == mop_l) {
        out.var_count++;
        return;
    }

    if (op.t == mop_d && op.d) {
        out.op_count++;
        count_complexity(op.d->l, out);
        if (op.d->r.t != mop_z) {
            count_complexity(op.d->r, out);
        }
    }
}

constant_optimizer_t::complexity_t
constant_optimizer_t::analyze_complexity(const minsn_t* ins) {
    complexity_t result = {0, 0, 0};
    if (!ins) return result;

    result.op_count = 1;
    count_complexity(ins->l, result);
    if (ins->r.t != mop_z) {
        count_complexity(ins->r, result);
    }
    return result;
}

constant_optimizer_t::complexity_t
constant_optimizer_t::analyze_complexity(const mop_t& op) {
    complexity_t result = {0, 0, 0};
    count_complexity(op, result);
    return result;
}

std::optional<uint64_t> constant_optimizer_t::quick_eval(const z3::expr& expr, int bits) {
    try {
        // Collect all variables in the expression
        std::set<std::string> var_names;
        // Z3 doesn't have a direct way to get free variables, so we use evaluation

        z3::context& ctx = m_ctx.ctx();

        // Test with x = 0 for all variables
        z3::model model1(ctx);

        // Create a solver to get a model with 0s
        z3::solver solver1(ctx);
        // Build constraints: all free vars = 0

        // Simplified: just evaluate directly with simplify
        z3::expr e0 = expr.simplify();

        // If it simplifies to a constant, return it
        if (e0.is_numeral()) {
            return e0.get_numeral_uint64();
        }

        // Otherwise, can't quick-evaluate
        return std::nullopt;

    } catch (z3::exception&) {
        return std::nullopt;
    }
}

bool constant_optimizer_t::z3_verify_constant(const z3::expr& expr, uint64_t expected, int bits) {
    try {
        z3::context& ctx = m_ctx.ctx();
        z3::solver& solver = m_ctx.solver();

        solver.reset();

        // Check if expr can ever NOT equal expected
        z3::expr expected_val = ctx.bv_val(expected, bits);
        solver.add(expr != expected_val);

        // If unsatisfiable, expr is always equal to expected
        return solver.check() == z3::unsat;

    } catch (z3::exception&) {
        return false;
    }
}

constant_optimizer_t::const_result_t
constant_optimizer_t::analyze(const minsn_t* ins, const config_t& cfg) {
    const_result_t result;
    if (!ins) return result;

    // Check complexity threshold
    auto complexity = analyze_complexity(ins);
    if (complexity.op_count < cfg.min_opcodes) {
        return result;  // Not complex enough to be obfuscated
    }

    int bits = ins->d.size * 8;
    if (bits == 0) bits = 64;

    try {
        m_ctx.set_timeout(cfg.timeout_ms);
        z3::expr e = m_translator.translate_insn(ins);

        // Quick eval first
        auto quick_result = quick_eval(e, bits);
        if (quick_result.has_value()) {
            result.is_constant = true;
            result.value = *quick_result;
            result.bit_width = bits;
            result.method = "quick_eval";
            return result;
        }

        // Try Z3 simplification
        z3::expr simplified = e.simplify();
        if (simplified.is_numeral()) {
            result.is_constant = true;
            result.value = simplified.get_numeral_uint64();
            result.bit_width = bits;
            result.method = "z3_simplify";
            return result;
        }

    } catch (z3::exception& e) {
        deobf::log_verbose("[z3] Exception in constant analysis: %s\n", e.msg());
    }

    return result;
}

constant_optimizer_t::const_result_t
constant_optimizer_t::analyze_operand(const mop_t& op, const config_t& cfg) {
    const_result_t result;

    // Direct constant
    if (op.t == mop_n) {
        result.is_constant = true;
        result.value = op.nnn->value;
        result.bit_width = op.size * 8;
        result.method = "direct";
        return result;
    }

    // Sub-instruction
    if (op.t == mop_d && op.d) {
        return analyze(op.d, cfg);
    }

    return result;
}

//--------------------------------------------------------------------------
// predicate_simplifier_t implementation
//--------------------------------------------------------------------------
predicate_simplifier_t::predicate_simplifier_t(z3_context_t& ctx)
    : m_ctx(ctx), m_translator(ctx) {
}

std::optional<bool> predicate_simplifier_t::simplify_setz(const minsn_t* ins) {
    if (!ins || ins->opcode != m_setz)
        return std::nullopt;

    try {
        z3::expr e = m_translator.translate_insn(ins);
        z3::expr simplified = e.simplify();

        if (simplified.is_numeral()) {
            return simplified.get_numeral_uint64() != 0;
        }
    } catch (z3::exception&) {
    }

    return std::nullopt;
}

std::optional<bool> predicate_simplifier_t::simplify_setnz(const minsn_t* ins) {
    if (!ins || ins->opcode != m_setnz)
        return std::nullopt;

    try {
        z3::expr e = m_translator.translate_insn(ins);
        z3::expr simplified = e.simplify();

        if (simplified.is_numeral()) {
            return simplified.get_numeral_uint64() != 0;
        }
    } catch (z3::exception&) {
    }

    return std::nullopt;
}

std::optional<bool> predicate_simplifier_t::simplify_lnot(const minsn_t* ins) {
    if (!ins || ins->opcode != m_lnot)
        return std::nullopt;

    try {
        z3::expr e = m_translator.translate_insn(ins);
        z3::expr simplified = e.simplify();

        if (simplified.is_numeral()) {
            return simplified.get_numeral_uint64() != 0;
        }
    } catch (z3::exception&) {
    }

    return std::nullopt;
}

std::optional<bool> predicate_simplifier_t::check_comparison_constant(
    mcode_t cmp_op, const mop_t& left, const mop_t& right) {

    try {
        z3::expr l = m_translator.translate_operand(left);
        z3::expr r = m_translator.translate_operand(right);

        z3::expr cmp_expr = m_ctx.ctx().bool_val(false);
        switch (cmp_op) {
            case m_setz:  cmp_expr = (l == r); break;
            case m_setnz: cmp_expr = (l != r); break;
            case m_setl:  cmp_expr = (l < r); break;
            case m_setle: cmp_expr = (l <= r); break;
            case m_setg:  cmp_expr = (l > r); break;
            case m_setge: cmp_expr = (l >= r); break;
            case m_setb:  cmp_expr = z3::ult(l, r); break;
            case m_setbe: cmp_expr = z3::ule(l, r); break;
            case m_seta:  cmp_expr = z3::ugt(l, r); break;
            case m_setae: cmp_expr = z3::uge(l, r); break;
            default:
                return std::nullopt;
        }

        z3::expr simplified = cmp_expr.simplify();
        if (simplified.is_true()) return true;
        if (simplified.is_false()) return false;

    } catch (z3::exception&) {
    }

    return std::nullopt;
}

int predicate_simplifier_t::simplify_jcc(const minsn_t* jcc) {
    if (!jcc || !is_mcode_jcond(jcc->opcode))
        return -1;

    try {
        z3::expr cond = m_translator.translate_jcc_condition(jcc);

        // Check if always true
        m_ctx.solver().reset();
        m_ctx.solver().add(!cond);
        if (m_ctx.solver().check() == z3::unsat) {
            return 1;  // Always taken
        }

        // Check if always false
        m_ctx.solver().reset();
        m_ctx.solver().add(cond);
        if (m_ctx.solver().check() == z3::unsat) {
            return 0;  // Never taken
        }

    } catch (z3::exception&) {
    }

    return -1;  // Unknown
}

} // namespace z3_solver
