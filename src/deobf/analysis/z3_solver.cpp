#include "z3_solver.h"
#include "opaque_eval.h"
#include "../../common/bitvector.h"
#include "../../common/z3_utils.h"
#include <climits>
#include <cstring>

namespace z3_solver {

namespace {
bool register_range_contains(const symbolic_var_t& outer,
                             const symbolic_var_t& inner);
}

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

unsigned get_global_timeout() {
    return g_timeout_ms;
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
    z3::params p(m_ctx);
    p.set("timeout", ms);
    m_solver.set(p);
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
    const int bits = var.size() > 0 && var.size() <= 128
                   ? var.size() * 8 : 32;

    // Check if we have a known value for this variable
    auto it = m_known_values.find(var);
    if (it != m_known_values.end()) {
        return make_const(it->second, bits);
    }

    // Check cache
    auto cache_it = m_var_cache.find(var);
    if (cache_it != m_var_cache.end()) {
        return *cache_it->second;
    }

    // Hex-Rays names overlapping machine-register views by byte intervals.
    // A write to RDX followed by a read from EDX must therefore reuse the low
    // 32 bits of the RDX value instead of creating an unrelated symbol.
    if ( var.kind() == symbolic_var_t::VAR_REGISTER && var.size() > 0 ) {
        for ( const auto &entry : m_known_values ) {
            const symbolic_var_t &stored = entry.first;
            if ( !register_range_contains(stored, var)
              || stored.size() > 8 )
                continue;
            const uint64_t byte_offset = var.id() - stored.id();
            if ( byte_offset >= 8 )
                continue;
            const uint64_t mask = var.size() >= 8
                ? UINT64_MAX : ((uint64_t(1) << (var.size() * 8)) - 1);
            return make_const(
                (entry.second >> (byte_offset * 8)) & mask, bits);
        }
        for ( const auto &entry : m_var_cache ) {
            const symbolic_var_t &stored = entry.first;
            if ( !register_range_contains(stored, var) || !entry.second )
                continue;
            const z3::expr &value = *entry.second;
            const int value_bits = value.get_sort().bv_size();
            const uint64_t byte_offset = var.id() - stored.id();
            const uint64_t low = byte_offset * 8;
            if ( low > static_cast<uint64_t>(INT_MAX)
              || low + static_cast<uint64_t>(bits)
                   > static_cast<uint64_t>(value_bits) )
                continue;
            if ( value_bits == bits && low == 0 )
                return value;
            return extract(
                value, static_cast<int>(low) + bits - 1,
                static_cast<int>(low));
        }
    }

    // Create fresh symbolic variable
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

    name += "_" + std::to_string(var.size()) + "_v"
          + std::to_string(m_fresh_counter++);

    z3::expr e = m_ctx.ctx().bv_const(name.c_str(), bits);
    m_var_cache[var] = std::make_shared<z3::expr>(e);
    return e;
}

z3::expr mcode_translator_t::make_symbolic(const mop_t& op) {
    return make_symbolic(mop_to_var(op));
}

void mcode_translator_t::set_known_value(const symbolic_var_t& var, uint64_t value) {
    m_known_values[var] = value;
    // Update cache to constant
    const int bits = var.size() > 0 && var.size() <= 128
                   ? var.size() * 8 : 32;
    m_var_cache[var] = std::make_shared<z3::expr>(make_const(value, bits));
}

void mcode_translator_t::set_known_value(const mop_t& op, uint64_t value) {
    set_known_value(mop_to_var(op), value);
}

void mcode_translator_t::set_symbolic_value(const symbolic_var_t& var,
                                             const z3::expr& value) {
    m_known_values.erase(var);
    const int bits = var.size() > 0 ? var.size() * 8
                                    : value.get_sort().bv_size();
    m_var_cache[var] = std::make_shared<z3::expr>(resize(value, bits));
}

void mcode_translator_t::set_symbolic_value(const mop_t& op,
                                             const z3::expr& value) {
    set_symbolic_value(mop_to_var(op), value);
}

void mcode_translator_t::invalidate_all_values() {
    m_var_cache.clear();
    m_known_values.clear();
}

void mcode_translator_t::invalidate_memory_values() {
    const auto is_memory = [](const symbolic_var_t& var) {
        return var.kind() == symbolic_var_t::VAR_STACK ||
               var.kind() == symbolic_var_t::VAR_GLOBAL ||
               var.kind() == symbolic_var_t::VAR_MEMORY;
    };

    for ( auto p = m_var_cache.begin(); p != m_var_cache.end(); ) {
        p = is_memory(p->first) ? m_var_cache.erase(p) : std::next(p);
    }
    for ( auto p = m_known_values.begin(); p != m_known_values.end(); ) {
        p = is_memory(p->first) ? m_known_values.erase(p) : std::next(p);
    }
}

void mcode_translator_t::invalidate_values_if(
    const std::function<bool(const symbolic_var_t&)>& predicate) {
    for ( auto p = m_var_cache.begin(); p != m_var_cache.end(); ) {
        p = predicate(p->first) ? m_var_cache.erase(p) : std::next(p);
    }
    for ( auto p = m_known_values.begin(); p != m_known_values.end(); ) {
        p = predicate(p->first) ? m_known_values.erase(p) : std::next(p);
    }
}

namespace {

bool unsigned_ranges_overlap(uint64_t left, int left_size,
                             uint64_t right, int right_size)
{
    if ( left_size <= 0 || right_size <= 0 )
        return left == right;
    const uint64_t lsize = static_cast<uint64_t>(left_size);
    const uint64_t rsize = static_cast<uint64_t>(right_size);
    if ( left > UINT64_MAX - lsize || right > UINT64_MAX - rsize )
        return true;
    return left < right + rsize && right < left + lsize;
}

bool signed_ranges_overlap(uint64_t left_id, int left_size,
                           uint64_t right_id, int right_size)
{
    const int64_t left = static_cast<int64_t>(left_id);
    const int64_t right = static_cast<int64_t>(right_id);
    if ( left_size <= 0 || right_size <= 0 )
        return left == right;
    if ( left > INT64_MAX - left_size || right > INT64_MAX - right_size )
        return true;
    return left < right + right_size && right < left + left_size;
}

bool unsigned_range_contains(uint64_t outer, int outer_size,
                             uint64_t inner, int inner_size)
{
    if ( outer_size <= 0 || inner_size <= 0 )
        return outer == inner && outer_size == inner_size;
    const uint64_t outer_width = static_cast<uint64_t>(outer_size);
    const uint64_t inner_width = static_cast<uint64_t>(inner_size);
    if ( outer > inner || outer > UINT64_MAX - outer_width
      || inner > UINT64_MAX - inner_width )
        return false;
    return inner + inner_width <= outer + outer_width;
}

bool signed_range_contains(uint64_t outer_id, int outer_size,
                           uint64_t inner_id, int inner_size)
{
    const int64_t outer = static_cast<int64_t>(outer_id);
    const int64_t inner = static_cast<int64_t>(inner_id);
    if ( outer_size <= 0 || inner_size <= 0 )
        return outer == inner && outer_size == inner_size;
    if ( outer > inner || outer > INT64_MAX - outer_size
      || inner > INT64_MAX - inner_size )
        return false;
    return inner + inner_size <= outer + outer_size;
}

bool register_range_contains(const symbolic_var_t& outer,
                             const symbolic_var_t& inner)
{
    if ( outer.kind() != symbolic_var_t::VAR_REGISTER
      || inner.kind() != symbolic_var_t::VAR_REGISTER
      || outer.size() <= 0 || inner.size() <= 0
      || outer.id() > inner.id() )
        return false;
    const uint64_t outer_size = static_cast<uint64_t>(outer.size());
    const uint64_t inner_size = static_cast<uint64_t>(inner.size());
    if ( outer.id() > UINT64_MAX - outer_size
      || inner.id() > UINT64_MAX - inner_size )
        return false;
    return inner.id() + inner_size <= outer.id() + outer_size;
}

bool variable_range_contains(const symbolic_var_t& outer,
                             const symbolic_var_t& inner)
{
    if ( outer.kind() != inner.kind() )
        return false;
    switch ( outer.kind() ) {
        case symbolic_var_t::VAR_REGISTER:
            return register_range_contains(outer, inner);
        case symbolic_var_t::VAR_STACK:
            return signed_range_contains(
                outer.id(), outer.size(), inner.id(), inner.size());
        case symbolic_var_t::VAR_GLOBAL:
            return unsigned_range_contains(
                outer.id(), outer.size(), inner.id(), inner.size());
        case symbolic_var_t::VAR_LOCAL:
            return outer.id() == inner.id()
                && (outer.size() <= 0 || inner.size() <= 0
                    ? outer.size() == inner.size()
                    : outer.size() >= inner.size());
        default:
            return outer == inner;
    }
}

bool variables_may_alias(const symbolic_var_t& left,
                         const symbolic_var_t& right)
{
    const auto is_memory = [](symbolic_var_t::var_kind_t kind) {
        return kind == symbolic_var_t::VAR_STACK ||
               kind == symbolic_var_t::VAR_GLOBAL ||
               kind == symbolic_var_t::VAR_MEMORY;
    };

    if ( is_memory(left.kind()) && is_memory(right.kind()) ) {
        if ( left.kind() == symbolic_var_t::VAR_MEMORY
          || right.kind() == symbolic_var_t::VAR_MEMORY )
            return true;
        if ( left.kind() != right.kind() )
            return false;
        if ( left.kind() == symbolic_var_t::VAR_STACK )
            return signed_ranges_overlap(
                left.id(), left.size(), right.id(), right.size());
        if ( left.kind() == symbolic_var_t::VAR_GLOBAL )
            return unsigned_ranges_overlap(
                left.id(), left.size(), right.id(), right.size());
        if ( left.kind() == symbolic_var_t::VAR_MEMORY )
            return true;
        return left.id() == right.id();
    }
    if ( left.kind() != right.kind() )
        return false;

    if ( left.kind() == symbolic_var_t::VAR_REGISTER ) {
        return unsigned_ranges_overlap(
            left.id(), left.size(), right.id(), right.size());
    }

    // Local IDs name the same lvar independent of the access width. Temporary
    // IDs are unique within one translator epoch.
    return left.id() == right.id();
}

std::optional<symbolic_var_t> symbolic_var_from_mop(const mop_t& op)
{
    switch ( op.t ) {
        case mop_r:
            return symbolic_var_t(
                symbolic_var_t::VAR_REGISTER, op.r, op.size);
        case mop_S:
            if ( op.s )
                return symbolic_var_t(
                    symbolic_var_t::VAR_STACK,
                    static_cast<uint64_t>(op.s->off), op.size);
            break;
        case mop_v:
            return symbolic_var_t(
                symbolic_var_t::VAR_GLOBAL, op.g, op.size);
        case mop_l:
            if ( op.l )
                return symbolic_var_t(
                    symbolic_var_t::VAR_LOCAL,
                    static_cast<uint64_t>(op.l->idx), op.size);
            break;
        default:
            break;
    }
    return std::nullopt;
}

} // namespace

void mcode_translator_t::invalidate_aliases(const symbolic_var_t& var) {
    if ( var.kind() == symbolic_var_t::VAR_MEMORY ) {
        invalidate_memory_values();
        return;
    }

    for ( auto p = m_var_cache.begin(); p != m_var_cache.end(); ) {
        p = variables_may_alias(p->first, var) ? m_var_cache.erase(p)
                                                : std::next(p);
    }
    for ( auto p = m_known_values.begin(); p != m_known_values.end(); ) {
        p = variables_may_alias(p->first, var) ? m_known_values.erase(p)
                                                : std::next(p);
    }
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
            if ( op.nnn )
                return make_const(op.nnn->value, bits);
            break;

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

    const int result_bits = ins->d.size > 0 ? ins->d.size * 8 : 32;

    // This translator models integer bit-vectors only. A fresh value preserves
    // soundness for floating-point instructions (notably NaN-sensitive setX)
    // without claiming IEEE 754 equivalences that were never encoded.
    if (ins->is_fpinsn()) {
        return m_ctx.ctx().bv_const(
            ("fp_" + std::to_string(m_fresh_counter++)).c_str(), result_bits);
    }

    // Hex-Rays represents rotate intrinsics as nested helper calls (for
    // example, `mov call !__ROL4__(x, 7), edx`). They are pure bit-vector
    // operations and must remain related to their arguments for encoded CFF
    // state expressions to cancel exactly.
    if ( ins->opcode == m_call && ins->d.t == mop_f && ins->d.f
      && ins->d.f->args.size() >= 2 ) {
        const funcrole_t role = ins->d.f->role;
        const char *helper = ins->l.t == mop_h ? ins->l.helper : nullptr;
        const bool is_rol = role == ROLE_ROL
          || (helper && std::strstr(helper, "ROL") != nullptr);
        const bool is_ror = role == ROLE_ROR
          || (helper && std::strstr(helper, "ROR") != nullptr);
        if ( is_rol || is_ror ) {
            z3::expr value = translate_operand(ins->d.f->args[0]);
            const int width = value.get_sort().bv_size();
            if ( width > 0 && (width & (width - 1)) == 0 ) {
                z3::expr shift = resize(
                    translate_operand(ins->d.f->args[1]), width);
                const z3::expr mask = make_const(
                    static_cast<uint64_t>(width - 1), width);
                shift = shift & mask;
                const z3::expr inverse =
                    (make_const(static_cast<uint64_t>(width), width) - shift)
                    & mask;
                z3::expr rotated = is_rol
                    ? (z3::shl(value, shift) | z3::lshr(value, inverse))
                    : (z3::lshr(value, shift) | z3::shl(value, inverse));
                return resize(rotated, result_bits);
            }
        }
    }

    // Translate operands
    z3::expr l = translate_operand(ins->l, result_bits / 8);
    z3::expr r = translate_operand(ins->r, result_bits / 8);

    // Ensure operands have matching bit widths for binary operations
    if (l.get_sort().bv_size() != r.get_sort().bv_size()) {
        int max_bits = std::max((int)l.get_sort().bv_size(), (int)r.get_sort().bv_size());
        const bool signed_operands =
            ins->opcode == m_setl || ins->opcode == m_setle ||
            ins->opcode == m_setg || ins->opcode == m_setge ||
            ins->opcode == m_sdiv || ins->opcode == m_smod ||
            ins->opcode == m_sar;
        l = resize(l, max_bits, signed_operands);
        r = resize(r, max_bits, signed_operands);
    }

    z3::expr result = m_ctx.ctx().bv_val(0, result_bits);

    switch (ins->opcode) {
        // Data movement
        case m_ldc:
        case m_mov:
            result = l;
            break;

        case m_ldx:
            // A load is not equal to its segment selector. Without a memory
            // model, a fresh value is the conservative representation.
            result = m_ctx.ctx().bv_const(
                ("load_" + std::to_string(m_fresh_counter++)).c_str(), result_bits);
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
        case m_sdiv:
        case m_umod:
        case m_smod: {
            // SMT-LIB makes division by zero total, but executable division
            // can trap. Only model division/modulo when the divisor is an
            // exact nonzero value. Signed MIN / -1 can overflow as well.
            const int operand_bytes =
                static_cast<int>(r.get_sort().bv_size() / 8U);
            const int divisor_bytes =
                chernobog::bitvector::valid_byte_width(ins->r.size)
                ? ins->r.size : operand_bytes;
            const std::optional<uint64_t> divisor_value =
                opaque_eval_t::evaluate_operand(ins->r);
            const uint64_t divisor = divisor_value
                ? chernobog::bitvector::truncate(*divisor_value, divisor_bytes)
                : 0;

            bool safe = divisor_value.has_value() && divisor != 0;
            if ( safe && (ins->opcode == m_sdiv || ins->opcode == m_smod) &&
                 chernobog::bitvector::sign_extend(divisor, divisor_bytes) == -1 ) {
                const std::optional<uint64_t> dividend_value =
                    opaque_eval_t::evaluate_operand(ins->l);
                const int dividend_bytes =
                    chernobog::bitvector::valid_byte_width(ins->l.size)
                    ? ins->l.size : operand_bytes;
                safe = dividend_value.has_value() &&
                    chernobog::bitvector::sign_extend(
                        *dividend_value, dividend_bytes) !=
                    chernobog::bitvector::signed_min(operand_bytes);
            }

            if ( !safe ) {
                result = m_ctx.ctx().bv_const(
                    ("div_" + std::to_string(m_fresh_counter++)).c_str(),
                    result_bits);
            } else if ( ins->opcode == m_udiv ) {
                result = z3::udiv(l, r);
            } else if ( ins->opcode == m_sdiv ) {
                result = l / r;
            } else if ( ins->opcode == m_umod ) {
                result = z3::urem(l, r);
            } else {
                result = z3::srem(l, r);
            }
            break;
        }

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
            result = z3::ite(l == 0, m_ctx.ctx().bv_val(1, result_bits),
                            m_ctx.ctx().bv_val(0, result_bits));
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

        // These operations are pure and write only their explicit result.
        // Keep the flag bit unconstrained instead of risking an incomplete
        // architecture-specific flags model. This over-approximates the
        // concrete operation and therefore cannot manufacture uniqueness.
        case m_cfadd:
        case m_ofadd:
        case m_cfshl:
        case m_cfshr:
        case m_sets:
        case m_seto:
        case m_setp:
            result = m_ctx.ctx().bv_const(
                ("flag_" + std::to_string(m_fresh_counter++)).c_str(),
                result_bits);
            break;

        // Comparisons (return 1 or 0)
        case m_setz:
            result = z3::ite(l == r, m_ctx.ctx().bv_val(1, result_bits),
                            m_ctx.ctx().bv_val(0, result_bits));
            break;

        case m_setnz:
            result = z3::ite(l != r, m_ctx.ctx().bv_val(1, result_bits),
                            m_ctx.ctx().bv_val(0, result_bits));
            break;

        case m_setl:
            result = z3::ite(l < r, m_ctx.ctx().bv_val(1, result_bits),
                            m_ctx.ctx().bv_val(0, result_bits));
            break;

        case m_setle:
            result = z3::ite(l <= r, m_ctx.ctx().bv_val(1, result_bits),
                            m_ctx.ctx().bv_val(0, result_bits));
            break;

        case m_setg:
            result = z3::ite(l > r, m_ctx.ctx().bv_val(1, result_bits),
                            m_ctx.ctx().bv_val(0, result_bits));
            break;

        case m_setge:
            result = z3::ite(l >= r, m_ctx.ctx().bv_val(1, result_bits),
                            m_ctx.ctx().bv_val(0, result_bits));
            break;

        case m_setb:
            result = z3::ite(z3::ult(l, r), m_ctx.ctx().bv_val(1, result_bits),
                            m_ctx.ctx().bv_val(0, result_bits));
            break;

        case m_setbe:
            result = z3::ite(z3::ule(l, r), m_ctx.ctx().bv_val(1, result_bits),
                            m_ctx.ctx().bv_val(0, result_bits));
            break;

        case m_seta:
            result = z3::ite(z3::ugt(l, r), m_ctx.ctx().bv_val(1, result_bits),
                            m_ctx.ctx().bv_val(0, result_bits));
            break;

        case m_setae:
            result = z3::ite(z3::uge(l, r), m_ctx.ctx().bv_val(1, result_bits),
                            m_ctx.ctx().bv_val(0, result_bits));
            break;

        // Sign extension
        case m_xds:
            result = sign_extend(l, result_bits);
            break;

        // Zero extension
        case m_xdu:
            result = zero_extend(l, result_bits);
            break;

        // Low/high byte operations
        case m_low:
            if (l.get_sort().bv_size() >= result_bits) {
                result = extract(l, result_bits - 1, 0);
            } else {
                result = l;
            }
            break;

        case m_high:
            {
                int src_bits = l.get_sort().bv_size();
                if (src_bits > result_bits) {
                    result = extract(l, src_bits - 1, src_bits - result_bits);
                } else {
                    result = make_const(0, result_bits);
                }
            }
            break;

        default:
            // Unknown operation - return fresh variable
            deobf::log_verbose("[z3] Unknown opcode %d in translate_insn\n", ins->opcode);
            result = m_ctx.ctx().bv_const(
                ("insn_" + std::to_string(m_fresh_counter++)).c_str(), result_bits);
            break;
    }

    return resize(result, result_bits);
}

z3::expr mcode_translator_t::translate_jcc_condition(const minsn_t* jcc) {
    if (!jcc) {
        return m_ctx.ctx().bool_val(false);
    }

    if (jcc->is_fpinsn()) {
        return m_ctx.ctx().bool_const(
            ("fpjcc_" + std::to_string(m_fresh_counter++)).c_str());
    }

    z3::expr l = translate_operand(jcc->l);
    if (jcc->opcode == m_jcnd) {
        return l != 0;
    }

    // Hex-Rays jX instructions compare L and R directly. A nested setX in L
    // remains an ordinary bit-vector operand; interpreting it separately and
    // then negating for jz loses the value of R.
    z3::expr r = translate_operand(jcc->r);
    if (l.get_sort().bv_size() != r.get_sort().bv_size()) {
        const int bits = std::max(static_cast<int>(l.get_sort().bv_size()),
                                  static_cast<int>(r.get_sort().bv_size()));
        const bool signed_compare = jcc->opcode == m_jl || jcc->opcode == m_jle ||
                                    jcc->opcode == m_jg || jcc->opcode == m_jge;
        l = resize(l, bits, signed_compare);
        r = resize(r, bits, signed_compare);
    }

    switch (jcc->opcode) {
        case m_jnz: return l != r;
        case m_jz:  return l == r;
        case m_jae: return z3::uge(l, r);
        case m_jb:  return z3::ult(l, r);
        case m_ja:  return z3::ugt(l, r);
        case m_jbe: return z3::ule(l, r);
        case m_jg:  return l > r;
        case m_jge: return l >= r;
        case m_jl:  return l < r;
        case m_jle: return l <= r;
        default:
            // A non-jcc/unsupported condition is unknown, never false by
            // construction. Callers may attempt tautology proofs on it.
            return m_ctx.ctx().bool_const(
                ("jcc_" + std::to_string(m_fresh_counter++)).c_str());
    }
}

//--------------------------------------------------------------------------
// symbolic_executor_t implementation
//--------------------------------------------------------------------------
symbolic_executor_t::symbolic_executor_t(z3_context_t& ctx)
    : m_ctx(ctx), m_translator(ctx) {
}

void symbolic_executor_t::reset() {
    m_state.clear();
    m_call_preserved.clear();
    m_assumptions.clear();
    m_translator.reset();
}

namespace {

bool is_modeled_pure_rotate_call(const minsn_t *instruction)
{
    if ( !instruction || instruction->opcode != m_call
      || instruction->d.t != mop_f || !instruction->d.f )
        return false;
    if ( instruction->d.f->role == ROLE_ROL
      || instruction->d.f->role == ROLE_ROR )
        return true;
    const char *helper = instruction->l.t == mop_h
        ? instruction->l.helper : nullptr;
    return helper && (std::strstr(helper, "ROL") != nullptr
                   || std::strstr(helper, "ROR") != nullptr);
}

struct nested_call_collector_t : public minsn_visitor_t
{
    const minsn_t *root = nullptr;
    std::vector<const minsn_t *> calls;

    explicit nested_call_collector_t(const minsn_t *instruction)
      : root(instruction) {}

    int idaapi visit_minsn() override
    {
        if ( curins != nullptr && curins != root
          && is_mcode_call(curins->opcode)
          && !is_modeled_pure_rotate_call(curins) )
        {
            calls.push_back(curins);
        }
        return 0;
    }
};

} // namespace

void symbolic_executor_t::invalidate_call_effects(const minsn_t* ins) {
    const mcallinfo_t *call_info =
        ins && ins->d.t == mop_f ? ins->d.f : nullptr;
    const auto preserved = [&](const symbolic_var_t &candidate) {
        return std::any_of(
            m_call_preserved.begin(), m_call_preserved.end(),
            [&](const symbolic_var_t &value) {
                // A proof for one byte/range cannot preserve a wider stale
                // binding merely because the ranges overlap.
                return variable_range_contains(value, candidate);
            });
    };
    const auto invalidated = [&](const symbolic_var_t &candidate) {
        if ( preserved(candidate) )
            return false;
        if ( candidate.kind() == symbolic_var_t::VAR_REGISTER ) {
            return !call_info || call_info->spoiled.reg.has_any(
                static_cast<mreg_t>(candidate.id()), candidate.size());
        }
        if ( candidate.kind() == symbolic_var_t::VAR_STACK
          || candidate.kind() == symbolic_var_t::VAR_GLOBAL
          || candidate.kind() == symbolic_var_t::VAR_LOCAL
          || candidate.kind() == symbolic_var_t::VAR_MEMORY ) {
            return !call_info || call_info->spoiled.has_memory();
        }
        return false;
    };
    for ( auto p = m_state.begin(); p != m_state.end(); )
        p = invalidated(p->first) ? m_state.erase(p) : std::next(p);
    m_translator.invalidate_values_if(invalidated);
}

void symbolic_executor_t::execute_insn(const minsn_t* ins) {
    if (!ins) return;

    // Propagated expressions can contain calls. Apply their spoil sets before
    // evaluating the enclosing assignment; otherwise a nested unknown call can
    // leave a stale selector binding live and manufacture a transition proof.
    nested_call_collector_t nested_calls(ins);
    const_cast<minsn_t *>(ins)->for_all_insns(nested_calls);
    for ( const minsn_t *nested : nested_calls.calls ) {
        if ( !is_modeled_pure_rotate_call(nested) )
            invalidate_call_effects(nested);
    }

    // Respect Hex-Rays' explicit spoiled-register set. Missing callinfo is a
    // hard register/global-memory barrier. Private stack/local storage is not
    // call-visible because recurrent-switch analysis rejects address escape.
    if (is_mcode_call(ins->opcode)) {
        if ( !is_modeled_pure_rotate_call(ins) )
            invalidate_call_effects(ins);
        return;
    }

    switch (ins->opcode) {
        case m_mov:
            handle_assignment(ins);
            break;

        case m_ldx:
            handle_load(ins);
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
    const std::optional<symbolic_var_t> destination =
        symbolic_var_from_mop(ins->d);
    if ( destination ) {
        const symbolic_var_t &dst_var = *destination;
        for ( auto p = m_state.begin(); p != m_state.end(); ) {
            p = variables_may_alias(p->first, dst_var) ? m_state.erase(p)
                                                        : std::next(p);
        }
        m_translator.invalidate_aliases(dst_var);
        m_state[dst_var] = std::make_shared<z3::expr>(value);
        m_translator.set_symbolic_value(dst_var, value);
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

    std::optional<z3::expr> stored_value;
    if (ins->d.t == mop_S || ins->d.t == mop_v)
        stored_value = m_translator.translate_operand(ins->l);

    // A store can overlap a previously tracked location. Invalidate memory
    // first, then install an exact direct stack/global destination if present.
    for ( auto p = m_state.begin(); p != m_state.end(); ) {
        const auto kind = p->first.kind();
        const bool memory = kind == symbolic_var_t::VAR_STACK ||
                            kind == symbolic_var_t::VAR_GLOBAL ||
                            kind == symbolic_var_t::VAR_MEMORY;
        p = memory ? m_state.erase(p) : std::next(p);
    }
    m_translator.invalidate_memory_values();

    if (stored_value.has_value()) {
        symbolic_var_t dst_var = symbolic_var_t(
            ins->d.t == mop_S ? symbolic_var_t::VAR_STACK : symbolic_var_t::VAR_GLOBAL,
            ins->d.t == mop_S && ins->d.s ? ins->d.s->off : ins->d.g,
            ins->d.size
        );
        m_state[dst_var] = std::make_shared<z3::expr>(*stored_value);
        m_translator.set_symbolic_value(dst_var, *stored_value);
    }
}

void symbolic_executor_t::execute_block(const mblock_t* blk) {
    if (!blk) return;

    for (const minsn_t* ins = blk->head; ins; ins = ins->next) {
        execute_insn(ins);
    }
}

z3::expr symbolic_executor_t::evaluate_operand(
    const mop_t& op, int default_size) {
    return m_translator.translate_operand(op, default_size);
}

z3::expr symbolic_executor_t::evaluate_jcc_condition(const minsn_t* jcc) {
    return m_translator.translate_jcc_condition(jcc);
}

bool symbolic_executor_t::assume(const z3::expr& condition) {
    if ( &condition.ctx() != &m_ctx.ctx() || !condition.is_bool() )
        return false;
    m_assumptions.push_back(condition);
    return true;
}

symbolic_executor_t::feasibility_t
symbolic_executor_t::check_feasibility() {
    try {
        m_ctx.solver().reset();
        for ( const z3::expr &condition : m_assumptions )
            m_ctx.solver().add(condition);
        const z3::check_result result = m_ctx.solver().check();
        if ( result == z3::sat )
            return feasibility_t::feasible;
        if ( result == z3::unsat )
            return feasibility_t::infeasible;
        deobf::log_verbose(
            "[z3] path-feasibility query returned unknown: %s\n",
            m_ctx.solver().reason_unknown().c_str());
    } catch ( ... ) {
        deobf::log_verbose(
            "[z3] path-feasibility query raised an exception\n");
    }
    return feasibility_t::unknown;
}

void symbolic_executor_t::set_value(
    const mop_t& op, const z3::expr& value, bool preserve_across_calls) {
    const std::optional<symbolic_var_t> destination =
        symbolic_var_from_mop(op);
    if ( !destination )
        return;
    for ( auto p = m_state.begin(); p != m_state.end(); ) {
        p = variables_may_alias(p->first, *destination)
            ? m_state.erase(p) : std::next(p);
    }
    m_translator.invalidate_aliases(*destination);
    m_state[*destination] = std::make_shared<z3::expr>(value);
    m_translator.set_symbolic_value(*destination, value);
    if ( preserve_across_calls
      && std::none_of(
          m_call_preserved.begin(), m_call_preserved.end(),
          [&](const symbolic_var_t &existing) {
              return existing == *destination;
          }) ) {
        m_call_preserved.push_back(*destination);
    }
}

void symbolic_executor_t::preserve_across_calls(const mop_t& op) {
    const std::optional<symbolic_var_t> value = symbolic_var_from_mop(op);
    if ( !value )
        return;
    if ( std::none_of(
            m_call_preserved.begin(), m_call_preserved.end(),
            [&](const symbolic_var_t &existing) {
                return existing == *value;
            }) ) {
        m_call_preserved.push_back(*value);
    }
}

void symbolic_executor_t::invalidate_memory_values() {
    const auto is_memory = [](const symbolic_var_t &var) {
        return var.kind() == symbolic_var_t::VAR_STACK
            || var.kind() == symbolic_var_t::VAR_GLOBAL
            || var.kind() == symbolic_var_t::VAR_LOCAL
            || var.kind() == symbolic_var_t::VAR_MEMORY;
    };
    for ( auto p = m_state.begin(); p != m_state.end(); ) {
        p = is_memory(p->first) ? m_state.erase(p) : std::next(p);
    }
    m_translator.invalidate_values_if(is_memory);
}

std::optional<z3::expr> symbolic_executor_t::get_value(const symbolic_var_t& var) {
    auto it = m_state.find(var);
    if (it != m_state.end() && it->second) {
        return *it->second;
    }
    if ( var.kind() == symbolic_var_t::VAR_REGISTER && var.size() > 0 ) {
        for ( const auto &entry : m_state ) {
            const symbolic_var_t &stored = entry.first;
            if ( !register_range_contains(stored, var) || !entry.second )
                continue;
            const int bits = var.size() * 8;
            const z3::expr &value = *entry.second;
            const uint64_t byte_offset = var.id() - stored.id();
            const uint64_t low = byte_offset * 8;
            const uint64_t value_bits = value.get_sort().bv_size();
            if ( low + static_cast<uint64_t>(bits) > value_bits )
                continue;
            if ( value_bits == static_cast<unsigned>(bits) && low == 0 )
                return value;
            return value.extract(
                static_cast<unsigned>(low) + bits - 1,
                static_cast<unsigned>(low));
        }
    }
    return std::nullopt;
}

std::optional<z3::expr> symbolic_executor_t::get_value(const mop_t& op) {
    if ( (op.t == mop_S && !op.s) || (op.t == mop_l && !op.l) ||
         (op.t != mop_r && op.t != mop_S && op.t != mop_v && op.t != mop_l) )
        return std::nullopt;

    const std::optional<symbolic_var_t> var = symbolic_var_from_mop(op);
    return var ? get_value(*var) : std::nullopt;
}

std::optional<uint64_t> symbolic_executor_t::solve_for_value(const z3::expr& expr) {
    try {
        if ( !expr.is_bv() || expr.get_sort().bv_size() > 64U )
            return std::nullopt;
        m_ctx.solver().reset();
        for ( const z3::expr &condition : m_assumptions )
            m_ctx.solver().add(condition);
        const z3::check_result first = m_ctx.solver().check();
        if ( first != z3::sat ) {
            if ( first == z3::unknown ) {
                deobf::log_verbose(
                    "[z3] unique-value model query returned unknown: %s\n",
                    m_ctx.solver().reason_unknown().c_str());
            }
            return std::nullopt;
        }
        const z3::expr value = m_ctx.solver().get_model().eval(expr, true);
        uint64_t concrete = 0;
        if ( !value.is_numeral()
          || !Z3_get_numeral_uint64(expr.ctx(), value, &concrete) )
            return std::nullopt;

        m_ctx.solver().push();
        m_ctx.solver().add(expr != expr.ctx().bv_val(
            concrete, expr.get_sort().bv_size()));
        const z3::check_result alternative = m_ctx.solver().check();
        if ( alternative == z3::unknown ) {
            deobf::log_verbose(
                "[z3] unique-value exclusion query returned unknown: %s\n",
                m_ctx.solver().reason_unknown().c_str());
        }
        m_ctx.solver().pop();
        return alternative == z3::unsat
            ? std::optional<uint64_t>(concrete) : std::nullopt;
    } catch ( ... ) {
        deobf::log_verbose(
            "[z3] unique-value query raised an exception\n");
        return std::nullopt;
    }
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

                            // A block reference transfers to the block start.
                            // Mapping an interior instruction to the containing
                            // block would silently change the branch target.
                            for (int bi = 0; bi < mba->qty; bi++) {
                                mblock_t* tblk = mba->get_mblock(bi);
                                if (tblk && tblk->start == target_addr) {
                                    target_block = bi;
                                    break;
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

    // Fallback: inspect the last relevant write only. Returning an earlier
    // constant after a later unknown write would manufacture a transition.
    for (const minsn_t* ins = blk->tail; ins; ins = ins->prev) {
        if ( is_mcode_call(ins->opcode) )
            return std::nullopt;

        // Check whether the explicit destination matches the state variable.
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
            if ((ins->opcode == m_mov || ins->opcode == m_stx) &&
                ins->l.t == mop_n && ins->l.nnn &&
                is_hikari_state_const(ins->l.nnn->value)) {
                return ins->l.nnn->value;
            }
            return std::nullopt;
        }

        // An intervening store may alias a stack/global state variable.
        if ( ins->opcode == m_stx &&
             (state_var.kind() == symbolic_var_t::VAR_STACK ||
              state_var.kind() == symbolic_var_t::VAR_GLOBAL) )
            return std::nullopt;
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

    return machine;
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
