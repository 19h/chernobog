#include "mba_simplify.h"
#include "../analysis/ast.h"
#include "../analysis/ast_builder.h"
#include "../analysis/chain_simplify.h"
#include "../analysis/z3_solver.h"
#include "../../common/z3_utils.h"

// Include all rule headers to trigger registration
#include "../rules/rules_add.h"
#include "../rules/rules_sub.h"
#include "../rules/rules_xor.h"
#include "../rules/rules_and.h"
#include "../rules/rules_or.h"
#include "../rules/rules_misc.h"

using namespace chernobog::ast;
using namespace chernobog::rules;

// Static member initialization
bool mba_simplify_handler_t::initialized_ = false;
size_t mba_simplify_handler_t::total_simplified_ = 0;

namespace {

static void mba_affine_debug(const char *fmt, ...)
{
    qstring env;
    if ( !qgetenv("CHERNOBOG_MBA_DEBUG", &env) || env.empty() || env[0] == '0' )
        return;

#ifndef _WIN32
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    int len = qvsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if ( len <= 0 )
        return;
    const size_t bytes = std::min(static_cast<size_t>(len), sizeof(buf) - 1);

    int fd = open("/tmp/chernobog_mba_debug.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if ( fd >= 0 )
    {
        write(fd, buf, bytes);
        close(fd);
    }
#else
    (void)fmt;
#endif
}

static uint64_t mba_mask_for_size(int size)
{
    switch ( size )
    {
        case 1: return 0xFFULL;
        case 2: return 0xFFFFULL;
        case 4: return 0xFFFFFFFFULL;
        case 8: return 0xFFFFFFFFFFFFFFFFULL;
        default: return 0xFFFFFFFFFFFFFFFFULL;
    }
}

static bool mba_pure_mop(const mop_t &mop);

static bool mba_pure_insn(const minsn_t *ins)
{
    if ( !ins )
        return false;

    switch ( ins->opcode )
    {
        case m_mov:
        case m_add:
        case m_sub:
        case m_mul:
        case m_and:
        case m_or:
        case m_xor:
        case m_bnot:
        case m_neg:
        case m_shl:
        case m_shr:
        case m_sar:
        case m_xdu:
        case m_xds:
        case m_low:
        case m_high:
            break;
        default:
            return false;
    }

    return mba_pure_mop(ins->l) && mba_pure_mop(ins->r);
}

static bool mba_pure_mop(const mop_t &mop)
{
    switch ( mop.t )
    {
        case mop_z:
        case mop_n:
        case mop_r:
        case mop_l:
        case mop_S:
            return true;
        case mop_d:
            return mop.d != nullptr && mba_pure_insn(mop.d);
        default:
            return false;
    }
}

static int mba_expr_op_count(const minsn_t *ins)
{
    if ( !ins )
        return 0;
    int count = 1;
    if ( ins->l.t == mop_d && ins->l.d )
        count += mba_expr_op_count(ins->l.d);
    if ( ins->r.t == mop_d && ins->r.d )
        count += mba_expr_op_count(ins->r.d);
    return count;
}

static bool mba_is_const_mop(const mop_t &mop)
{
    return mop.t == mop_n && mop.nnn != nullptr;
}

static bool mba_is_add_tree(const mop_t &mop)
{
    if ( mop.t != mop_d || !mop.d )
        return false;
    return mop.d->opcode == m_add || mop.d->opcode == m_sub;
}

static bool mba_is_small_affine_candidate(const minsn_t *ins, int op_count)
{
    if ( op_count >= 8 )
        return true;
    if ( !ins || op_count < 3 )
        return false;

    if ( ins->opcode == m_mul )
    {
        return (mba_is_const_mop(ins->l) && mba_is_add_tree(ins->r))
            || (mba_is_const_mop(ins->r) && mba_is_add_tree(ins->l));
    }

    return false;
}

static bool mba_affine_enabled()
{
    static int cached = -1;
    if ( cached != -1 )
        return cached == 1;

    qstring env;
    cached = (qgetenv("CHERNOBOG_MBA_AFFINE", &env)
           && !env.empty() && env[0] == '1') ? 1 : 0;
    return cached == 1;
}

static bool mba_is_readable_modular_value(uint64_t value, uint64_t mask)
{
    value &= mask;
    const uint64_t negative_magnitude = ((~value) + 1) & mask;
    return value <= 0x1000 || negative_magnitude <= 0x1000;
}

static bool mba_same_mop(const mop_t &a, const mop_t &b)
{
    return a.size > 0 && a.size == b.size && a.equal_mops(b, EQ_IGNSIZE);
}

static void mba_collect_vars(const mop_t &mop, std::vector<mop_t> *out)
{
    if ( !out )
        return;
    if ( mop.t == mop_d && mop.d )
    {
        mba_collect_vars(mop.d->l, out);
        mba_collect_vars(mop.d->r, out);
        return;
    }
    if ( mop.t != mop_r && mop.t != mop_l && mop.t != mop_S )
        return;

    for ( const mop_t &existing : *out )
    {
        if ( mba_same_mop(existing, mop) )
            return;
    }
    out->push_back(mop);
}

static void mba_collect_vars(const minsn_t *ins, std::vector<mop_t> *out)
{
    if ( !ins || !out )
        return;
    mba_collect_vars(ins->l, out);
    mba_collect_vars(ins->r, out);
}

static bool z3_eval_with_model(z3_solver::z3_context_t &zctx,
                               const z3::expr &expr,
                               const std::vector<z3::expr> &vars,
                               size_t hot_idx,
                               uint64_t hot_value,
                               uint64_t *out)
{
    if ( !out )
        return false;

    zctx.solver().reset();
    for ( size_t i = 0; i < vars.size(); ++i )
    {
        unsigned bits = vars[i].get_sort().bv_size();
        uint64_t value = (i == hot_idx) ? hot_value : 0;
        zctx.solver().add(vars[i] == zctx.ctx().bv_val(value, bits));
    }

    if ( zctx.solver().check() != z3::sat )
        return false;

    z3::expr val = zctx.solver().get_model().eval(expr, true);
    return Z3_get_numeral_uint64(zctx.ctx(), val, out);
}

static bool make_scaled_term(mop_t *out,
                             const mop_t &var,
                             uint64_t coeff,
                             ea_t ea,
                             int size)
{
    if ( !out || coeff == 0 )
        return false;

    if ( coeff == 1 )
    {
        *out = var;
        out->size = size;
        return true;
    }

    minsn_t mul(ea);
    mul.opcode = m_mul;
    mul.l.make_number(coeff, size);
    mul.r = var;
    mul.r.size = size;
    mul.d.size = size;
    out->create_from_insn(&mul);
    out->size = size;
    return out->t != mop_z;
}

static bool rewrite_as_affine(minsn_t *ins,
                              const std::vector<mop_t> &vars,
                              const std::vector<uint64_t> &coeffs,
                              uint64_t constant)
{
    if ( !ins || vars.size() != coeffs.size() )
        return false;

    int size = ins->d.size;
    if ( size <= 0 || size > 4 )
        return false;

    std::vector<mop_t> terms;
    terms.reserve(vars.size() + (constant != 0));

    for ( size_t i = 0; i < vars.size(); ++i )
    {
        if ( coeffs[i] == 0 )
            continue;

        mop_t term;
        if ( !make_scaled_term(&term, vars[i], coeffs[i], ins->ea, size) )
            return false;
        terms.push_back(term);
    }

    if ( constant != 0 )
    {
        mop_t c;
        c.make_number(constant, size);
        terms.push_back(c);
    }

    ea_t ea = ins->ea;
    mop_t dst = ins->d;
    dst.size = size;

    if ( terms.empty() )
    {
        ins->opcode = m_mov;
        ins->l.make_number(0, size);
        ins->r.erase();
        ins->d = dst;
        ins->ea = ea;
        return true;
    }

    if ( terms.size() == 1 )
    {
        ins->opcode = m_mov;
        ins->l = terms[0];
        ins->l.size = size;
        ins->r.erase();
        ins->d = dst;
        ins->ea = ea;
        return true;
    }

    mop_t accum = terms[0];
    for ( size_t i = 1; i + 1 < terms.size(); ++i )
    {
        minsn_t add(ea);
        add.opcode = m_add;
        add.l = accum;
        add.l.size = size;
        add.r = terms[i];
        add.r.size = size;
        add.d.size = size;
        mop_t next;
        next.create_from_insn(&add);
        next.size = size;
        accum = next;
    }

    ins->opcode = m_add;
    ins->l = accum;
    ins->l.size = size;
    ins->r = terms.back();
    ins->r.size = size;
    ins->d = dst;
    ins->ea = ea;
    return true;
}

static int try_affine_bv_simplify(minsn_t *ins)
{
    if ( !mba_affine_enabled() || !ins || ins->opcode == m_mov )
        return 0;

    const int size = ins->d.size;
    if ( size <= 0 || size > 4 )
    {
        mba_affine_debug("[MBA affine] skip size=%d op=%d ea=%llx\n",
                         size, ins->opcode, (unsigned long long)ins->ea);
        return 0;
    }
    int op_count = mba_expr_op_count(ins);
    if ( !mba_is_small_affine_candidate(ins, op_count) || op_count > 256 )
    {
        mba_affine_debug("[MBA affine] skip op_count=%d op=%d ea=%llx\n",
                         op_count, ins->opcode, (unsigned long long)ins->ea);
        return 0;
    }
    if ( !mba_pure_insn(ins) )
    {
        mba_affine_debug("[MBA affine] skip impure op=%d ea=%llx\n",
                         ins->opcode, (unsigned long long)ins->ea);
        return 0;
    }

    std::vector<mop_t> vars;
    mba_collect_vars(ins, &vars);
    if ( vars.empty() || vars.size() > 4 )
    {
        mba_affine_debug("[MBA affine] skip vars=%zu op=%d ea=%llx\n",
                         vars.size(), ins->opcode, (unsigned long long)ins->ea);
        return 0;
    }

    for ( const mop_t &v : vars )
    {
        if ( v.size != size )
        {
            mba_affine_debug("[MBA affine] skip var size=%d expr size=%d op=%d ea=%llx\n",
                             v.size, size, ins->opcode, (unsigned long long)ins->ea);
            return 0;
        }
    }

    try
    {
        z3_solver::z3_context_t zctx;
        zctx.set_timeout(500);
        z3_solver::mcode_translator_t translator(zctx);
        z3::expr expr = translator.translate_insn(ins);
        int bits = size * 8;
        if ( (int)expr.get_sort().bv_size() != bits )
        {
            mba_affine_debug("[MBA affine] skip expr bits=%u wanted=%d op=%d ea=%llx\n",
                             expr.get_sort().bv_size(), bits, ins->opcode, (unsigned long long)ins->ea);
            return 0;
        }

        std::vector<z3::expr> zvars;
        zvars.reserve(vars.size());
        for ( const mop_t &v : vars )
        {
            z3::expr zv = translator.translate_operand(v, size);
            if ( (int)zv.get_sort().bv_size() != bits )
            {
                mba_affine_debug("[MBA affine] skip var bits=%u wanted=%d op=%d ea=%llx\n",
                                 zv.get_sort().bv_size(), bits, ins->opcode, (unsigned long long)ins->ea);
                return 0;
            }
            zvars.push_back(zv);
        }

        uint64_t mask = mba_mask_for_size(size);
        uint64_t at_zero = 0;
        if ( !z3_eval_with_model(zctx, expr, zvars, vars.size(), 0, &at_zero) )
        {
            mba_affine_debug("[MBA affine] skip eval zero op=%d ea=%llx\n",
                             ins->opcode, (unsigned long long)ins->ea);
            return 0;
        }
        at_zero &= mask;

        std::vector<uint64_t> coeffs(vars.size(), 0);
        for ( size_t i = 0; i < vars.size(); ++i )
        {
            uint64_t at_one = 0;
            if ( !z3_eval_with_model(zctx, expr, zvars, i, 1, &at_one) )
            {
                mba_affine_debug("[MBA affine] skip eval coeff[%zu] op=%d ea=%llx\n",
                                 i, ins->opcode, (unsigned long long)ins->ea);
                return 0;
            }
            coeffs[i] = (at_one - at_zero) & mask;

            // Keep this pass for readable affine reductions. Large modular
            // coefficients are sound, but usually not a deobfuscation win.
            if ( !mba_is_readable_modular_value(coeffs[i], mask) )
            {
                mba_affine_debug("[MBA affine] skip coeff[%zu]=0x%llx op=%d ea=%llx\n",
                                 i, (unsigned long long)coeffs[i], ins->opcode, (unsigned long long)ins->ea);
                return 0;
            }
        }
        if ( !mba_is_readable_modular_value(at_zero, mask) )
        {
            mba_affine_debug("[MBA affine] skip constant=0x%llx op=%d ea=%llx\n",
                             (unsigned long long)at_zero, ins->opcode, (unsigned long long)ins->ea);
            return 0;
        }

        z3::expr cand = zctx.ctx().bv_val(at_zero, bits);
        for ( size_t i = 0; i < zvars.size(); ++i )
        {
            if ( coeffs[i] == 0 )
                continue;
            cand = cand + (zctx.ctx().bv_val(coeffs[i], bits) * zvars[i]);
        }

        if ( !chernobog::z3_utils::prove_bv_equivalent(expr, cand, 500) )
        {
            mba_affine_debug("[MBA affine] skip proof vars=%zu ops=%d op=%d ea=%llx\n",
                             vars.size(), op_count, ins->opcode, (unsigned long long)ins->ea);
            return 0;
        }

        size_t term_count = at_zero != 0 ? 1 : 0;
        size_t reconstructed_ops = 0;
        for ( uint64_t coeff : coeffs )
        {
            if ( coeff == 0 )
                continue;
            ++term_count;
            if ( coeff != 1 )
                ++reconstructed_ops;
        }
        reconstructed_ops += term_count > 1 ? term_count - 1 : 1;
        if ( reconstructed_ops >= static_cast<size_t>(op_count) )
        {
            mba_affine_debug("[MBA affine] skip non-reducing rewrite old=%d new=%zu ea=%llx\n",
                             op_count, reconstructed_ops,
                             (unsigned long long)ins->ea);
            return 0;
        }

        bool rewritten = rewrite_as_affine(ins, vars, coeffs, at_zero);
        mba_affine_debug("[MBA affine] %s vars=%zu ops=%d op=%d ea=%llx\n",
                         rewritten ? "rewrote" : "rewrite failed",
                         vars.size(), op_count, ins->opcode, (unsigned long long)ins->ea);
        return rewritten ? 1 : 0;
    }
    catch ( ... )
    {
        mba_affine_debug("[MBA affine] skip exception op=%d ea=%llx\n",
                         ins->opcode, (unsigned long long)ins->ea);
        return 0;
    }
}

} // namespace


//--------------------------------------------------------------------------
// Initialization
//--------------------------------------------------------------------------
void mba_simplify_handler_t::initialize() {
    if ( initialized_ ) {
        return;
    }

    // Initialize the rule registry (builds pattern index)
    try {
        RuleRegistry::instance().initialize();
    } catch (...) {
        msg("[chernobog] ERROR: Exception during rule registry initialization\n");
        return;
    }

    initialized_ = true;
    msg("[chernobog] MBA simplify handler initialized\n");
}

bool mba_simplify_handler_t::is_initialized() {
    return initialized_;
}

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool mba_simplify_handler_t::detect(mbl_array_t *mba) {
    if ( !mba ) {
        return false;
    }

    // Ensure initialized
    if ( !initialized_ ) {
        initialize();
    }

    // Look for complex arithmetic/logic patterns
    int complex_count = 0;
    const int THRESHOLD = 3;  // Need at least 3 complex patterns

    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk) continue;

        for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
            // Look for nested operations (sign of obfuscation)
            if ( !is_mba_opcode(ins->opcode) ) {
                continue;
            }

            // Check if operands contain nested operations
            bool has_nested = false;

            if ( ins->l.t == mop_d && ins->l.d ) {
                if ( is_mba_opcode(ins->l.d->opcode) ) {
                    has_nested = true;
                }
            }

            if ( ins->r.t == mop_d && ins->r.d ) {
                if ( is_mba_opcode(ins->r.d->opcode) ) {
                    has_nested = true;
                }
            }

            if ( has_nested ) {
                complex_count++;
                if ( complex_count >= THRESHOLD ) {
                    return true;
                }
            }
        }
    }

    return complex_count > 0;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int mba_simplify_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if ( !mba || !ctx ) {
        return 0;
    }

    if ( !initialized_ ) {
        initialize();
    }

    int total_changes = 0;
    int pass = 0;
    int pass_changes = 0;
    const int MAX_PASSES = 10;

    // Multi-pass simplification (simplifications may enable more simplifications)
    do {
        pass_changes = 0;
        pass++;

        for ( int i = 0; i < mba->qty; ++i ) {
            mblock_t *blk = mba->get_mblock(i);
            if ( !blk) continue;

            for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
                int changes = try_simplify_instruction(blk, ins);
                pass_changes += changes;
            }
        }

        total_changes += pass_changes;

        if ( pass_changes > 0 ) {
            // Verify after changes
            mba->verify(false);
        }

    } while ( pass < MAX_PASSES && pass_changes > 0 );

    if ( total_changes > 0 ) {
        ctx->expressions_simplified += total_changes;
        deobf::log_verbose("[MBA] Simplified %d expressions\n", total_changes);
    }

    return total_changes;
}

//--------------------------------------------------------------------------
// Instruction-level simplification
//--------------------------------------------------------------------------
int mba_simplify_handler_t::simplify_insn(mblock_t *blk, minsn_t *ins, deobf_ctx_t *ctx) {
    // Early null check before anything else
    if ( !blk || !ins ) {
        return 0;
    }

    // Only try to simplify if registry is initialized
    if ( !initialized_ ) {
        // Don't initialize here - do it at plugin init time
        return 0;
    }

    int changes = try_simplify_instruction(blk, ins);

    if ( changes > 0 && ctx ) {
        ctx->expressions_simplified += changes;
    }

    return changes;
}

//--------------------------------------------------------------------------
// Internal simplification
//--------------------------------------------------------------------------
int mba_simplify_handler_t::try_simplify_instruction(mblock_t *blk, minsn_t *ins) {
    if ( !ins || ins->is_fpinsn() || !is_mba_opcode(ins->opcode) ) {
        return 0;
    }

    // Ensure initialized
    if ( !initialized_ ) {
        initialize();
    }

    int changes =
        chernobog::chain::chain_simplify_handler_t::simplify_insn(blk, ins, nullptr);
    if ( changes > 0 )
    {
        blk->mark_lists_dirty();
        total_simplified_ += static_cast<size_t>(changes);
    }

    if ( !is_mba_opcode(ins->opcode) )
        return changes;

    const int affine_changes = try_affine_bv_simplify(ins);
    if ( affine_changes > 0 )
    {
        blk->mark_lists_dirty();
        total_simplified_ += static_cast<size_t>(affine_changes);
        return changes + affine_changes;
    }

    // Try to find a matching rule
    auto match = RuleRegistry::instance().find_match(ins);
    if ( !match.rule ) {
        return changes;
    }

    // Apply the matched rule
    return changes + apply_match(blk, ins, match);
}

int mba_simplify_handler_t::apply_match(mblock_t *blk, minsn_t *ins,
                                        const RuleRegistry::MatchResult &match)
                                        {
    if ( !match.rule ) {
        return 0;
    }

    // Apply the replacement
    minsn_t *replacement = match.rule->apply_replacement(match.bindings, blk, ins);

    if ( !replacement ) {
        return 0;
    }

    // Save original properties
    ea_t orig_ea = ins->ea;
    mop_t orig_dest = ins->d;

    // Copy replacement instruction fields
    ins->opcode = replacement->opcode;
    ins->l.swap(replacement->l);  // Use swap for proper mop_t handling
    ins->r.swap(replacement->r);

    // Restore original ea and destination
    ins->ea = orig_ea;
    ins->d = orig_dest;

    // Ensure operand sizes match destination
    if ( ins->l.size == 0 && orig_dest.size > 0 ) {
        ins->l.size = orig_dest.size;
    }
    if ( ins->r.size == 0 && orig_dest.size > 0 && ins->r.t != mop_z ) {
        ins->r.size = orig_dest.size;
    }

    delete replacement;

    blk->mark_lists_dirty();

    total_simplified_++;

    return 1;
}

//--------------------------------------------------------------------------
// Statistics
//--------------------------------------------------------------------------
void mba_simplify_handler_t::reset_statistics() {
    total_simplified_ = 0;
    RuleRegistry::instance().clear_statistics();
}

void mba_simplify_handler_t::dump_statistics() {
    msg("[chernobog] MBA Simplify Statistics:\n");
    msg("  Total simplifications: %zu\n", total_simplified_);

    RuleRegistry::instance().dump();
}
