#include "bogus_cf.h"
#include "../analysis/pattern_match.h"
#include "../analysis/opaque_eval.h"
#include <functional>
#include <optional>

namespace {

bool is_constant_tree(const mop_t &op)
{
    if ( op.t == mop_n || op.t == mop_z )
        return true;
    return op.t == mop_d && op.d != nullptr
        && is_constant_tree(op.d->l)
        && is_constant_tree(op.d->r);
}

bool is_add_one_of(const mop_t &candidate, const mop_t &value)
{
    if ( candidate.t != mop_d || candidate.d == nullptr
      || candidate.d->opcode != m_add )
        return false;

    const minsn_t *add = candidate.d;
    const auto equal_width_value = [&value](const mop_t& operand) {
        return operand.size > 0 && operand.size == value.size &&
               operand.equal_mops(value, EQ_IGNSIZE);
    };
    return (equal_width_value(add->l)
         && add->r.t == mop_n && add->r.nnn && add->r.nnn->value == 1)
        || (equal_width_value(add->r)
         && add->l.t == mop_n && add->l.nnn && add->l.nnn->value == 1);
}

bool is_even_consecutive_product(const mop_t &candidate)
{
    if ( candidate.t != mop_d || candidate.d == nullptr )
        return false;

    const minsn_t *mod = candidate.d;
    if ( (mod->opcode != m_smod && mod->opcode != m_umod)
      || mod->r.t != mop_n || !mod->r.nnn || mod->r.nnn->value != 2
      || mod->l.t != mop_d || mod->l.d == nullptr
      || mod->l.d->opcode != m_mul )
        return false;

    const minsn_t *mul = mod->l.d;
    return is_add_one_of(mul->l, mul->r) || is_add_one_of(mul->r, mul->l);
}

void replace_successors(mblock_t *blk, int new_target)
{
    if ( blk == nullptr || blk->mba == nullptr )
        return;

    for ( int old_target : blk->succset ) {
        if ( old_target < 0 || old_target >= blk->mba->qty || old_target == new_target )
            continue;
        mblock_t *old_dst = blk->mba->get_mblock(old_target);
        if ( old_dst != nullptr ) {
            auto pred = std::find(old_dst->predset.begin(), old_dst->predset.end(), blk->serial);
            if ( pred != old_dst->predset.end() )
                old_dst->predset.erase(pred);
            old_dst->mark_lists_dirty();
        }
    }

    blk->succset.clear();
    if ( new_target >= 0 && new_target < blk->mba->qty ) {
        blk->succset.push_back(new_target);
        mblock_t *new_dst = blk->mba->get_mblock(new_target);
        if ( new_dst != nullptr
          && std::find(new_dst->predset.begin(), new_dst->predset.end(), blk->serial)
             == new_dst->predset.end() ) {
            new_dst->predset.push_back(blk->serial);
            new_dst->mark_lists_dirty();
        }
    }
    blk->mark_lists_dirty();
}

std::optional<int> find_not_taken_successor(const mblock_t *blk,
                                            int taken_target)
{
    if ( !blk || taken_target < 0 )
        return std::nullopt;

    std::optional<int> candidate;
    bool saw_taken = false;
    for ( int successor : blk->succset ) {
        if ( successor == taken_target ) {
            saw_taken = true;
            continue;
        }
        if ( candidate && *candidate != successor )
            return std::nullopt;
        candidate = successor;
    }

    if ( candidate )
        return candidate;
    // Both conditional edges may coalesce into the immediately following
    // block, leaving one unique successor in the set.
    if ( saw_taken && taken_target == blk->serial + 1 )
        return taken_target;
    return std::nullopt;
}

} // namespace

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool bogus_cf_handler_t::detect(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba ) 
        return false;

    // Look for opaque predicates
    for ( int i = 0; i < mba->qty; ++i ) 
    {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk || !blk->tail ) 
            continue;

        if ( deobf::is_jcc(blk->tail->opcode) ) 
        {
            bool is_true;
            if ( is_opaque_predicate(blk->tail, &is_true) ) 
            {
                return true;
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int bogus_cf_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx ) 
        return 0;

    deobf::log("[bogus_cf] Starting bogus control flow removal\n");

    int total_changes = 0;

    // Find all opaque predicates
    auto opaques = find_opaque_predicates(mba, ctx);
    deobf::log("[bogus_cf] Found %zu opaque predicates\n", opaques.size());

    // Remove dead branches (replace conditional with unconditional)
    total_changes += remove_dead_branches(mba, opaques);

    deobf::log("[bogus_cf] Bogus CF removal complete, %d changes\n", total_changes);
    return total_changes;
}

//--------------------------------------------------------------------------
// Find all opaque predicates
//--------------------------------------------------------------------------
std::vector<bogus_cf_handler_t::opaque_info_t> bogus_cf_handler_t::find_opaque_predicates(
    mbl_array_t *mba, deobf_ctx_t *ctx)
{
    std::vector<opaque_info_t> result;

    for ( int i = 0; i < mba->qty; ++i ) 
    {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk || !blk->tail ) 
            continue;

        minsn_t *tail = blk->tail;
        if ( !deobf::is_jcc(tail->opcode) ) 
            continue;

        bool is_true;
        if ( is_opaque_predicate(tail, &is_true) ) 
        {
            // Only block-target jumps can be rewritten as CFG edges here.
            if ( tail->d.t != mop_b )
                continue;

            opaque_info_t info;
            info.block_idx = i;
            info.cond_insn = tail;
            info.always_true = is_true;

            const int taken_target = tail->d.b;
            const auto fallthrough = find_not_taken_successor(blk, taken_target);
            if ( taken_target < 0 || taken_target >= mba->qty || !fallthrough )
                continue;

            // is_true means that the jX relation itself is true, i.e. the
            // conditional branch is taken, for every conditional opcode.
            info.live_target = is_true ? taken_target : *fallthrough;
            info.dead_target = is_true ? *fallthrough : taken_target;

            result.push_back(info);
            deobf::log_verbose("[bogus_cf] Opaque predicate in block %d: always %s\n",
                              i, is_true ? "true" : "false");
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Check if condition is opaque
//--------------------------------------------------------------------------
bool bogus_cf_handler_t::is_opaque_predicate(minsn_t *cond, bool *is_true)
{
    if ( !cond || !is_true || !is_mcode_jcond(cond->opcode) || cond->is_fpinsn() )
        return false;

    // Try different opaque patterns (fast path first)

    if ( check_const_comparison(cond, is_true) ) 
        return true;

    if ( check_math_identity(cond, is_true) ) 
        return true;

    if ( check_global_var_pattern(cond, is_true) ) 
        return true;

    // Use Z3-based analysis for complex predicates
    auto z3_result = opaque_eval_t::check_opaque_predicate(cond);
    switch ( z3_result ) {
        case opaque_eval_t::OPAQUE_ALWAYS_TRUE:
            *is_true = true;
            deobf::log_verbose("[bogus_cf] Z3 determined predicate is always true\n");
            return true;
        case opaque_eval_t::OPAQUE_ALWAYS_FALSE:
            *is_true = false;
            deobf::log_verbose("[bogus_cf] Z3 determined predicate is always false\n");
            return true;
        default:
            break;
    }

    return false;
}

//--------------------------------------------------------------------------
// Check constant comparison (e.g., 1 == 1, 5 < 10)
//--------------------------------------------------------------------------
bool bogus_cf_handler_t::check_const_comparison(minsn_t *insn, bool *result)
{
    if ( !insn || !result || !is_mcode_jcond(insn->opcode) )
        return false;
    if ( !is_constant_tree(insn->l)
      || (insn->opcode != m_jcnd && !is_constant_tree(insn->r)) )
        return false;
    return opaque_eval_t::evaluate_condition(insn, result);
}

//--------------------------------------------------------------------------
// Check math identity pattern: x * (x + 1) % 2 == 0
// This is always true because consecutive integers have opposite parity
//--------------------------------------------------------------------------
bool bogus_cf_handler_t::check_math_identity(minsn_t *insn, bool *result)
{
    if ( !insn || !result || (insn->opcode != m_jz && insn->opcode != m_jnz)
      || insn->r.t != mop_n || !insn->r.nnn )
        return false;

    // Direct form: jz/jnz ((x * (x + 1)) % 2), C.
    if ( is_even_consecutive_product(insn->l) ) {
        const bool equal = insn->r.nnn->value == 0;
        *result = insn->opcode == m_jz ? equal : !equal;
        return true;
    }

    // Nested form: jz/jnz setz(((x * (x + 1)) % 2), 0), C.
    if ( insn->l.t != mop_d || insn->l.d == nullptr
      || insn->l.d->opcode != m_setz
      || insn->l.d->r.t != mop_n || !insn->l.d->r.nnn
      || insn->l.d->r.nnn->value != 0
      || !is_even_consecutive_product(insn->l.d->l) )
        return false;

    const bool equal = insn->r.nnn->value == 1;
    *result = insn->opcode == m_jz ? equal : !equal;
    return true;
}

//--------------------------------------------------------------------------
// Check global variable pattern (Hikari uses LHSGV/RHSGV)
// This handles complex expressions using global constants like:
//   ((~((~(~dword_Y | ~dword_X) | v2 ^ (v1 | ~dword_X & mask)) + C) & M1) * ...) / D < threshold
//--------------------------------------------------------------------------
bool bogus_cf_handler_t::check_global_var_pattern(minsn_t *insn, bool *result)
{
    if ( !insn ) 
        return false;

    // Use the opaque evaluator to try to evaluate the full expression
    // It will read globals from the binary and compute the result

    // First, check if this expression involves any global variables
    bool has_global = false;
    std::function<void(const mop_t &)> check_op = [&](const mop_t &op)
    {
        if ( op.t == mop_v ) {
            has_global = true;
        } else if ( op.t == mop_d && op.d ) {
            check_op(op.d->l);
            check_op(op.d->r);
        }
    };

    check_op(insn->l);
    check_op(insn->r);

    if ( !has_global ) 
        return false;

    // Try to evaluate the condition
    bool eval_result;
    if ( opaque_eval_t::evaluate_condition(insn, &eval_result) ) {
        *result = eval_result;
        deobf::log_verbose("[bogus_cf] Evaluated global pattern: always %s\n",
                          eval_result ? "true" : "false");
        return true;
    }

    // No partial-expression fallback: a branch may be removed only when the
    // complete jX relation, including both operands, is constant.
    return false;
}

//--------------------------------------------------------------------------
// Remove dead branches
//--------------------------------------------------------------------------
int bogus_cf_handler_t::remove_dead_branches(mbl_array_t *mba,
    const std::vector<opaque_info_t> &opaques)
    {

    int changes = 0;

    for ( const auto &op : opaques ) {
        mblock_t *blk = mba->get_mblock(op.block_idx);
        if ( !blk || !blk->tail ) 
            continue;

        minsn_t *tail = blk->tail;

        if ( op.live_target < 0 || op.live_target >= mba->qty )
            continue;

        tail->opcode = m_goto;
        tail->l.make_blkref(op.live_target);
        tail->r.erase();
        tail->d.erase();
        blk->type = BLT_1WAY;
        replace_successors(blk, op.live_target);

        changes++;
        deobf::log_verbose("[bogus_cf] Replaced opaque branch in block %d with goto blk%d\n",
                          op.block_idx, op.live_target);
    }

    return changes;
}
