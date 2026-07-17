#include "select_chain.h"

namespace
{

constexpr size_t kMinimumChainLength = 8;
constexpr size_t kMinimumFunctionDiamonds = 64;

struct select_diamond_t
{
    int parent = -1;
    int assignment = -1;
    int join = -1;
    bool assignment_on_jump = false;
};

bool is_standard_width(int size)
{
    return size == 1 || size == 2 || size == 4 || size == 8;
}

bool is_boolean_condition(const mop_t &condition)
{
    if ( condition.size != 1 )
        return false;
    if ( condition.t == mop_r )
        return mop_t::is_bit_reg(condition.r);
    return condition.t == mop_d && condition.d
        && (condition.d->opcode == m_lnot
         || is_mcode_set(condition.d->opcode));
}

bool is_supported_assignment(const minsn_t *ins)
{
    if ( !ins || ins->d.t != mop_r || !is_standard_width(ins->d.size) )
        return false;

    if ( ins->opcode == m_mov )
        return ins->l.t == mop_r && ins->l.size == ins->d.size;

    // A 32-bit x86 cmov defines the full 64-bit micro-register by zeroing its
    // upper half.  Hex-Rays represents that conditional payload as xdu.  Keep
    // the conversion nested so the branchless candidate has the exact value
    // and width of the original assignment.
    return ins->opcode == m_xdu && ins->l.t == mop_r
        && is_standard_width(ins->l.size) && ins->l.size < ins->d.size;
}

// Match one exact conditional-move diamond:
//
//       parent
//       /    \
// assignment |       assignment contains one register-to-register mov
//       \    /
//        join
//
// Assertions are artificial optimizer facts and do not represent executed
// writes.  Requiring a fake, single-predecessor assignment block excludes
// ordinary source-level if statements and blocks with observable side effects.
bool match_diamond(mbl_array_t *mba, int parent_idx, select_diamond_t *out)
{
    if ( !mba || parent_idx < 0 || parent_idx >= mba->qty )
        return false;

    mblock_t *parent = mba->get_mblock(parent_idx);
    if ( !parent || parent->type != BLT_2WAY || parent->nsucc() != 2 )
        return false;

    minsn_t *jcc = parent->tail;
    if ( !jcc
      || (jcc->opcode != m_jcnd
       && !is_mcode_convertible_to_set(jcc->opcode))
      || jcc->is_fpinsn() || jcc->d.t != mop_b )
        return false;
    // jcnd tests nonzero, whereas the arithmetic mask below requires exactly
    // 0 or 1. Accept only microcode operands whose opcode/register class
    // guarantees that range.
    if ( jcc->opcode == m_jcnd && !is_boolean_condition(jcc->l) )
        return false;

    const int jump_target = jcc->d.b;
    for ( int side = 0; side < 2; ++side )
    {
        const int assignment_idx = parent->succ(side);
        const int join_idx = parent->succ(1 - side);
        if ( assignment_idx < 0 || assignment_idx >= mba->qty
          || join_idx < 0 || join_idx >= mba->qty
          || assignment_idx == join_idx )
            continue;

        mblock_t *assignment = mba->get_mblock(assignment_idx);
        if ( !assignment || (assignment->flags & MBL_FAKE) == 0
          || assignment->npred() != 1 || assignment->pred(0) != parent_idx
          || assignment->nsucc() != 1 || assignment->succ(0) != join_idx )
            continue;

        if ( jump_target != assignment_idx && jump_target != join_idx )
            continue;

        minsn_t *move = nullptr;
        bool invalid = false;
        for ( minsn_t *ins = assignment->head; ins; ins = ins->next )
        {
            if ( ins->is_assert() || ins->opcode == m_nop )
                continue;
            if ( move != nullptr )
            {
                invalid = true;
                break;
            }
            move = ins;
        }

        if ( invalid || !is_supported_assignment(move) )
            continue;

        if ( out )
        {
            out->parent = parent_idx;
            out->assignment = assignment_idx;
            out->join = join_idx;
            out->assignment_on_jump = jump_target == assignment_idx;
        }
        return true;
    }

    return false;
}

std::vector<std::vector<int>> find_long_chains(mbl_array_t *mba)
{
    std::vector<std::vector<int>> result;
    if ( !mba || mba->qty <= 0 )
        return result;

    // Dense select-lowered functions can interleave short cmov clusters with
    // genuine branches.  Once the independently exact diamonds reach a high
    // function-level threshold, collapsing all of them is structurally useful
    // without weakening the per-diamond semantic checks.
    std::vector<int> all_diamonds;
    all_diamonds.reserve(static_cast<size_t>(mba->qty) / 2);
    for ( int i = 0; i < mba->qty; ++i )
    {
        if ( match_diamond(mba, i, nullptr) )
            all_diamonds.push_back(i);
    }
    if ( all_diamonds.size() >= kMinimumFunctionDiamonds )
    {
        result.push_back(std::move(all_diamonds));
        return result;
    }

    std::vector<bool> visited(static_cast<size_t>(mba->qty), false);
    for ( int start = 0; start < mba->qty; ++start )
    {
        if ( visited[static_cast<size_t>(start)] )
            continue;

        std::vector<int> chain;
        int current = start;
        while ( current >= 0 && current < mba->qty
             && !visited[static_cast<size_t>(current)] )
        {
            select_diamond_t diamond;
            if ( !match_diamond(mba, current, &diamond) )
                break;

            visited[static_cast<size_t>(current)] = true;
            chain.push_back(current);
            current = diamond.join;
        }

        if ( chain.size() >= kMinimumChainLength )
            result.push_back(std::move(chain));
    }
    return result;
}

mop_t make_nested_unary(ea_t ea, mcode_t opcode, const mop_t &operand,
                        int result_size)
{
    minsn_t expression(ea);
    expression.opcode = opcode;
    expression.l = operand;
    expression.d.size = result_size;
    mop_t result;
    result.create_from_insn(&expression);
    return result;
}

mop_t make_nested_binary(ea_t ea, mcode_t opcode, const mop_t &left,
                         const mop_t &right, int result_size)
{
    minsn_t expression(ea);
    expression.opcode = opcode;
    expression.l = left;
    expression.r = right;
    expression.d.size = result_size;
    mop_t result;
    result.create_from_insn(&expression);
    return result;
}

void replace_successors(mbl_array_t *mba, mblock_t *parent, int join_idx)
{
    for ( int old_idx : parent->succset )
    {
        if ( old_idx < 0 || old_idx >= mba->qty || old_idx == join_idx )
            continue;
        mblock_t *old_dst = mba->get_mblock(old_idx);
        auto pred = std::find(old_dst->predset.begin(), old_dst->predset.end(),
                              parent->serial);
        if ( pred != old_dst->predset.end() )
            old_dst->predset.erase(pred);
        old_dst->mark_lists_dirty();
    }

    parent->succset.clear();
    parent->succset.push_back(join_idx);
    mblock_t *join = mba->get_mblock(join_idx);
    if ( std::find(join->predset.begin(), join->predset.end(), parent->serial)
         == join->predset.end() )
        join->predset.push_back(parent->serial);
    parent->mark_lists_dirty();
    join->mark_lists_dirty();
}

bool collapse_diamond(mbl_array_t *mba, const select_diamond_t &diamond)
{
    mblock_t *parent = mba->get_mblock(diamond.parent);
    mblock_t *assignment = mba->get_mblock(diamond.assignment);
    minsn_t *jcc = parent ? parent->tail : nullptr;
    if ( !parent || !assignment || !jcc )
        return false;

    minsn_t *move = nullptr;
    for ( minsn_t *ins = assignment->head; ins; ins = ins->next )
    {
        if ( !ins->is_assert() && ins->opcode != m_nop )
        {
            if ( move != nullptr )
                return false;
            move = ins;
        }
    }
    if ( !move )
        return false;

    const int size = move->d.size;
    const ea_t ea = jcc->ea;
    mop_t condition_value;
    if ( jcc->opcode == m_jcnd )
    {
        condition_value = jcc->l;
        if ( !diamond.assignment_on_jump )
            condition_value = make_nested_unary(ea, m_lnot,
                                                  condition_value, 1);
    }
    else
    {
        mcode_t condition_opcode = jcnd2set(jcc->opcode);
        if ( !diamond.assignment_on_jump )
            condition_opcode = negate_mcode_relation(condition_opcode);

        minsn_t condition(ea);
        condition.opcode = condition_opcode;
        condition.l = jcc->l;
        condition.r = jcc->r;
        condition.d.size = 1;
        condition_value.create_from_insn(&condition);
    }

    if ( size != 1 )
        condition_value = make_nested_unary(ea, m_xdu, condition_value, size);
    mop_t mask = make_nested_unary(ea, m_neg, condition_value, size);
    mop_t candidate;
    if ( move->opcode == m_xdu )
        candidate.create_from_insn(move);
    else
        candidate = move->l;
    mop_t delta = make_nested_binary(ea, m_xor, move->d, candidate, size);
    mop_t selected_delta = make_nested_binary(ea, m_and, delta, mask, size);

    // For c in {0,1}, mask=-c is either 0 or 2^w-1. Therefore:
    // d ^ ((d ^ x) & -c) == c ? x : d, modulo 2^w.
    minsn_t *replacement = new minsn_t(ea);
    replacement->opcode = m_xor;
    replacement->l = move->d;
    replacement->r = selected_delta;
    replacement->d = move->d;
    parent->insert_into_block(replacement, jcc->prev);

    // The assignment block still occupies the next natural serial until the
    // unreachable-block cleanup below.  Retain an explicit terminator so the
    // parent transfers to its nonadjacent join in every intermediate CFG.
    jcc->opcode = m_goto;
    jcc->l.make_blkref(diamond.join);
    jcc->r.erase();
    jcc->d.erase();

    parent->type = BLT_1WAY;
    replace_successors(mba, parent, diamond.join);
    return true;
}

} // namespace

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool select_chain_handler_t::detect(mbl_array_t *mba)
{
    return !find_long_chains(mba).empty();
}

//--------------------------------------------------------------------------
// Transformation
//--------------------------------------------------------------------------
int select_chain_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx || mba->has_bad_sp() || mba->bad_call_sp_detected() )
        return 0;

    const std::vector<std::vector<int>> chains = find_long_chains(mba);
    if ( chains.empty() )
        return 0;

    int collapsed = 0;
    for ( const std::vector<int> &chain : chains )
    {
        for ( int parent_idx : chain )
        {
            select_diamond_t diamond;
            if ( match_diamond(mba, parent_idx, &diamond)
              && collapse_diamond(mba, diamond) )
                ++collapsed;
        }
    }

    if ( collapsed == 0 )
        return 0;

    mba->mark_chains_dirty();
    const int blocks_before = mba->qty;
    mba->remove_empty_and_unreachable_blocks();
    const int blocks_removed = std::max(0, blocks_before - mba->qty);
    mba->mark_chains_dirty();
    mba->verify(true);

    ctx->branches_simplified += collapsed;
    ctx->expressions_simplified += collapsed;
    ctx->blocks_merged += blocks_removed;
    deobf::log("[select_chain] Collapsed %d select diamonds in %zu chains; "
               "removed %d blocks\n",
               collapsed, chains.size(), blocks_removed);
    return collapsed;
}
