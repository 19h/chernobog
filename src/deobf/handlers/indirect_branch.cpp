#include "indirect_branch.h"

#include "../analysis/opaque_eval.h"

#include <unordered_map>

namespace {

//--------------------------------------------------------------------------
// Replace every old CFG successor and install the single direct successor.
//--------------------------------------------------------------------------
void replace_cfg_successors(mbl_array_t *mba, mblock_t *src, int target_idx)
{
    for ( int old_idx : src->succset ) {
        if ( old_idx < 0 || old_idx >= mba->qty || old_idx == target_idx )
            continue;

        mblock_t *old_dst = mba->get_mblock(old_idx);
        if ( !old_dst )
            continue;

        auto pred = std::find(old_dst->predset.begin(), old_dst->predset.end(),
                              src->serial);
        if ( pred != old_dst->predset.end() )
            old_dst->predset.erase(pred);
        old_dst->mark_lists_dirty();
    }

    src->succset.clear();
    src->succset.push_back(target_idx);

    mblock_t *dst = mba->get_mblock(target_idx);
    auto pred = std::find(dst->predset.begin(), dst->predset.end(), src->serial);
    if ( pred == dst->predset.end() )
        dst->predset.push_back(src->serial);

    src->mark_lists_dirty();
    dst->mark_lists_dirty();
}

//--------------------------------------------------------------------------
// Resolve the actual m_ijmp offset operand.  A target merely contained in a
// block is insufficient: m_goto transfers to the block start, so accepting an
// interior address would change program semantics.
//--------------------------------------------------------------------------
int resolve_ijmp(
    mbl_array_t *mba,
    mblock_t *src,
    deobf_ctx_t *ctx,
    const std::unordered_map<ea_t, int> &block_starts)
{
    minsn_t *ijmp = src->tail;
    if ( !ijmp || ijmp->opcode != m_ijmp || ijmp->d.empty() )
        return 0;

    // In a selector/offset instruction, a global operand is address-used: its
    // EA is the offset. In nested value expressions, mop_v instead denotes the
    // global's contents and is handled by the immutable evaluator.
    const std::optional<uint64_t> value = ijmp->d.t == mop_v
        ? std::optional<uint64_t>(ijmp->d.g)
        : opaque_eval_t::evaluate_operand(ijmp->d);
    if ( !value )
        return 0;

    const ea_t target_ea = static_cast<ea_t>(*value);
    const auto target = block_starts.find(target_ea);
    const int target_idx = target == block_starts.end() ? -1 : target->second;

    if ( target_idx < 0 ) {
        deobf::log_verbose(
            "[indirect_branch] Exact target %a is not a unique microblock start\n",
            target_ea);
        return 0;
    }

    deobf::log("[indirect_branch] Converting block %d ijmp to goto block %d "
               "(target %a)\n",
               src->serial, target_idx, target_ea);

    ijmp->opcode = m_goto;
    ijmp->l.make_blkref(target_idx);
    ijmp->r.erase();
    ijmp->d.erase();

    replace_cfg_successors(mba, src, target_idx);
    src->type = BLT_1WAY;
    ++ctx->branches_simplified;
    return 1;
}

} // namespace

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool indirect_branch_handler_t::detect(mbl_array_t *mba)
{
    if ( !mba )
        return false;

    for ( int i = 0; i < mba->qty; ++i ) {
        const mblock_t *blk = mba->get_mblock(i);
        if ( blk && blk->tail && blk->tail->opcode == m_ijmp )
            return true;
    }
    return false;
}

//--------------------------------------------------------------------------
// Main pass
//--------------------------------------------------------------------------
int indirect_branch_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx )
        return 0;

    // Index exact microblock starts once. Resolution is therefore expected
    // O(B + J) for B blocks and J indirect jumps, with O(B) auxiliary space.
    std::unordered_map<ea_t, int> block_starts;
    block_starts.reserve(static_cast<size_t>(mba->qty));
    for ( int i = 0; i < mba->qty; ++i ) {
        const mblock_t *blk = mba->get_mblock(i);
        if ( blk ) {
            auto [entry, inserted] = block_starts.emplace(blk->start, i);
            if ( !inserted )
                entry->second = -1;
        }
    }

    int changes = 0;
    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( blk && blk->tail && blk->tail->opcode == m_ijmp )
            changes += resolve_ijmp(mba, blk, ctx, block_starts);
    }

    deobf::log("[indirect_branch] Resolved %d exact indirect branches\n",
               changes);
    return changes;
}
