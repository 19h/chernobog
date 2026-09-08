#include "block_merge.h"

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool block_merge_handler_t::detect_split_blocks(mbl_array_t *mba)
{
    if ( !mba || mba->qty <= 0 )
        return false;

    // CFG rewriting is unsafe when Hex-Rays has already observed inconsistent
    // stack-pointer state. Such functions can naturally produce long runs of
    // tiny goto blocks, but those runs are not evidence of block splitting.
    if ( mba->has_bad_sp() || mba->bad_call_sp_detected() )
        return false;

    // Classify candidate blocks first, then follow real successor edges. The
    // old detector accumulated a "chain" while iterating blocks in serial
    // order and did not reset it for non-candidates, so unrelated blocks could
    // form a false chain.
    std::vector<bool> candidates(static_cast<size_t>(mba->qty), false);
    int small_blocks = 0;

    for ( int i = 0; i < mba->qty; ++i )
    {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk )
            continue;

        if ( count_insns(blk) <= 2 && has_single_goto_succ(blk) )
        {
            candidates[static_cast<size_t>(i)] = true;
            ++small_blocks;
        }
    }

    const double ratio = static_cast<double>(small_blocks) /
                         static_cast<double>(mba->qty);
    if ( ratio <= 0.30 )
        return false;

    // Detection needs four distinct blocks, not the exact longest chain.
    // Bound each walk to that threshold so long chains/cycles do not cause
    // quadratic rescanning. A fixed local history preserves short-cycle
    // rejection without allocating a function-sized bitmap for every start.
    constexpr int required_chain = 4;
    for ( int start = 0; start < mba->qty; ++start )
    {
        if ( !candidates[static_cast<size_t>(start)] )
            continue;

        int seen[required_chain];
        int current = start;
        int chain_length = 0;
        while ( current >= 0 && current < mba->qty
             && candidates[static_cast<size_t>(current)]
             && std::find(seen, seen + chain_length, current)
                  == seen + chain_length )
        {
            seen[chain_length++] = current;
            if ( chain_length == required_chain )
                return true;

            mblock_t *blk = mba->get_mblock(current);
            if ( !blk || blk->nsucc() != 1 )
                break;
            const int successor = blk->succ(0);
            if ( successor < 0 || successor >= mba->qty )
                break;

            mblock_t *successor_block = mba->get_mblock(successor);
            // Linear split chains have no joins. Requiring one predecessor
            // avoids treating normal control-flow convergence as splitting.
            if ( !successor_block || successor_block->npred() != 1 )
                break;
            current = successor;
        }
    }
    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int block_merge_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx ) 
        return 0;

    deobf::log("[block_merge] Starting block merge\n");

    const int before = mba->qty;
    const bool changed = mba->merge_blocks();
    const int merged = std::max(0, before - mba->qty);
    const int total_changes = changed ? std::max(1, merged) : 0;
    ctx->blocks_merged += merged;
    if ( changed )
        mba->mark_chains_dirty();

    deobf::log("[block_merge] Merged %d blocks\n", ctx->blocks_merged);
    return total_changes;
}

//--------------------------------------------------------------------------
// Count instructions in block
//--------------------------------------------------------------------------
int block_merge_handler_t::count_insns(mblock_t *blk)
{
    if ( !blk ) 
        return 0;

    int count = 0;
    for ( minsn_t *ins = blk->head; ins; ins = ins->next ) 
    {
        // The detector only distinguishes <= 2 from > 2 instructions.
        // There is no need to count the rest of a large noncandidate block.
        if ( ++count > 2 )
            break;
    }
    return count;
}

//--------------------------------------------------------------------------
// Check for single unconditional successor
//--------------------------------------------------------------------------
bool block_merge_handler_t::has_single_goto_succ(mblock_t *blk)
{
    if ( !blk ) 
        return false;

    // Must have exactly one successor
    if ( blk->nsucc() != 1 ) 
        return false;

    // Must end with goto (not conditional jump)
    if ( !blk->tail || blk->tail->opcode != m_goto ) 
        return false;

    return true;
}
