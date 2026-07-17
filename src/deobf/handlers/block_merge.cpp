#include "block_merge.h"

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool block_merge_handler_t::detect_split_blocks(mbl_array_t *mba)
{
    if ( !mba ) 
        return false;

    // Count small blocks and check for chains
    int small_blocks = 0;
    int chain_length = 0;
    int max_chain = 0;

    for ( int i = 0; i < mba->qty; ++i ) 
    {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk ) 
            continue;

        int insn_count = count_insns(blk);

        // Small block with single successor
        if ( insn_count <= 2 && has_single_goto_succ(blk) ) 
        {
            small_blocks++;

            // Check if successor is also small (chain)
            if ( blk->nsucc() == 1 ) 
            {
                int succ = blk->succ(0);
                mblock_t *succ_blk = mba->get_mblock(succ);
                if ( succ_blk && count_insns(succ_blk) <= 2 ) 
                {
                    chain_length++;
                    if ( chain_length > max_chain ) 
                        max_chain = chain_length;
                }
                else
                {
                    chain_length = 0;
                }
            }
        }
    }

    // Heuristic: if >30% of blocks are small with chains, likely split
    float ratio = (float)small_blocks / mba->qty;
    return ( ratio > 0.3f && max_chain >= 3) || max_chain >= 5;
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
        count++;
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
