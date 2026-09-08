// Frozen pre-optimization detector oracle. Source body was taken from
// src/deobf/handlers/block_merge.cpp, SHA-256
// 6af53f1639ba45dfce4b4db882e0550104a429b32db916de6c1fc758dea93d0f.
// Keep the exact longest-chain algorithm here for differential tests.
#include "block_merge_ida_stub.hpp"

bool reference_detect_split_blocks(mbl_array_t *mba)
{
    if ( !mba || mba->qty <= 0 )
        return false;
    if ( mba->has_bad_sp() || mba->bad_call_sp_detected() )
        return false;

    std::vector<bool> candidates(static_cast<size_t>(mba->qty), false);
    int small_blocks = 0;
    for ( int i = 0; i < mba->qty; ++i )
    {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk )
            continue;
        int count = 0;
        for ( minsn_t *ins = blk->head; ins; ins = ins->next )
            ++count;
        if ( count <= 2 && blk->nsucc() == 1
          && blk->tail && blk->tail->opcode == m_goto )
        {
            candidates[static_cast<size_t>(i)] = true;
            ++small_blocks;
        }
    }

    int max_chain = 0;
    for ( int start = 0; start < mba->qty; ++start )
    {
        if ( !candidates[static_cast<size_t>(start)] )
            continue;
        std::vector<bool> seen(static_cast<size_t>(mba->qty), false);
        int current = start;
        int chain_length = 0;
        while ( current >= 0 && current < mba->qty
             && candidates[static_cast<size_t>(current)]
             && !seen[static_cast<size_t>(current)] )
        {
            seen[static_cast<size_t>(current)] = true;
            ++chain_length;
            mblock_t *blk = mba->get_mblock(current);
            if ( !blk || blk->nsucc() != 1 )
                break;
            const int successor = blk->succ(0);
            if ( successor < 0 || successor >= mba->qty )
                break;
            mblock_t *successor_block = mba->get_mblock(successor);
            if ( !successor_block || successor_block->npred() != 1 )
                break;
            current = successor;
        }
        max_chain = std::max(max_chain, chain_length);
    }
    const double ratio = static_cast<double>(small_blocks) /
                         static_cast<double>(mba->qty);
    return ratio > 0.30 && max_chain >= 4;
}
