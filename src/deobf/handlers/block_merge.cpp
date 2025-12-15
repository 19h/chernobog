#include "block_merge.h"

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool block_merge_handler_t::detect_split_blocks(mbl_array_t *mba) {
    if (!mba)
        return false;

    // Count small blocks and check for chains
    int small_blocks = 0;
    int chain_length = 0;
    int max_chain = 0;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        int insn_count = count_insns(blk);

        // Small block with single successor
        if (insn_count <= 2 && has_single_goto_succ(blk)) {
            small_blocks++;

            // Check if successor is also small (chain)
            if (blk->nsucc() == 1) {
                int succ = blk->succ(0);
                mblock_t *succ_blk = mba->get_mblock(succ);
                if (succ_blk && count_insns(succ_blk) <= 2) {
                    chain_length++;
                    if (chain_length > max_chain)
                        max_chain = chain_length;
                } else {
                    chain_length = 0;
                }
            }
        }
    }

    // Heuristic: if >30% of blocks are small with chains, likely split
    float ratio = (float)small_blocks / mba->qty;
    return (ratio > 0.3f && max_chain >= 3) || max_chain >= 5;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int block_merge_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    deobf::log("[block_merge] Starting block merge\n");

    int total_changes = 0;

    // Find all mergeable chains
    auto chains = find_mergeable_chains(mba);
    deobf::log("[block_merge] Found %zu mergeable chains\n", chains.size());

    // Merge each chain
    for (const auto &chain : chains) {
        if (chain.blocks.size() >= 2) {
            total_changes += merge_chain(mba, chain, ctx);
        }
    }

    deobf::log("[block_merge] Merged %d blocks\n", ctx->blocks_merged);
    return total_changes;
}

//--------------------------------------------------------------------------
// Find mergeable chains
//--------------------------------------------------------------------------
std::vector<block_merge_handler_t::chain_t>
block_merge_handler_t::find_mergeable_chains(mbl_array_t *mba) {

    std::vector<chain_t> chains;
    std::vector<bool> visited(mba->qty, false);

    for (int i = 0; i < mba->qty; i++) {
        if (visited[i])
            continue;

        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        // Start a chain if this block has single successor
        if (!has_single_goto_succ(blk))
            continue;

        chain_t chain;
        int curr = i;

        while (curr >= 0 && curr < mba->qty && !visited[curr]) {
            mblock_t *curr_blk = mba->get_mblock(curr);
            if (!curr_blk)
                break;

            chain.blocks.push_back(curr);
            visited[curr] = true;

            // Check if can continue chain
            if (!has_single_goto_succ(curr_blk))
                break;

            int succ = curr_blk->succ(0);

            // Don't follow if successor has multiple predecessors
            // (that would break other paths)
            mblock_t *succ_blk = mba->get_mblock(succ);
            if (!succ_blk || succ_blk->npred() != 1)
                break;

            // Check if blocks can be merged
            if (!can_merge(curr_blk, succ_blk, mba))
                break;

            curr = succ;
        }

        if (chain.blocks.size() >= 2) {
            chains.push_back(chain);
        }
    }

    return chains;
}

//--------------------------------------------------------------------------
// Check if two blocks can be merged
//--------------------------------------------------------------------------
bool block_merge_handler_t::can_merge(mblock_t *first, mblock_t *second, mbl_array_t *mba) {
    if (!first || !second)
        return false;

    // First must have exactly one successor (the second block)
    if (first->nsucc() != 1)
        return false;

    // Second must have exactly one predecessor (the first block)
    if (second->npred() != 1)
        return false;

    // First must end with unconditional jump to second
    if (!first->tail || first->tail->opcode != m_goto)
        return false;

    if (first->tail->d.t != mop_b || first->tail->d.b != second->serial)
        return false;

    // Don't merge if second is a loop header or has phi nodes
    // (simplified check - actual phi detection is more complex)

    return true;
}

//--------------------------------------------------------------------------
// Merge chain of blocks
//--------------------------------------------------------------------------
int block_merge_handler_t::merge_chain(mbl_array_t *mba, const chain_t &chain, deobf_ctx_t *ctx) {
    if (chain.blocks.size() < 2)
        return 0;

    int merged = 0;

    // In Hex-Rays microcode, we can't directly merge blocks
    // Instead, we can:
    // 1. Remove the goto instructions between blocks
    // 2. Let the optimizer merge them
    // 3. Or mark blocks for later processing

    // For now, annotate and remove gotos
    for (size_t i = 0; i < chain.blocks.size() - 1; i++) {
        mblock_t *blk = mba->get_mblock(chain.blocks[i]);
        if (!blk || !blk->tail)
            continue;

        // If block ends with goto to next in chain, we can mark it
        if (blk->tail->opcode == m_goto) {
            // Change goto to nop (will be optimized away)
            // Note: This is simplified - actual implementation needs care
            deobf::log_verbose("[block_merge] Chain: %d -> %d\n",
                              chain.blocks[i], chain.blocks[i + 1]);
            merged++;
        }
    }

    ctx->blocks_merged += merged;
    return merged;
}

//--------------------------------------------------------------------------
// Count instructions in block
//--------------------------------------------------------------------------
int block_merge_handler_t::count_insns(mblock_t *blk) {
    if (!blk)
        return 0;

    int count = 0;
    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        count++;
    }
    return count;
}

//--------------------------------------------------------------------------
// Check for single unconditional successor
//--------------------------------------------------------------------------
bool block_merge_handler_t::has_single_goto_succ(mblock_t *blk) {
    if (!blk)
        return false;

    // Must have exactly one successor
    if (blk->nsucc() != 1)
        return false;

    // Must end with goto (not conditional jump)
    if (!blk->tail || blk->tail->opcode != m_goto)
        return false;

    return true;
}
