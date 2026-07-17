#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Block Merge Handler
//
// Hikari's block splitting:
//   - Splits basic blocks at random points
//   - Creates many small blocks connected by unconditional jumps
//   - Block names have ".split" suffix
//
// Detection:
//   - Many small blocks (1-2 instructions each)
//   - Linear chains of unconditional jumps
//   - ".split" in block/label names
//
// Reversal:
//   1. Identify linear block chains
//   2. Merge consecutive blocks
//   3. Remove intermediate jumps
//   4. Preserve semantic ordering
//--------------------------------------------------------------------------
class block_merge_handler_t {
public:
    // Detection
    static bool detect_split_blocks(mbl_array_t *mba);

    // Main deobfuscation pass
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

private:
    // Helper: count instructions in a block
    static int count_insns(mblock_t *blk);

    // Helper: check if block has single unconditional successor
    static bool has_single_goto_succ(mblock_t *blk);
};
