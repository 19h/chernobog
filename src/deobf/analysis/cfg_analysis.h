#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Control Flow Graph analysis utilities
//--------------------------------------------------------------------------
namespace cfg_analysis {

// Basic block information
struct block_info_t {
    int block_idx;
    std::vector<int> predecessors;
    std::vector<int> successors;
    int dominator;              // Immediate dominator
    int post_dominator;         // Immediate post-dominator
    bool is_loop_header;
    bool is_loop_exit;
    int loop_depth;
};

// Build CFG info for all blocks
std::vector<block_info_t> analyze_cfg(mbl_array_t *mba);

// Compute dominators
void compute_dominators(mbl_array_t *mba, std::vector<block_info_t> &blocks);

// Find natural loops
struct loop_info_t {
    int header;                 // Loop header block
    std::set<int> body;        // All blocks in loop body
    std::vector<int> exits;    // Exit blocks
    std::vector<int> backedges;// Blocks with backedges to header
};

std::vector<loop_info_t> find_loops(mbl_array_t *mba, const std::vector<block_info_t> &blocks);

// Check if block A dominates block B
bool dominates(int a, int b, const std::vector<block_info_t> &blocks);

// Get all blocks reachable from a given block
std::set<int> get_reachable(int from, mbl_array_t *mba);

// Get all blocks that can reach a given block
std::set<int> get_reaching(int to, mbl_array_t *mba);

// Find dispatcher block (for deflattening)
// Returns -1 if not found
int find_dispatcher_block(mbl_array_t *mba);

// Find loop back edge targets (for deflattening)
std::vector<int> find_backedge_targets(mbl_array_t *mba);

// Check if a block is dead (unreachable or always-false branch)
bool is_dead_block(mblock_t *blk, mbl_array_t *mba, deobf_ctx_t *ctx);

// Get the condition that leads to a block
// Returns nullptr if unconditional
minsn_t *get_branch_condition(int from_blk, int to_blk, mbl_array_t *mba);

} // namespace cfg_analysis
