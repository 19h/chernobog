#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Control Flow Deflattening Handler
//
// Hikari's flattening transforms:
//   Original CFG -> switch-based dispatcher loop
//
// ENHANCED: Supports hierarchical/nested flattening where:
//   - Outer dispatcher jumps to labels that contain inner dispatchers
//   - Different state variables used in different sub-dispatchers
//   - State variable rotation/aliasing between dispatcher levels
//
// Detection:
//   - Switch statement or cascading conditionals on state variable
//   - Loop structure: entry -> dispatcher -> cases -> loop_end -> entry
//   - State variable updates in each case block
//   - Nested while(true) loops with their own switches
//
// Reversal:
//   1. Identify ALL dispatcher blocks (recursive)
//   2. For each dispatcher, identify ITS state variable (taint analysis)
//   3. Map state values to original blocks per-dispatcher
//   4. Trace state transitions to reconstruct CFG
//   5. Replace switches with direct branches
//   6. Remove dispatcher loop infrastructure
//--------------------------------------------------------------------------
class deflatten_handler_t {
public:
    // Detection
    static bool detect(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Main deobfuscation pass
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

private:
    //----------------------------------------------------------------------
    // Dispatcher info - supports multiple/nested dispatchers
    //----------------------------------------------------------------------
    struct dispatcher_info_t {
        int block_idx;              // Block containing the switch/dispatcher
        mop_t state_var;            // State variable for THIS dispatcher
        int parent_dispatcher;      // Parent dispatcher index (-1 if root)
        int nesting_level;          // 0 = root, 1 = nested, etc.
        std::set<int> case_blocks;  // Blocks belonging to this dispatcher
        std::map<uint64_t, int> state_to_block;  // State -> target block
        bool is_while_loop;         // True if wrapped in while(true)
    };

    // Find ALL dispatchers (recursive/hierarchical)
    static std::vector<dispatcher_info_t> find_all_dispatchers(mbl_array_t *mba);

    // Find the dispatcher block containing the switch
    static int find_dispatcher(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Find the state variable for a specific dispatcher (taint analysis)
    static bool find_state_variable(mbl_array_t *mba, int dispatcher_blk, deobf_ctx_t *ctx);
    static bool find_state_variable_for_dispatcher(mbl_array_t *mba, dispatcher_info_t *disp);

    // Check if a block is itself a dispatcher (for nested detection)
    static bool is_dispatcher_block(mblock_t *blk, mop_t *out_state_var);

    // Check if block is inside a while(true) loop
    static bool is_in_infinite_loop(mbl_array_t *mba, int block_idx);

    // Map state values to blocks
    static bool build_state_map(mbl_array_t *mba, deobf_ctx_t *ctx);
    static bool build_state_map_for_dispatcher(mbl_array_t *mba, dispatcher_info_t *disp);

    // Trace state transitions to find original edges
    struct edge_t {
        int from_block;
        int to_block;
        bool is_conditional;
        minsn_t *condition;
        int dispatcher_level;       // Which dispatcher level this edge is in
    };
    static std::vector<edge_t> trace_transitions(mbl_array_t *mba, deobf_ctx_t *ctx);
    static std::vector<edge_t> trace_transitions_for_dispatcher(mbl_array_t *mba,
                                                                 const dispatcher_info_t &disp);

    // Reconstruct CFG with direct branches
    static int reconstruct_cfg(mbl_array_t *mba, const std::vector<edge_t> &edges, deobf_ctx_t *ctx);

    // Helper: get state value written by block
    static std::optional<uint64_t> get_written_state(mblock_t *blk, deobf_ctx_t *ctx);
    static std::optional<uint64_t> get_written_state(mblock_t *blk, const mop_t &state_var);

    // Helper: get state value read as condition
    static std::optional<uint64_t> get_state_comparison(minsn_t *cmp_insn, deobf_ctx_t *ctx);

    // Flatten all dispatchers recursively
    static int deflatten_hierarchical(mbl_array_t *mba,
                                      const std::vector<dispatcher_info_t> &dispatchers,
                                      deobf_ctx_t *ctx);
};
