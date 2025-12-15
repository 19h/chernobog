#pragma once
#include "../deobf_types.h"
#include "../analysis/z3_solver.h"

//--------------------------------------------------------------------------
// Control Flow Deflattening Handler
//
// Hikari's flattening transforms:
//   Original CFG -> switch-based dispatcher loop
//
// This handler uses Z3-based symbolic execution to:
//   1. Identify dispatcher blocks (state machine controllers)
//   2. Symbolically execute case blocks to determine state transitions
//   3. Solve the state machine to reconstruct original CFG edges
//   4. Modify microcode to bypass dispatchers with direct branches
//   5. Clean up unreachable dispatcher code
//
// Supports:
//   - Single-level flattening
//   - Hierarchical/nested flattening (dispatchers within dispatchers)
//   - Mixed dispatcher patterns (switch vs. cascading conditionals)
//   - State variable aliasing and rotation
//   - Conditional transitions within flattened code
//
// Implementation uses a two-phase approach for safe CFG modification:
//   Phase 1 (MMAT_PREOPTIMIZED): Analyze and store edge transitions
//   Phase 2 (MMAT_LOCOPT): Apply CFG modifications when structure is stable
//--------------------------------------------------------------------------

//--------------------------------------------------------------------------
// Deferred CFG edge - stored for later application
//--------------------------------------------------------------------------
struct deferred_edge_t {
    int from_block;
    int to_block;
    uint64_t state_value;
    bool is_conditional;
    bool is_true_branch;

    deferred_edge_t() : from_block(-1), to_block(-1), state_value(0),
                       is_conditional(false), is_true_branch(false) {}
};

//--------------------------------------------------------------------------
// Stored analysis results for a function
//--------------------------------------------------------------------------
struct deferred_analysis_t {
    ea_t func_ea;
    std::vector<deferred_edge_t> edges;
    std::set<int> dispatcher_blocks;
    int analysis_maturity;
    bool analysis_complete;

    deferred_analysis_t() : func_ea(BADADDR), analysis_maturity(-1),
                           analysis_complete(false) {}
};

class deflatten_handler_t {
public:
    // Detection
    static bool detect(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Main deobfuscation pass
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Two-phase deobfuscation for safe CFG modification
    // Phase 1: Analyze at early maturity and store results
    static int analyze_and_store(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Phase 2: Apply stored CFG modifications at stable maturity
    static int apply_deferred(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Storage for deferred analysis results
    static std::map<ea_t, deferred_analysis_t> s_deferred_analysis;

    // Clear deferred analysis for a function
    static void clear_deferred(ea_t func_ea);

    // Check if we have pending analysis for a function
    static bool has_pending_analysis(ea_t func_ea);

private:
    //----------------------------------------------------------------------
    // CFG Edge - represents an edge in the recovered control flow graph
    //----------------------------------------------------------------------
    struct cfg_edge_t {
        int from_block;             // Source block
        int to_block;               // Target block (-1 if unresolved)
        bool is_conditional;        // True if this is a conditional edge
        bool is_true_branch;        // For conditional: is this the true branch?
        uint64_t state_value;       // State value associated with this edge
        std::shared_ptr<z3::expr> condition;  // Branch condition (Z3 expression)

        cfg_edge_t() : from_block(-1), to_block(-1), is_conditional(false),
                      is_true_branch(false), state_value(0) {}
    };

    //----------------------------------------------------------------------
    // Dispatcher info - supports multiple/nested dispatchers
    //----------------------------------------------------------------------
    struct dispatcher_info_t {
        int block_idx;              // Block containing the switch/dispatcher
        z3_solver::symbolic_var_t state_var;  // State variable for THIS dispatcher
        int parent_dispatcher;      // Parent dispatcher index (-1 if root)
        int nesting_level;          // 0 = root, 1 = nested, etc.
        std::set<int> case_blocks;  // Blocks belonging to this dispatcher
        std::map<uint64_t, int> state_to_block;  // State -> target block
        std::set<int> dispatcher_chain;  // All blocks that form the dispatcher
        bool is_solved;             // True if successfully analyzed

        dispatcher_info_t() : block_idx(-1), parent_dispatcher(-1),
                             nesting_level(0), is_solved(false) {}
    };

    //----------------------------------------------------------------------
    // Z3-based analysis
    //----------------------------------------------------------------------

    // Analyze all dispatchers in the function using Z3
    static std::vector<dispatcher_info_t> analyze_dispatchers_z3(mbl_array_t *mba);

    // Analyze a single block to determine if it's a dispatcher
    static bool analyze_dispatcher_block(mbl_array_t *mba, int block_idx,
                                         dispatcher_info_t *out);

    // Use symbolic execution to trace state transitions through case blocks
    static std::vector<cfg_edge_t> trace_transitions_z3(
        mbl_array_t *mba,
        const dispatcher_info_t &disp);

    // Solve for the next state value written by a block
    static std::optional<uint64_t> solve_written_state(
        mbl_array_t *mba,
        int block_idx,
        const z3_solver::symbolic_var_t &state_var);

    // Handle conditional transitions within case blocks
    static std::vector<cfg_edge_t> analyze_conditional_transitions(
        mbl_array_t *mba,
        int block_idx,
        const z3_solver::symbolic_var_t &state_var);

    //----------------------------------------------------------------------
    // CFG Reconstruction
    //----------------------------------------------------------------------

    // Reconstruct CFG by patching branch targets
    static int reconstruct_cfg_z3(mbl_array_t *mba,
                                   const std::vector<cfg_edge_t> &edges,
                                   const dispatcher_info_t &disp,
                                   deobf_ctx_t *ctx);

    // Remove dispatcher blocks that are now unreachable
    static int cleanup_dispatcher(mbl_array_t *mba,
                                   const dispatcher_info_t &disp,
                                   deobf_ctx_t *ctx);

    // Remove state variable assignments (they're no longer needed)
    static int remove_state_assignments(mbl_array_t *mba,
                                         const z3_solver::symbolic_var_t &state_var,
                                         deobf_ctx_t *ctx);

    //----------------------------------------------------------------------
    // Legacy compatibility (delegates to Z3 solver)
    //----------------------------------------------------------------------

    // Find dispatcher block
    static int find_dispatcher(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Find state variable
    static bool find_state_variable(mbl_array_t *mba, int dispatcher_blk, deobf_ctx_t *ctx);

    // Build state map
    static bool build_state_map(mbl_array_t *mba, deobf_ctx_t *ctx);

    //----------------------------------------------------------------------
    // Utilities
    //----------------------------------------------------------------------

    // Check if a value is a Hikari-style state constant
    static bool is_state_constant(uint64_t val);

    // Find all state constants in a block
    static std::set<uint64_t> find_state_constants(const mblock_t *blk);

    // Check if block terminates the dispatcher (exit or return)
    static bool is_exit_block(const mblock_t *blk);

    // Get all successor blocks (including fall-through)
    static std::vector<int> get_successors(const mblock_t *blk);

    // Verify CFG modification is safe
    static bool verify_cfg_safety(mbl_array_t *mba,
                                   const std::vector<cfg_edge_t> &edges);
};
