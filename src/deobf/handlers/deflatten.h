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
// State transition - represents a transition from one state to another
// This is stable across maturities since it uses state VALUES, not block indices
//--------------------------------------------------------------------------
struct state_transition_t {
    uint64_t from_state;      // State being handled
    uint64_t to_state;        // State being transitioned to
    bool is_conditional;      // True if transition depends on a condition
    bool is_true_branch;      // For conditional: is this the true branch?

    state_transition_t() : from_state(0), to_state(0),
                          is_conditional(false), is_true_branch(false) {}
};

//--------------------------------------------------------------------------
// Deferred CFG edge - stored for later application
// Uses addresses instead of block indices since indices change between maturities
//--------------------------------------------------------------------------
struct deferred_edge_t {
    ea_t from_addr;           // Start address of source block
    ea_t to_addr;             // Start address of target block (for verification)
    uint64_t state_value;     // State value being written (to look up target at apply time)
    bool is_conditional;
    bool is_true_branch;

    deferred_edge_t() : from_addr(BADADDR), to_addr(BADADDR), state_value(0),
                       is_conditional(false), is_true_branch(false) {}
};

//--------------------------------------------------------------------------
// Stored analysis results for a function
//--------------------------------------------------------------------------
struct deferred_analysis_t {
    ea_t func_ea;
    std::vector<deferred_edge_t> edges;               // Block-level edges (may not work across maturities)
    std::vector<state_transition_t> state_transitions; // State-level transitions (stable)
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

    //----------------------------------------------------------------------
    // Utilities (public for use by helper functions)
    //----------------------------------------------------------------------

    // Check if a value is a Hikari-style state constant
    static bool is_state_constant(uint64_t val);

    //----------------------------------------------------------------------
    // Dispatcher info - supports multiple/nested dispatchers
    // (Public for use by helper functions)
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
        bool is_jump_table;         // True if jump-table style (small int states 0..n)
        int max_state;              // Maximum state value for jump-table validation

        dispatcher_info_t() : block_idx(-1), parent_dispatcher(-1),
                             nesting_level(0), is_solved(false),
                             is_jump_table(false), max_state(0) {}
    };

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
    // Z3-based analysis
    //----------------------------------------------------------------------

    // Analyze jump table-based flattening (index-based, not magic constants)
    static bool analyze_jump_table_flattening(mbl_array_t *mba,
                                              std::vector<dispatcher_info_t> &dispatchers);

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
    // max_jump_table_state: if > 0, accept small indices [0..max] instead of Hikari constants
    static std::optional<uint64_t> solve_written_state(
        mbl_array_t *mba,
        int block_idx,
        const z3_solver::symbolic_var_t &state_var,
        int max_jump_table_state = -1);

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
    // max_jump_table_state: if > 0, treat small indices as valid state values
    static int remove_state_assignments(mbl_array_t *mba,
                                         const z3_solver::symbolic_var_t &state_var,
                                         deobf_ctx_t *ctx,
                                         int max_jump_table_state = -1);

    //----------------------------------------------------------------------
    // Legacy compatibility (delegates to Z3 solver)
    //----------------------------------------------------------------------

    // Find dispatcher block
    static int find_dispatcher(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Find state variable
    static bool find_state_variable(mbl_array_t *mba, int dispatcher_blk, deobf_ctx_t *ctx);

    // Build state map
    static bool build_state_map(mbl_array_t *mba, deobf_ctx_t *ctx);

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
