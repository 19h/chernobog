#pragma once
#include "../deobf_types.h"
#include "../analysis/z3_solver.h"
#include <memory>
#include <vector>
#include <map>
#include <set>
#include <optional>
#include <functional>

//--------------------------------------------------------------------------
// Unflattener Base Class
//
// Abstract base class for control flow unflattening algorithms.
// Provides common infrastructure for:
//   - Dispatcher pattern detection
//   - State variable identification and tracking
//   - Z3-based symbolic execution for state transition analysis
//   - CFG reconstruction utilities
//   - Two-phase analysis/application for safe modification
//
// Derived classes implement specific unflattening strategies:
//   - OLLVMUnflattener: O-LLVM switch-based flattening
//   - HikariUnflattener: Hikari-style state machine (built-in)
//   - GenericUnflattener: Heuristic-based generic approach
//   - IndirectJumpUnflattener: Jump table-based flattening
//
// Design principles:
//   - Z3-first: Use SMT solving for robust state analysis
//   - Pattern fallback: Fast pattern matching for common cases
//   - Safe modification: Two-phase analyze/apply for CFG changes
//   - Extensible: Easy to add new unflattening strategies
//--------------------------------------------------------------------------

namespace chernobog {

//--------------------------------------------------------------------------
// State Variable - represents the control flow state variable
//--------------------------------------------------------------------------
struct StateVariable {
    z3_solver::symbolic_var_t var;
    mop_t mop;              // Original microcode operand
    int size;               // Size in bytes
    bool is_stack;          // True if stack variable
    bool is_global;         // True if global variable
    sval_t stack_offset;    // Stack offset (if is_stack)
    ea_t global_addr;       // Global address (if is_global)

    StateVariable() : size(4), is_stack(false), is_global(false),
                      stack_offset(0), global_addr(BADADDR) {}

    bool is_valid() const {
        return size > 0 && (is_stack || is_global || mop.t != mop_z);
    }
};

//--------------------------------------------------------------------------
// Dispatcher Block - represents a state machine dispatcher
//--------------------------------------------------------------------------
struct DispatcherBlock {
    int block_idx;                      // Block index in mbl_array_t
    ea_t start_addr;                    // Start address
    StateVariable state_var;            // State variable for this dispatcher

    // State to target mapping
    std::map<uint64_t, int> state_to_block;

    // Dispatcher structure
    std::set<int> dispatcher_chain;     // All blocks forming the dispatcher
    std::set<int> case_blocks;          // Case blocks handled by this dispatcher
    int default_block;                  // Default/fallback block (-1 if none)
    int exit_block;                     // Exit block (-1 if none)

    // Hierarchy support
    int parent_dispatcher;              // Parent dispatcher index (-1 if root)
    std::vector<int> child_dispatchers; // Nested dispatcher indices
    int nesting_level;                  // 0 = root, 1 = nested, etc.

    // Analysis state
    bool is_analyzed;                   // True if analysis complete
    bool is_solvable;                   // True if can be unflattened

    DispatcherBlock() : block_idx(-1), default_block(-1), exit_block(-1),
                        parent_dispatcher(-1), nesting_level(0),
                        is_analyzed(false), is_solvable(false) {}
};

//--------------------------------------------------------------------------
// State Transition - represents a control flow edge in the state machine
//--------------------------------------------------------------------------
struct StateTransition {
    // Source
    int from_block;                 // Source block index
    uint64_t from_state;            // Current state value (or 0 if unknown)

    // Destination
    int to_block;                   // Target block index (-1 if via dispatcher)
    uint64_t to_state;              // Target state value

    // Condition
    bool is_conditional;            // True if conditional transition
    bool is_true_branch;            // For conditional: true or false branch
    std::shared_ptr<z3::expr> condition;  // Z3 condition expression

    // Metadata
    ea_t transition_addr;           // Address of state assignment

    StateTransition() : from_block(-1), from_state(0), to_block(-1), to_state(0),
                        is_conditional(false), is_true_branch(false),
                        transition_addr(BADADDR) {}
};

//--------------------------------------------------------------------------
// Unflattening Result - returned by unflattening pass
//--------------------------------------------------------------------------
struct UnflattenResult {
    bool success;                       // True if unflattening succeeded
    int edges_recovered;                // Number of CFG edges recovered
    int blocks_modified;                // Number of blocks modified
    int dispatchers_eliminated;         // Number of dispatchers removed
    std::vector<StateTransition> transitions;  // Recovered transitions
    std::string error_message;          // Error message if failed

    UnflattenResult() : success(false), edges_recovered(0),
                        blocks_modified(0), dispatchers_eliminated(0) {}
};

//--------------------------------------------------------------------------
// Z3 State Solver - handles symbolic state analysis
//--------------------------------------------------------------------------
class Z3StateSolver {
public:
    explicit Z3StateSolver(z3_solver::z3_context_t& ctx);

    //----------------------------------------------------------------------
    // State Variable Detection
    //----------------------------------------------------------------------

    // Find potential state variables in the function
    std::vector<StateVariable> find_state_variables(mbl_array_t* mba);

    // Verify a candidate state variable is valid
    bool verify_state_variable(mbl_array_t* mba, const StateVariable& var);

    // Find where a state variable is written in a block
    std::optional<uint64_t> find_state_write(mblock_t* blk,
                                              const StateVariable& var);

    //----------------------------------------------------------------------
    // Dispatcher Analysis
    //----------------------------------------------------------------------

    // Analyze potential dispatcher block
    bool analyze_dispatcher(mbl_array_t* mba, int block_idx,
                           const StateVariable& var, DispatcherBlock* out);

    // Build state-to-block mapping for a dispatcher
    bool build_state_map(mbl_array_t* mba, DispatcherBlock* disp);

    // Check if a block is part of a dispatcher chain
    bool is_dispatcher_block(mblock_t* blk, const StateVariable& var);

    //----------------------------------------------------------------------
    // Transition Analysis
    //----------------------------------------------------------------------

    // Symbolically execute a block to find state transitions
    std::vector<StateTransition> analyze_block_transitions(
        mbl_array_t* mba, int block_idx, const StateVariable& var);

    // Solve for the written state value in a block
    std::optional<uint64_t> solve_written_state(
        mbl_array_t* mba, int block_idx, const StateVariable& var);

    // Handle conditional state writes
    std::vector<StateTransition> analyze_conditional_writes(
        mbl_array_t* mba, int block_idx, const StateVariable& var);

    //----------------------------------------------------------------------
    // Z3 Utilities
    //----------------------------------------------------------------------

    // Create Z3 expression for state variable
    z3::expr state_to_z3(const StateVariable& var);

    // Solve for a constant value
    std::optional<uint64_t> solve_constant(const z3::expr& expr, int bits);

    // Check if expression is constant
    bool is_constant_expr(const z3::expr& expr, int bits);

    // Check satisfiability with timeout
    z3_solver::sat_result_t check_sat(const z3::expr& constraint);

    //----------------------------------------------------------------------
    // Configuration
    //----------------------------------------------------------------------

    void set_timeout(unsigned ms);
    void reset();

private:
    z3_solver::z3_context_t& ctx_;
    z3_solver::mcode_translator_t translator_;
    unsigned timeout_ms_ = 5000;

    // Cache of analyzed blocks
    std::map<int, std::vector<StateTransition>> transition_cache_;
};

//--------------------------------------------------------------------------
// UnflattenerBase - abstract base class
//--------------------------------------------------------------------------
class UnflattenerBase {
public:
    virtual ~UnflattenerBase() = default;

    //----------------------------------------------------------------------
    // Interface (must be implemented by derived classes)
    //----------------------------------------------------------------------

    // Name of the unflattening algorithm
    virtual const char* name() const = 0;

    // Priority (higher = tried first)
    virtual int priority() const { return 50; }

    // Check if this unflattener applies to the function
    // Returns confidence score: 0 = doesn't apply, 100 = definite match
    virtual int detect(mbl_array_t* mba) = 0;

    // Analyze the function and build transition map
    // Called at early maturity to gather information
    virtual bool analyze(mbl_array_t* mba, deobf_ctx_t* ctx) = 0;

    // Apply the unflattening transformation
    // Called at stable maturity to modify CFG
    virtual UnflattenResult apply(mbl_array_t* mba, deobf_ctx_t* ctx) = 0;

    //----------------------------------------------------------------------
    // Optional overrides
    //----------------------------------------------------------------------

    // Called after successful unflattening for cleanup
    virtual void cleanup(mbl_array_t* mba, deobf_ctx_t* ctx) {}

    // Check if analysis is complete and ready to apply
    virtual bool is_ready() const { return analysis_complete_; }

    // Reset state for new function
    virtual void reset();

    //----------------------------------------------------------------------
    // Statistics
    //----------------------------------------------------------------------

    size_t functions_unflattened() const { return functions_unflattened_; }
    size_t edges_recovered() const { return edges_recovered_; }
    size_t dispatchers_eliminated() const { return dispatchers_eliminated_; }

    void reset_statistics();

    //----------------------------------------------------------------------
    // Common Utilities (public for Z3StateSolver access)
    //----------------------------------------------------------------------

    // Heuristic checks for state constants
    static bool is_state_constant(uint64_t val);
    static bool is_hikari_constant(uint64_t val);
    static bool is_ollvm_constant(uint64_t val);

protected:
    UnflattenerBase();

    //----------------------------------------------------------------------
    // Z3 Solver Access
    //----------------------------------------------------------------------

    Z3StateSolver& solver();

    // Find all potential state constants in a block
    static std::set<uint64_t> find_constants_in_block(const mblock_t* blk);

    // CFG modification utilities
    static bool redirect_edge(mbl_array_t* mba, int from_block,
                             int old_target, int new_target);
    static bool convert_to_goto(mblock_t* blk, int target_block);
    static bool convert_to_nop(mblock_t* blk, minsn_t* ins);
    static bool remove_dead_stores(mblock_t* blk, const StateVariable& var);

    // Block analysis utilities
    static bool is_exit_block(const mblock_t* blk);
    static bool is_return_block(const mblock_t* blk);
    static std::vector<int> get_successors(const mblock_t* blk);
    static std::vector<int> get_predecessors(const mblock_t* blk);

    // Dispatcher detection heuristics
    int count_state_comparisons(const mblock_t* blk);
    bool has_state_variable_read(const mblock_t* blk, const StateVariable& var);

    //----------------------------------------------------------------------
    // Analysis State
    //----------------------------------------------------------------------

    bool analysis_complete_ = false;
    std::vector<DispatcherBlock> dispatchers_;
    std::vector<StateTransition> transitions_;
    StateVariable primary_state_var_;

    //----------------------------------------------------------------------
    // Statistics
    //----------------------------------------------------------------------

    size_t functions_unflattened_ = 0;
    size_t edges_recovered_ = 0;
    size_t dispatchers_eliminated_ = 0;

private:
    std::unique_ptr<Z3StateSolver> solver_;
};

//--------------------------------------------------------------------------
// Unflattener Registry - manages multiple unflattening algorithms
//--------------------------------------------------------------------------
class UnflattenerRegistry {
public:
    static UnflattenerRegistry& instance();

    // Register an unflattener
    void register_unflattener(std::unique_ptr<UnflattenerBase> unflattener);

    // Initialize all built-in unflatteners
    void initialize();

    // Try all unflatteners on a function
    // Returns the best matching unflattener (or nullptr)
    UnflattenerBase* find_best_match(mbl_array_t* mba);

    // Run unflattening on a function
    UnflattenResult unflatten(mbl_array_t* mba, deobf_ctx_t* ctx);

    // Get statistics
    void dump_statistics();
    void reset_statistics();

    // Access unflatteners
    const std::vector<std::unique_ptr<UnflattenerBase>>& unflatteners() const {
        return unflatteners_;
    }

private:
    UnflattenerRegistry() = default;

    std::vector<std::unique_ptr<UnflattenerBase>> unflatteners_;
    bool initialized_ = false;
};

//--------------------------------------------------------------------------
// Built-in Unflatteners
//--------------------------------------------------------------------------

// Hikari-style state machine (already implemented in deflatten.cpp)
class HikariUnflattener : public UnflattenerBase {
public:
    const char* name() const override { return "HikariUnflattener"; }
    int priority() const override { return 80; }
    int detect(mbl_array_t* mba) override;
    bool analyze(mbl_array_t* mba, deobf_ctx_t* ctx) override;
    UnflattenResult apply(mbl_array_t* mba, deobf_ctx_t* ctx) override;
};

// O-LLVM switch-based flattening
class OLLVMUnflattener : public UnflattenerBase {
public:
    const char* name() const override { return "OLLVMUnflattener"; }
    int priority() const override { return 70; }
    int detect(mbl_array_t* mba) override;
    bool analyze(mbl_array_t* mba, deobf_ctx_t* ctx) override;
    UnflattenResult apply(mbl_array_t* mba, deobf_ctx_t* ctx) override;

private:
    // O-LLVM specific detection
    bool detect_switch_dispatcher(mbl_array_t* mba);
    bool detect_prologue_pattern(mbl_array_t* mba);
};

// Generic heuristic-based unflattener (fallback)
class GenericUnflattener : public UnflattenerBase {
public:
    const char* name() const override { return "GenericUnflattener"; }
    int priority() const override { return 30; }
    int detect(mbl_array_t* mba) override;
    bool analyze(mbl_array_t* mba, deobf_ctx_t* ctx) override;
    UnflattenResult apply(mbl_array_t* mba, deobf_ctx_t* ctx) override;

private:
    // Generic detection heuristics
    int score_as_dispatcher(const mblock_t* blk);
    bool detect_state_variable_generic(mbl_array_t* mba);
};

// Index-based jump table flattening
class JumpTableUnflattener : public UnflattenerBase {
public:
    const char* name() const override { return "JumpTableUnflattener"; }
    int priority() const override { return 60; }
    int detect(mbl_array_t* mba) override;
    bool analyze(mbl_array_t* mba, deobf_ctx_t* ctx) override;
    UnflattenResult apply(mbl_array_t* mba, deobf_ctx_t* ctx) override;

private:
    // Jump table detection
    bool detect_jump_table(mbl_array_t* mba, int* table_block);
    bool analyze_index_computation(mblock_t* blk);
};

} // namespace chernobog
