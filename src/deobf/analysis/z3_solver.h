#pragma once
#include "../deobf_types.h"
#include <z3++.h>
#include <memory>
#include <unordered_map>
#include <optional>
#include <functional>

//--------------------------------------------------------------------------
// Z3-based Symbolic Solver for Microcode Analysis
//
// Provides comprehensive symbolic execution and constraint solving for:
//   - Control flow deflattening (solving state machine transitions)
//   - Opaque predicate evaluation (determining if conditions are constant)
//   - Constant folding and expression simplification
//   - Path constraint solving
//
// Design principles:
//   - Lazy symbol creation: only create Z3 variables when needed
//   - Efficient caching: memoize translations and solutions
//   - Sound analysis: never produce incorrect results (may be incomplete)
//   - Timeout-bounded: configurable limits to prevent infinite analysis
//--------------------------------------------------------------------------

namespace z3_solver {

//--------------------------------------------------------------------------
// Forward declarations
//--------------------------------------------------------------------------
class symbolic_state_t;
class path_constraint_t;

//--------------------------------------------------------------------------
// Result of satisfiability check
//--------------------------------------------------------------------------
enum class sat_result_t {
    SAT,            // Satisfiable - found a model
    UNSAT,          // Unsatisfiable - no solution exists
    UNKNOWN,        // Unknown - solver timed out or hit limits
};

//--------------------------------------------------------------------------
// Result of constant evaluation
//--------------------------------------------------------------------------
struct eval_result_t {
    bool is_constant;       // True if expression evaluates to a constant
    uint64_t value;         // The constant value (valid if is_constant)
    int bit_width;          // Bit width of the result

    eval_result_t() : is_constant(false), value(0), bit_width(64) {}
    eval_result_t(uint64_t v, int w) : is_constant(true), value(v), bit_width(w) {}
    static eval_result_t unknown() { return eval_result_t(); }
    static eval_result_t constant(uint64_t v, int w = 64) { return eval_result_t(v, w); }
};

//--------------------------------------------------------------------------
// Z3 Context wrapper - manages Z3 context lifetime
//--------------------------------------------------------------------------
class z3_context_t {
public:
    z3_context_t();
    ~z3_context_t();

    z3::context& ctx() { return m_ctx; }
    z3::solver& solver() { return m_solver; }

    // Reset solver state (keeps context)
    void reset();

    // Set timeout in milliseconds (0 = no timeout)
    void set_timeout(unsigned ms);

private:
    z3::context m_ctx;
    z3::solver m_solver;
};

//--------------------------------------------------------------------------
// Symbolic Variable - represents a microcode variable symbolically
//--------------------------------------------------------------------------
class symbolic_var_t {
public:
    enum var_kind_t {
        VAR_REGISTER,       // Machine register (mreg_t)
        VAR_STACK,          // Stack variable (stkvar)
        VAR_GLOBAL,         // Global variable (ea_t)
        VAR_LOCAL,          // Local variable (lvar)
        VAR_TEMP,           // Temporary expression
        VAR_MEMORY,         // Memory location
    };

    symbolic_var_t() : m_kind(VAR_TEMP), m_id(0), m_size(0) {}
    symbolic_var_t(var_kind_t kind, uint64_t id, int size)
        : m_kind(kind), m_id(id), m_size(size) {}

    var_kind_t kind() const { return m_kind; }
    uint64_t id() const { return m_id; }
    int size() const { return m_size; }

    bool operator==(const symbolic_var_t& other) const {
        return m_kind == other.m_kind && m_id == other.m_id && m_size == other.m_size;
    }

    // Hash function for use in unordered_map
    struct hash_t {
        size_t operator()(const symbolic_var_t& v) const {
            return std::hash<int>()(v.m_kind) ^
                   (std::hash<uint64_t>()(v.m_id) << 1) ^
                   (std::hash<int>()(v.m_size) << 2);
        }
    };

private:
    var_kind_t m_kind;
    uint64_t m_id;      // Register number, stack offset, global address, etc.
    int m_size;         // Size in bytes
};

//--------------------------------------------------------------------------
// Microcode to Z3 Translator
//
// Converts IDA Hex-Rays microcode instructions and operands to Z3
// bitvector expressions for symbolic analysis.
//--------------------------------------------------------------------------
class mcode_translator_t {
public:
    explicit mcode_translator_t(z3_context_t& ctx);

    // Translate a microcode operand to Z3 expression
    z3::expr translate_operand(const mop_t& op, int default_size = 4);

    // Translate a microcode instruction to Z3 expression
    z3::expr translate_insn(const minsn_t* ins);

    // Translate a conditional jump condition
    z3::expr translate_jcc_condition(const minsn_t* jcc);

    // Create a fresh symbolic variable for an operand
    z3::expr make_symbolic(const mop_t& op);
    z3::expr make_symbolic(const symbolic_var_t& var);

    // Create a constant bitvector
    z3::expr make_const(uint64_t value, int bits);

    // Set known value for a variable (from binary analysis)
    void set_known_value(const symbolic_var_t& var, uint64_t value);
    void set_known_value(const mop_t& op, uint64_t value);

    // Bind a variable to its current symbolic expression. This lets the
    // executor propagate values across instructions without treating each
    // read as an unrelated input symbol.
    void set_symbolic_value(const symbolic_var_t& var, const z3::expr& value);
    void set_symbolic_value(const mop_t& op, const z3::expr& value);

    // Forget current bindings while retaining fresh-name monotonicity.
    void invalidate_all_values();
    void invalidate_memory_values();
    void invalidate_values_if(
        const std::function<bool(const symbolic_var_t&)>& predicate);
    void invalidate_aliases(const symbolic_var_t& var);

    // Clear state (but keep context)
    void reset();

    // Get current context
    z3_context_t& context() { return m_ctx; }

private:
    // Convert mop_t to symbolic_var_t
    symbolic_var_t mop_to_var(const mop_t& op);

    // Size-aware operations
    z3::expr zero_extend(const z3::expr& e, int to_bits);
    z3::expr sign_extend(const z3::expr& e, int to_bits);
    z3::expr extract(const z3::expr& e, int high, int low);
    z3::expr resize(const z3::expr& e, int to_bits, bool sign_extend = false);

    z3_context_t& m_ctx;

    // Cache of variable -> Z3 expression mappings (using shared_ptr for non-default-constructible z3::expr)
    std::unordered_map<symbolic_var_t, std::shared_ptr<z3::expr>, symbolic_var_t::hash_t> m_var_cache;

    // Known constant values (from reading binary)
    std::unordered_map<symbolic_var_t, uint64_t, symbolic_var_t::hash_t> m_known_values;

    // Counter for fresh variable names
    int m_fresh_counter;
};

//--------------------------------------------------------------------------
// Symbolic Executor
//
// Performs symbolic execution over microcode blocks to track state values.
//--------------------------------------------------------------------------
class symbolic_executor_t {
public:
    explicit symbolic_executor_t(z3_context_t& ctx);

    // Execute a single instruction symbolically
    void execute_insn(const minsn_t* ins);

    // Execute an entire block symbolically
    void execute_block(const mblock_t* blk);

    // Read an operand through the executor's current bindings. Unlike
    // get_value(), this also translates nested expressions.
    z3::expr evaluate_operand(const mop_t& op, int default_size = 4);

    // Install a path invariant and keep it across call-clobber invalidation.
    // The caller must only preserve ABI/nonvolatile values it has proved.
    void set_value(const mop_t& op, const z3::expr& value,
                   bool preserve_across_calls = false);

    // Forget memory-backed bindings while retaining register invariants.
    void invalidate_memory_values();

    // Get symbolic value of a variable after execution
    std::optional<z3::expr> get_value(const mop_t& op);
    std::optional<z3::expr> get_value(const symbolic_var_t& var);

    // Try to solve for a specific variable value
    std::optional<uint64_t> solve_for_value(const z3::expr& expr);

    // Reset to initial state
    void reset();

private:
    // Handle assignment instructions
    void handle_assignment(const minsn_t* ins);

    // Handle memory operations
    void handle_load(const minsn_t* ins);
    void handle_store(const minsn_t* ins);

    z3_context_t& m_ctx;
    mcode_translator_t m_translator;

    // Current symbolic state: variable -> expression (using shared_ptr)
    std::unordered_map<symbolic_var_t, std::shared_ptr<z3::expr>, symbolic_var_t::hash_t> m_state;
    std::vector<symbolic_var_t> m_call_preserved;

};

//--------------------------------------------------------------------------
// State Machine Solver
//
// Specialized solver for control flow flattening. Analyzes the state
// variable transitions to determine the original CFG.
//--------------------------------------------------------------------------
class state_machine_solver_t {
public:
    explicit state_machine_solver_t(z3_context_t& ctx);

    // Analyze a potential dispatcher block
    struct dispatcher_analysis_t {
        bool is_dispatcher;
        int block_idx;
        symbolic_var_t state_var;
        std::map<uint64_t, int> state_to_block;  // state value -> target block
    };
    dispatcher_analysis_t analyze_dispatcher(mbl_array_t* mba, int block_idx);

    // Analyze a case block to determine its successor
    struct block_transition_t {
        int from_block;
        int to_block;              // -1 if conditional
        int to_block_true;         // For conditional transitions
        int to_block_false;        // For conditional transitions
        uint64_t next_state;       // State value written
        bool is_conditional;
        std::shared_ptr<z3::expr> condition;  // Branch condition (for conditional)
        bool solved;               // True if successfully analyzed

        block_transition_t() : from_block(-1), to_block(-1), to_block_true(-1),
                               to_block_false(-1), next_state(0), is_conditional(false),
                               solved(false) {}
    };
    block_transition_t analyze_block_transition(mbl_array_t* mba, int block_idx,
                                                 const symbolic_var_t& state_var);

    // Solve the complete state machine
    struct state_machine_t {
        std::vector<dispatcher_analysis_t> dispatchers;
        std::vector<block_transition_t> transitions;
        std::map<int, std::vector<int>> block_successors;  // Original CFG edges
        bool solved;
    };
    state_machine_t solve_state_machine(mbl_array_t* mba);

private:
    // Find all Hikari-style state constants in a block
    std::set<uint64_t> find_state_constants(const mblock_t* blk);

    // Determine what state value a block writes
    std::optional<uint64_t> determine_written_state(mbl_array_t* mba, int block_idx,
                                                     const symbolic_var_t& state_var);

    z3_context_t& m_ctx;
    mcode_translator_t m_translator;

    // Cached dispatcher analysis results
    std::map<int, dispatcher_analysis_t> m_dispatcher_cache;

};

//--------------------------------------------------------------------------
// Opaque Predicate Solver
//
// Uses Z3 to determine if a conditional expression is constant
// (always true or always false).
//--------------------------------------------------------------------------
class opaque_predicate_solver_t {
public:
    explicit opaque_predicate_solver_t(z3_context_t& ctx);

    // Check if a condition is an opaque predicate
    enum predicate_result_t {
        PRED_ALWAYS_TRUE,       // Condition is always true
        PRED_ALWAYS_FALSE,      // Condition is always false
        PRED_UNKNOWN,           // Not determinable (or depends on input)
        PRED_DEPENDS_ON_INPUT,  // Explicitly depends on unknown values
    };
    predicate_result_t analyze_condition(const minsn_t* cond);

private:
    z3_context_t& m_ctx;
    mcode_translator_t m_translator;
};

//--------------------------------------------------------------------------
// Z3 Predicate Simplifier
//
// Simplifies set/comparison instructions that evaluate to constants.
//--------------------------------------------------------------------------
class predicate_simplifier_t {
public:
    explicit predicate_simplifier_t(z3_context_t& ctx);

    // Check if setz/setnz result is constant
    std::optional<bool> simplify_setz(const minsn_t* ins);
    std::optional<bool> simplify_setnz(const minsn_t* ins);

    // Check if comparison is always true/false
    std::optional<bool> check_comparison_constant(mcode_t cmp_op,
                                                   const mop_t& left,
                                                   const mop_t& right);

    // Simplify conditional jump
    // Returns: 1 = always taken, 0 = never taken, -1 = unknown
    int simplify_jcc(const minsn_t* jcc);

private:
    z3_context_t& m_ctx;
    mcode_translator_t m_translator;
};

//--------------------------------------------------------------------------
// Global Z3 context management
//--------------------------------------------------------------------------

// Get the global Z3 context (lazy initialization)
z3_context_t& get_global_context();

// Reset global context (call between functions)
void reset_global_context();

// Set global timeout (milliseconds)
void set_global_timeout(unsigned ms);

//--------------------------------------------------------------------------
// Convenience functions
//--------------------------------------------------------------------------

} // namespace z3_solver
