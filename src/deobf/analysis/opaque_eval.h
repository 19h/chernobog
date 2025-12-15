#pragma once
#include "../deobf_types.h"
#include <map>
#include <optional>

//--------------------------------------------------------------------------
// Opaque Predicate Evaluator
//
// Evaluates complex boolean expressions that use global constants.
// These are commonly used in Hikari-style obfuscation where:
//   - Global constants are loaded: dword_XXX, dword_YYY
//   - Complex expressions are computed: ~(~a | ~b) & mask ...
//   - Results are compared to determine branch direction
//   - The expression ALWAYS evaluates to the same result
//
// Approach:
//   1. Read actual values of global constants from binary
//   2. Symbolically evaluate the expression using Z3 when needed
//   3. Determine if the condition is constant
//   4. Return the constant result
//
// The evaluator uses a two-tier approach:
//   - Tier 1: Fast constant propagation for simple expressions
//   - Tier 2: Z3 SMT solver for complex/symbolic expressions
//--------------------------------------------------------------------------
class opaque_eval_t {
public:
    //----------------------------------------------------------------------
    // Result types for detailed analysis
    //----------------------------------------------------------------------
    enum eval_status_t {
        EVAL_SUCCESS,           // Successfully evaluated
        EVAL_UNKNOWN,           // Could not determine
        EVAL_TIMEOUT,           // Z3 solver timed out
        EVAL_COMPLEX,           // Too complex, gave up
    };

    struct eval_result_t {
        eval_status_t status;
        bool is_constant;       // True if expression is constant
        uint64_t value;         // The constant value (if is_constant)
        std::string reason;     // Human-readable explanation

        eval_result_t() : status(EVAL_UNKNOWN), is_constant(false), value(0) {}
        static eval_result_t success(uint64_t v) {
            eval_result_t r;
            r.status = EVAL_SUCCESS;
            r.is_constant = true;
            r.value = v;
            return r;
        }
        static eval_result_t unknown(const std::string& reason = "") {
            eval_result_t r;
            r.status = EVAL_UNKNOWN;
            r.reason = reason;
            return r;
        }
    };

    //----------------------------------------------------------------------
    // Primary API
    //----------------------------------------------------------------------

    // Evaluate a microcode condition expression
    // Returns: true if constant, with result in *out_result
    static bool evaluate_condition(minsn_t *cond, bool *out_result);

    // Evaluate an arbitrary microcode expression to a constant
    // Returns: optional containing the value if constant
    static std::optional<uint64_t> evaluate_expr(minsn_t *expr);
    static std::optional<uint64_t> evaluate_operand(const mop_t &op);

    // Read a global constant from the binary
    static std::optional<uint64_t> read_global(ea_t addr, int size);

    // Clear cache (call when analyzing new function)
    static void clear_cache();

    //----------------------------------------------------------------------
    // Z3-enhanced API
    //----------------------------------------------------------------------

    // Evaluate with detailed result information
    static eval_result_t evaluate_detailed(minsn_t *expr);

    // Check if condition is an opaque predicate using Z3
    // Returns: ALWAYS_TRUE, ALWAYS_FALSE, or UNKNOWN
    enum opaque_result_t {
        OPAQUE_ALWAYS_TRUE,
        OPAQUE_ALWAYS_FALSE,
        OPAQUE_NOT_OPAQUE,      // Depends on input
        OPAQUE_UNKNOWN,         // Could not determine
    };
    static opaque_result_t check_opaque_predicate(minsn_t *cond);

    // Prove two expressions are equivalent using Z3
    static bool prove_equivalent(minsn_t *a, minsn_t *b);

    // Simplify expression using Z3 and return simplified form if possible
    static std::optional<uint64_t> z3_simplify(minsn_t *expr);

    //----------------------------------------------------------------------
    // Configuration
    //----------------------------------------------------------------------

    // Enable/disable Z3 backend (default: enabled)
    static void set_z3_enabled(bool enabled);
    static bool is_z3_enabled();

    // Set Z3 timeout in milliseconds (default: 1000ms)
    static void set_z3_timeout(unsigned ms);

private:
    // Evaluation state - tracks values during evaluation
    struct eval_state_t {
        std::map<ea_t, uint64_t> globals;     // Cached global values
        std::map<int, uint64_t> temps;         // Temporary values (mreg)
        int depth;                             // Recursion depth
    };

    // Core evaluation functions
    static std::optional<uint64_t> eval_insn(minsn_t *ins, eval_state_t &state);
    static std::optional<uint64_t> eval_mop(const mop_t &op, eval_state_t &state);

    // Arithmetic/logic operations
    static std::optional<uint64_t> eval_add(uint64_t a, uint64_t b, int size);
    static std::optional<uint64_t> eval_sub(uint64_t a, uint64_t b, int size);
    static std::optional<uint64_t> eval_mul(uint64_t a, uint64_t b, int size);
    static std::optional<uint64_t> eval_udiv(uint64_t a, uint64_t b, int size);
    static std::optional<uint64_t> eval_sdiv(int64_t a, int64_t b, int size);
    static std::optional<uint64_t> eval_umod(uint64_t a, uint64_t b, int size);
    static std::optional<uint64_t> eval_smod(int64_t a, int64_t b, int size);

    static std::optional<uint64_t> eval_and(uint64_t a, uint64_t b, int size);
    static std::optional<uint64_t> eval_or(uint64_t a, uint64_t b, int size);
    static std::optional<uint64_t> eval_xor(uint64_t a, uint64_t b, int size);
    static std::optional<uint64_t> eval_not(uint64_t a, int size);
    static std::optional<uint64_t> eval_neg(uint64_t a, int size);

    static std::optional<uint64_t> eval_shl(uint64_t a, uint64_t b, int size);
    static std::optional<uint64_t> eval_shr(uint64_t a, uint64_t b, int size);
    static std::optional<uint64_t> eval_sar(int64_t a, uint64_t b, int size);

    // Comparison operations
    static std::optional<bool> eval_setz(uint64_t a);
    static std::optional<bool> eval_setnz(uint64_t a);
    static std::optional<bool> eval_setl(int64_t a, int64_t b);
    static std::optional<bool> eval_setle(int64_t a, int64_t b);
    static std::optional<bool> eval_setg(int64_t a, int64_t b);
    static std::optional<bool> eval_setge(int64_t a, int64_t b);
    static std::optional<bool> eval_setb(uint64_t a, uint64_t b);
    static std::optional<bool> eval_setbe(uint64_t a, uint64_t b);
    static std::optional<bool> eval_seta(uint64_t a, uint64_t b);
    static std::optional<bool> eval_setae(uint64_t a, uint64_t b);

    // Mask value by size
    static uint64_t mask_by_size(uint64_t val, int size);
    static int64_t sign_extend(uint64_t val, int size);

    // Global cache
    static std::map<ea_t, uint64_t> s_global_cache;
    static constexpr int MAX_EVAL_DEPTH = 100;
};
