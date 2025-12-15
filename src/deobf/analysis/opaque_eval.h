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
//   2. Symbolically evaluate the expression
//   3. Determine if the condition is constant
//   4. Return the constant result
//--------------------------------------------------------------------------
class opaque_eval_t {
public:
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
