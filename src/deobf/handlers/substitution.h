#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Substitution Simplification Handler
//
// Hikari's instruction substitution:
//   - Replaces simple ops with equivalent complex expressions
//   - ADD: b - ~c - 1, (b|c)+(b&c), (b^c)+2*(b&c), etc.
//   - SUB: b + ~c + 1, etc.
//   - AND: (b^~c)&b, etc.
//   - OR:  (b&c)|(b^c), etc.
//   - XOR: (~a&b)|(a&~b), etc.
//
// Detection:
//   - Complex arithmetic/logic expression chains
//   - Multiple operations that could be simplified to one
//   - NOT/NEG operations interleaved with arithmetic
//
// Reversal:
//   1. Pattern match known substitution templates
//   2. Extract original operands
//   3. Replace complex expression with simple op
//   4. Use expression simplification for edge cases
//--------------------------------------------------------------------------
class substitution_handler_t {
public:
    // Detection
    static bool detect(mbl_array_t *mba);

    // Main deobfuscation pass
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Instruction-level simplification (called from optinsn_t)
    static int simplify_insn(mblock_t *blk, minsn_t *ins, deobf_ctx_t *ctx);

private:
    // Substitution patterns
    enum subst_type_t {
        SUBST_NONE,
        SUBST_ADD_1,    // b - ~c - 1 => b + c
        SUBST_ADD_2,    // (b|c) + (b&c) => b + c
        SUBST_ADD_3,    // (b^c) + 2*(b&c) => b + c
        SUBST_ADD_NEG,  // b - (-c) => b + c
        SUBST_ADD_DNEG, // -(-b + -c) => b + c
        SUBST_SUB_1,    // b + ~c + 1 => b - c
        SUBST_SUB_NEG,  // b + (-c) => b - c
        SUBST_AND_1,    // (b ^ ~c) & b => b & c
        SUBST_AND_2,    // (b|c) & ~(b^c) => b & c
        SUBST_OR_1,     // (b&c) | (b^c) => b | c
        SUBST_XOR_1,    // (~a&b) | (a&~b) => a ^ b
        SUBST_XOR_2,    // (b+c) - 2*(b&c) => b ^ c
    };

    struct match_result_t {
        subst_type_t type;
        mop_t operand1;
        mop_t operand2;
    };

    // Try to match instruction against all patterns
    static bool try_match(minsn_t *ins, match_result_t *out);

    // Pattern-specific matchers
    static bool match_add_pattern_1(minsn_t *ins, match_result_t *out);  // b - ~c - 1
    static bool match_add_pattern_2(minsn_t *ins, match_result_t *out);  // (b|c) + (b&c)
    static bool match_add_pattern_3(minsn_t *ins, match_result_t *out);  // (b^c) + 2*(b&c)
    static bool match_sub_pattern_1(minsn_t *ins, match_result_t *out);  // b + ~c + 1
    static bool match_and_pattern_1(minsn_t *ins, match_result_t *out);  // (b ^ ~c) & b
    static bool match_or_pattern_1(minsn_t *ins, match_result_t *out);   // (b&c) | (b^c)
    static bool match_xor_pattern_1(minsn_t *ins, match_result_t *out);  // (~a&b) | (a&~b)
    static bool match_xor_pattern_2(minsn_t *ins, match_result_t *out);  // (b+c) - 2*(b&c)

    // Apply simplification
    static int apply_simplification(mblock_t *blk, minsn_t *ins, const match_result_t &match);

    // Helper: check if two mops represent the same value
    static bool same_value(const mop_t &a, const mop_t &b);

    // Helper: extract operand from NOT instruction
    static bool get_not_operand(const mop_t &m, mop_t *out);
};
