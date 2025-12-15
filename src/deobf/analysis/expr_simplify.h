#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Expression simplification using algebraic rules and optionally Z3
// This handles the Hikari substitution patterns
//--------------------------------------------------------------------------
namespace expr_simplify {

// Result of simplification attempt
struct simplify_result_t {
    bool simplified;
    mcode_t new_opcode;     // Simplified opcode (if applicable)
    mop_t new_left;         // Simplified left operand
    mop_t new_right;        // Simplified right operand
    uint64_t const_result;  // If entire expression folds to constant
    bool is_const;

    simplify_result_t() : simplified(false), new_opcode(m_nop),
                         const_result(0), is_const(false) {}
};

// Main simplification entry point
simplify_result_t simplify_instruction(minsn_t *insn, deobf_ctx_t *ctx);

// Try to simplify the operand tree rooted at this mop
simplify_result_t simplify_mop(const mop_t &mop, deobf_ctx_t *ctx);

// Algebraic simplification rules
bool try_simplify_add(minsn_t *insn, simplify_result_t *out);
bool try_simplify_sub(minsn_t *insn, simplify_result_t *out);
bool try_simplify_and(minsn_t *insn, simplify_result_t *out);
bool try_simplify_or(minsn_t *insn, simplify_result_t *out);
bool try_simplify_xor(minsn_t *insn, simplify_result_t *out);
bool try_simplify_mul(minsn_t *insn, simplify_result_t *out);

// Pattern-specific simplifiers for Hikari substitutions
bool simplify_hikari_add_pattern1(minsn_t *insn, simplify_result_t *out);  // b - ~c - 1 => b + c
bool simplify_hikari_add_pattern2(minsn_t *insn, simplify_result_t *out);  // (b|c) + (b&c) => b + c
bool simplify_hikari_add_pattern3(minsn_t *insn, simplify_result_t *out);  // (b^c) + 2*(b&c) => b + c
bool simplify_hikari_sub_pattern1(minsn_t *insn, simplify_result_t *out);  // b + ~c + 1 => b - c
bool simplify_hikari_and_pattern1(minsn_t *insn, simplify_result_t *out);  // (b ^ ~c) & b => b & c
bool simplify_hikari_or_pattern1(minsn_t *insn, simplify_result_t *out);   // (b&c) | (b^c) => b | c
bool simplify_hikari_xor_pattern1(minsn_t *insn, simplify_result_t *out);  // (~a&b) | (a&~b) => a ^ b

// Constant propagation through XOR chains (for encrypted constants)
std::optional<uint64_t> trace_xor_chain(const mop_t &mop, deobf_ctx_t *ctx);

// Check if two mops are semantically equivalent
bool mops_equal(const mop_t &a, const mop_t &b);

// Create a new mop from simplified result
mop_t make_mop_from_const(uint64_t val, int size);
mop_t make_mop_from_binop(mcode_t op, const mop_t &left, const mop_t &right);

} // namespace expr_simplify
