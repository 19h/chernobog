#pragma once
#include "ast.h"
#include <vector>
#include <set>

//--------------------------------------------------------------------------
// Pattern Fuzzer - Generates Equivalent Pattern Variants
//
// For pattern matching to be effective, we need to handle:
//   1. Commutative operations: x + y == y + x
//   2. Add/Sub equivalence: x + neg(y) == x - y
//   3. Associative restructuring: (a + b) + c == a + (b + c)
//
// This fuzzer generates all mathematically equivalent variants of a pattern,
// allowing robust matching regardless of how the obfuscator arranged operands.
//
// Example: Pattern `(x XOR y) + 2*(x AND y)` generates ~32 variants
//
// Ported from d810-ng's handler.py ast_generator function
//--------------------------------------------------------------------------

namespace chernobog {
namespace ast {

//--------------------------------------------------------------------------
// Commutative opcodes
//--------------------------------------------------------------------------
inline bool is_commutative(mcode_t op) {
    switch (op) {
        case m_add:
        case m_mul:
        case m_and:
        case m_or:
        case m_xor:
            return true;
        default:
            return false;
    }
}

// Add and Sub are related (sub is add with negation)
inline bool is_add_sub(mcode_t op) {
    return op == m_add || op == m_sub;
}

//--------------------------------------------------------------------------
// Pattern Fuzzer
//--------------------------------------------------------------------------
class PatternFuzzer {
public:
    // Generate all equivalent pattern variants
    // Returns vector including the original plus all fuzzed variants
    static std::vector<AstPtr> generate_variants(AstPtr pattern);

    // Configuration
    struct Config {
        bool fuzz_commutative = true;   // Reorder commutative operands
        bool fuzz_add_sub = false;      // Generate add/sub equivalences (DISABLED - slow)
        bool fuzz_associative = false;  // Restructure associative trees (DISABLED - slow)
        int max_variants = 16;          // Limit to prevent explosion (was 1000)
    };

    static void set_config(const Config& cfg);
    static const Config& get_config();

private:
    static Config config_;

    //----------------------------------------------------------------------
    // Core fuzzing functions
    //----------------------------------------------------------------------

    // Main recursive fuzzer
    static std::vector<AstPtr> fuzz_recursive(
        AstPtr node,
        const std::set<mcode_t>& excluded_ops);

    // Fuzz commutative operation (XOR, AND, OR, MUL)
    static std::vector<AstPtr> fuzz_commutative_op(
        AstPtr node,
        const std::set<mcode_t>& excluded_ops);

    // Fuzz add/sub operations (special handling due to interdependence)
    static std::vector<AstPtr> fuzz_add_sub_op(
        AstPtr node,
        const std::set<mcode_t>& excluded_ops);

    // Fuzz unary operation (just recurse on operand)
    static std::vector<AstPtr> fuzz_unary_op(
        AstPtr node,
        const std::set<mcode_t>& excluded_ops);

    //----------------------------------------------------------------------
    // Operand extraction and tree building
    //----------------------------------------------------------------------

    // Operand with sign (for add/sub flattening)
    struct SignedOperand {
        AstPtr operand;
        bool is_negated;  // True if this operand is subtracted

        SignedOperand(AstPtr op, bool neg = false)
            : operand(op), is_negated(neg) {}
    };

    // Extract operands from chained same-opcode operations
    // e.g., add(add(x, y), z) -> [x, y, z]
    static std::vector<AstPtr> get_flat_operands(AstPtr node, mcode_t op);

    // Extract operands from add/sub chain with sign tracking
    // e.g., sub(add(x, y), z) -> [(x, +), (y, +), (z, -)]
    static std::vector<SignedOperand> get_add_sub_operands(AstPtr node);

    // Build all possible binary tree structures from flat operand list
    static std::vector<AstPtr> build_all_binary_trees(
        const std::vector<AstPtr>& operands,
        mcode_t op);

    // Build all add/sub trees from signed operand list
    static std::vector<AstPtr> build_add_sub_trees(
        const std::vector<SignedOperand>& operands);

    //----------------------------------------------------------------------
    // Add/Sub equivalence transformations
    //----------------------------------------------------------------------

    // Generate add/sub variations: x + neg(y) <-> x - y
    static std::vector<AstPtr> get_add_sub_variations(
        mcode_t op, AstPtr left, AstPtr right);

    //----------------------------------------------------------------------
    // Utility
    //----------------------------------------------------------------------

    // Generate all permutations of operands
    static std::vector<std::vector<AstPtr>> permute(
        const std::vector<AstPtr>& operands);

    // Generate all permutations of signed operands
    static std::vector<std::vector<SignedOperand>> permute_signed(
        const std::vector<SignedOperand>& operands);

    // Deduplicate variants by structure
    static std::vector<AstPtr> deduplicate(const std::vector<AstPtr>& variants);
};

} // namespace ast
} // namespace chernobog
