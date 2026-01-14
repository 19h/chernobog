#pragma once
#include "../deobf_types.h"
#include "../../common/simd.h"
#include <vector>
#include <set>

//--------------------------------------------------------------------------
// Chain Simplification - OPTIMIZED
//
// Handles flattening of chains of same-opcode operations and detecting
// identities that simplify to constants or single operands.
//
// Key identities:
//   XOR: x ^ x = 0, x ^ 0 = x, c1 ^ c2 = (c1 ^ c2)
//   AND: x & x = x, x & 0 = 0, x & ~x = 0, x & -1 = x
//   OR:  x | x = x, x | 0 = x, x | ~x = -1
//   ADD: x + (-x) = 0, x + 0 = x
//
// OPTIMIZATIONS:
//   - SmallVector to avoid heap allocation for typical chains
//   - SIMD-accelerated operand comparison
//   - Prefetching for O(n²) identity removal
//
// Ported from d810-ng's chain_simplification logic
//--------------------------------------------------------------------------

namespace chernobog {
namespace chain {

// Maximum operands typically seen in a chain
constexpr size_t TYPICAL_CHAIN_SIZE = 16;

//--------------------------------------------------------------------------
// Operand tracking for chain analysis
// Aligned for SIMD operations
//--------------------------------------------------------------------------
struct alignas(16) chain_operand_t {
    mop_t mop;
    bool is_negated;  // For XOR: ~x, for ADD: -x
    uint8_t _pad[7];  // Alignment padding

    chain_operand_t() : is_negated(false) {}
    chain_operand_t(const mop_t& m, bool neg = false)
        : mop(m), is_negated(neg) {}
};

//--------------------------------------------------------------------------
// Result of chain analysis
//--------------------------------------------------------------------------
struct chain_result_t {
    bool simplified;

    // Non-constant operands remaining after simplification
    std::vector<chain_operand_t> operands;

    // Merged constant value (result of folding all constants)
    uint64_t const_result;
    bool has_const;

    // Identity detected (e.g., x ^ x)
    bool has_identity;

    // Result is a single operand
    bool is_single_operand;

    // Result is zero
    bool is_zero;

    // Result is all ones (-1)
    bool is_all_ones;

    chain_result_t()
        : simplified(false), const_result(0), has_const(false),
          has_identity(false), is_single_operand(false),
          is_zero(false), is_all_ones(false) {}
};

//--------------------------------------------------------------------------
// Chain Simplifier
//--------------------------------------------------------------------------
class ChainSimplifier {
public:
    // Analyze and simplify XOR chain: x ^ y ^ z ^ ...
    static chain_result_t analyze_xor_chain(mblock_t* blk, minsn_t* ins);

    // Analyze and simplify AND chain: x & y & z & ...
    static chain_result_t analyze_and_chain(mblock_t* blk, minsn_t* ins);

    // Analyze and simplify OR chain: x | y | z | ...
    static chain_result_t analyze_or_chain(mblock_t* blk, minsn_t* ins);

    // Analyze and simplify ADD chain: x + y + z + ...
    static chain_result_t analyze_add_chain(mblock_t* blk, minsn_t* ins);

    // Apply simplification to instruction
    // Returns 1 if simplified, 0 otherwise
    static int simplify_chain(mblock_t* blk, minsn_t* ins);

private:
    // Extract all operands from nested same-opcode tree
    static void flatten_chain(const minsn_t* ins, mcode_t target_op,
                             std::vector<chain_operand_t>& operands,
                             std::vector<uint64_t>& constants,
                             int size);

    // Flatten operand (handles nested instructions)
    static void flatten_operand(const mop_t& mop, mcode_t target_op,
                               std::vector<chain_operand_t>& operands,
                               std::vector<uint64_t>& constants,
                               int size);

    // Find and remove identity pairs (x ^ x, x & ~x, etc.)
    static bool remove_identity_pairs(std::vector<chain_operand_t>& operands,
                                      mcode_t op, int size);

    // Check if two operands are the same
    static bool operands_equal(const mop_t& a, const mop_t& b);

    // Check if operand is NOT of another
    static bool is_not_of(const mop_t& a, const mop_t& b);

    // Check if operand is NEG of another
    static bool is_neg_of(const mop_t& a, const mop_t& b);

    // Get constant value from mop
    static bool get_const_value(const mop_t& mop, uint64_t* out);

    // Build simplified instruction from result
    static minsn_t* build_simplified(mblock_t* blk, minsn_t* orig,
                                     const chain_result_t& result,
                                     mcode_t op);

    // Get identity element for operation (0 for XOR/ADD/OR, -1 for AND)
    static uint64_t get_identity_element(mcode_t op, int size);

    // Get absorbing element for operation (0 for AND, -1 for OR)
    static bool has_absorbing_element(mcode_t op, uint64_t* out, int size);
};

//--------------------------------------------------------------------------
// Chain Simplify Handler - integrates with deobfuscation pipeline
//--------------------------------------------------------------------------
class chain_simplify_handler_t {
public:
    // Detect if chain patterns are present
    static bool detect(mbl_array_t* mba);

    // Run chain simplification pass
    static int run(mbl_array_t* mba, deobf_ctx_t* ctx);

    // Instruction-level simplification
    static int simplify_insn(mblock_t* blk, minsn_t* ins, deobf_ctx_t* ctx);
};

} // namespace chain
} // namespace chernobog
