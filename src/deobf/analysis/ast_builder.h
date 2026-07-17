#pragma once
#include "ast.h"
#include "../../common/simd.h"
#include <unordered_map>

//--------------------------------------------------------------------------
// AST Builder - Converts IDA microcode to AST representation
//
// Features:
//   - Recursive conversion of mop_t and minsn_t to AST
//   - Deduplication context to prevent exponential explosion
//   - OPTIMIZED: Hash-based key comparison, no string allocations
//
// Ported from d810-ng's tracker.py with C++ optimizations
//--------------------------------------------------------------------------

namespace chernobog {
namespace ast {

//--------------------------------------------------------------------------
// Cache key for mop_t - OPTIMIZED
// Uses hash-based comparison to eliminate string allocations and comparisons.
// The key is designed to fit in 32 bytes for cache efficiency.
//--------------------------------------------------------------------------
struct alignas(32) MopKey {
    uint64_t hash;          // Pre-computed hash for fast comparison
    uint64_t value1;        // Primary identifier (depends on type)
    uint64_t value2;        // Secondary identifier / hash extension
    uint16_t type;          // mopt_t (fits in 16 bits)
    uint16_t size;          // operand size
    uint32_t _pad;          // Alignment padding

    static MopKey from_mop(const mop_t& mop);
    
    // Compute hash for minsn_t (used for mop_d)
    static uint64_t hash_insn(const minsn_t* ins);

    bool operator<(const MopKey& other) const {
        // Compare hash first (most discriminating)
        if (hash != other.hash) return hash < other.hash;
        if (type != other.type) return type < other.type;
        if (value1 != other.value1) return value1 < other.value1;
        if (value2 != other.value2) return value2 < other.value2;
        return size < other.size;
    }
    
    bool operator==(const MopKey& other) const {
        // Fast path: compare hash first (single comparison covers most cases)
        if (hash != other.hash) return false;
        // Full comparison for hash collision resolution
        return type == other.type && 
               value1 == other.value1 && 
               value2 == other.value2 &&
               size == other.size;
    }

    // Hash function for unordered_map
    struct Hash {
        size_t operator()(const MopKey& k) const noexcept {
            // Hash is pre-computed, just return it
            return static_cast<size_t>(k.hash);
        }
    };
};

//--------------------------------------------------------------------------
// Deduplication context for AST building
// Prevents exponential explosion when same mop appears multiple times
// OPTIMIZED: Uses unordered_map with pre-computed hash for O(1) lookup
//--------------------------------------------------------------------------
class AstBuilderContext {
public:
    AstBuilderContext() {
        // Reserve reasonable capacity to avoid rehashing
        mop_to_ast_.reserve(64);
    }

    // Check if mop is already in context
    SIMD_FORCE_INLINE bool has(const MopKey& key) const {
        return mop_to_ast_.find(key) != mop_to_ast_.end();
    }

    // Get existing AST by key
    SIMD_FORCE_INLINE AstPtr get(const MopKey& key) const {
        auto p = mop_to_ast_.find(key);
        return ( p != mop_to_ast_.end() ) ? p->second : nullptr;
    }

    // Add new AST to context
    SIMD_FORCE_INLINE void add(const MopKey& key, AstPtr ast) {
        mop_to_ast_.emplace(key, std::move(ast));
    }

private:
    std::unordered_map<MopKey, AstPtr, MopKey::Hash> mop_to_ast_;
};

//--------------------------------------------------------------------------
// Main conversion functions
//--------------------------------------------------------------------------

// Convert microcode instruction to AST
// Returns nullptr if instruction cannot be converted (non-MBA opcode)
AstPtr minsn_to_ast(const minsn_t* ins);

//--------------------------------------------------------------------------
// Reverse conversion - AST back to microcode
//--------------------------------------------------------------------------

// Create new minsn_t from AST and variable bindings
// bindings maps variable names to actual mop_t values
minsn_t* ast_to_minsn(AstPtr ast,
                      const std::map<std::string, mop_t>& bindings,
                      mblock_t* blk,
                      ea_t ea);

// Create mop_t from AST leaf
mop_t ast_leaf_to_mop(AstLeafPtr leaf,
                      const std::map<std::string, mop_t>& bindings,
                      int constant_size = 0);

} // namespace ast
} // namespace chernobog
