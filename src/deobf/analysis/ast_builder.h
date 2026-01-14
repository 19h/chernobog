#pragma once
#include "ast.h"
#include "../../common/simd.h"
#include <unordered_map>
#include <mutex>

//--------------------------------------------------------------------------
// AST Builder - Converts IDA microcode to AST representation
//
// Features:
//   - Recursive conversion of mop_t and minsn_t to AST
//   - Deduplication context to prevent exponential explosion
//   - Global LRU cache for converted ASTs
//   - Thread-safe cache access
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

    // Get or create AST for mop, with deduplication
    AstPtr get_or_create(const mop_t& mop);

    // Check if mop is already in context
    SIMD_FORCE_INLINE bool has(const MopKey& key) const {
        return mop_to_ast_.find(key) != mop_to_ast_.end();
    }

    // Get existing AST by key
    SIMD_FORCE_INLINE AstPtr get(const MopKey& key) const {
        auto it = mop_to_ast_.find(key);
        return (it != mop_to_ast_.end()) ? it->second : nullptr;
    }

    // Add new AST to context
    SIMD_FORCE_INLINE void add(const MopKey& key, AstPtr ast) {
        ast->ast_index = next_index_++;
        mop_to_ast_.emplace(key, std::move(ast));
    }

    // Clear the context
    void clear() {
        mop_to_ast_.clear();
        next_index_ = 0;
    }

private:
    std::unordered_map<MopKey, AstPtr, MopKey::Hash> mop_to_ast_;
    int next_index_ = 0;
};

//--------------------------------------------------------------------------
// Global AST cache with LRU eviction
// OPTIMIZED: Uses unordered_map with pre-computed hash for O(1) lookup
//--------------------------------------------------------------------------
class AstCache {
public:
    static constexpr size_t MAX_CACHE_SIZE = 20480;
    static constexpr size_t EVICTION_BATCH = MAX_CACHE_SIZE / 10;

    static AstCache& instance();

    // Get cached AST (returns nullptr if not cached)
    AstPtr get(const MopKey& key);

    // Add AST to cache (freezes the AST)
    void put(const MopKey& key, AstPtr ast);

    // Clear cache
    void clear();

    // Get cache statistics
    size_t size() const { return cache_.size(); }
    size_t hits() const { return hit_count_; }
    size_t misses() const { return miss_count_; }

private:
    AstCache() {
        // Reserve capacity to minimize rehashing
        cache_.reserve(MAX_CACHE_SIZE);
    }

    std::mutex mutex_;
    std::unordered_map<MopKey, AstPtr, MopKey::Hash> cache_;
    size_t hit_count_ = 0;
    size_t miss_count_ = 0;

    // Simple eviction: remove entries when full
    void evict_if_needed();
};

//--------------------------------------------------------------------------
// Main conversion functions
//--------------------------------------------------------------------------

// Convert microcode instruction to AST
// Returns nullptr if instruction cannot be converted (non-MBA opcode)
AstPtr minsn_to_ast(const minsn_t* ins);

// Convert microcode operand to AST
// Uses global cache for performance
AstPtr mop_to_ast(const mop_t& mop);

// Convert with explicit context (for recursive building)
AstPtr mop_to_ast_with_context(const mop_t& mop, AstBuilderContext& ctx);

// Convert instruction with explicit context
AstPtr minsn_to_ast_with_context(const minsn_t* ins, AstBuilderContext& ctx);

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
                      const std::map<std::string, mop_t>& bindings);

//--------------------------------------------------------------------------
// Cache management
//--------------------------------------------------------------------------

// Clear all AST caches (call on function change)
void clear_ast_caches();

// Get cache statistics
struct AstCacheStats {
    size_t cache_size;
    size_t hit_count;
    size_t miss_count;
    double hit_rate;
};
AstCacheStats get_ast_cache_stats();

} // namespace ast
} // namespace chernobog
