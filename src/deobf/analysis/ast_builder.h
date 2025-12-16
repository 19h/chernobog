#pragma once
#include "ast.h"
#include <map>
#include <mutex>

//--------------------------------------------------------------------------
// AST Builder - Converts IDA microcode to AST representation
//
// Features:
//   - Recursive conversion of mop_t and minsn_t to AST
//   - Deduplication context to prevent exponential explosion
//   - Global LRU cache for converted ASTs
//   - Thread-safe cache access
//
// Ported from d810-ng's tracker.py with C++ optimizations
//--------------------------------------------------------------------------

namespace chernobog {
namespace ast {

//--------------------------------------------------------------------------
// Cache key for mop_t
// Intentionally drops SSA valnum for non-constants to enable pattern reuse
//--------------------------------------------------------------------------
struct MopKey {
    mopt_t type;
    int size;
    uint64_t value1;        // Primary identifier (depends on type)
    uint64_t value2;        // Secondary identifier (optional)
    std::string str_value;  // For string-based keys (mop_d)

    static MopKey from_mop(const mop_t& mop);

    bool operator<(const MopKey& other) const;
    bool operator==(const MopKey& other) const;

    // Hash function for unordered_map
    struct Hash {
        size_t operator()(const MopKey& k) const;
    };
};

//--------------------------------------------------------------------------
// Deduplication context for AST building
// Prevents exponential explosion when same mop appears multiple times
//--------------------------------------------------------------------------
class AstBuilderContext {
public:
    AstBuilderContext() = default;

    // Get or create AST for mop, with deduplication
    AstPtr get_or_create(const mop_t& mop);

    // Check if mop is already in context
    bool has(const MopKey& key) const;

    // Get existing AST by key
    AstPtr get(const MopKey& key) const;

    // Add new AST to context
    void add(const MopKey& key, AstPtr ast);

    // Clear the context
    void clear();

private:
    std::map<MopKey, AstPtr> mop_to_ast;
    int next_index = 0;
};

//--------------------------------------------------------------------------
// Global AST cache with LRU eviction
//--------------------------------------------------------------------------
class AstCache {
public:
    static constexpr size_t MAX_CACHE_SIZE = 20480;

    static AstCache& instance();

    // Get cached AST (returns nullptr if not cached)
    AstPtr get(const MopKey& key);

    // Add AST to cache (freezes the AST)
    void put(const MopKey& key, AstPtr ast);

    // Clear cache
    void clear();

    // Get cache statistics
    size_t size() const;
    size_t hits() const { return hit_count; }
    size_t misses() const { return miss_count; }

private:
    AstCache() = default;

    std::mutex mutex;
    std::map<MopKey, AstPtr> cache;
    size_t hit_count = 0;
    size_t miss_count = 0;

    // Simple eviction: remove oldest entries when full
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
