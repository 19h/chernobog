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

namespace chernobog
{
namespace ast
{

enum class AstBuildStatus
{
    Complete,
    NullInstruction,
    UnsupportedOperand,
    MalformedOperand,
    Cycle,
    DepthLimit,
    VisitLimit,
    TextLimit,
};

struct AstBuildReport
{
    AstBuildStatus status = AstBuildStatus::Complete;
    size_t visits = 0, instructions = 0, text_bytes = 0, maximum_depth = 0;
};

constexpr size_t ast_depth_limit = 64;
constexpr size_t ast_visit_limit = 1024;
constexpr size_t ast_text_limit = 4096;
constexpr size_t ast_total_text_limit = 65536;
const char *ast_build_status_name(AstBuildStatus status);

// Audit all owned operand payloads before hashing or any SDK operand copy.
// Repeated references consume visits; cyclic or excessive trees reject whole.
bool validate_ast_structure(const minsn_t *ins, AstBuildReport *report = nullptr);

//--------------------------------------------------------------------------
// Cache key for mop_t - OPTIMIZED
// Uses hash-based comparison to eliminate string allocations. A key match is
// only a candidate for reuse: nested instruction hashes can collide or omit
// metadata that the strict operand comparator retains.
// Scalar identity includes value numbers, properties, frame ownership and
// address-operand read/write extents.
//--------------------------------------------------------------------------
struct alignas(32) MopKey
{
    uint64_t hash;   // Pre-computed hash for fast comparison
    uint64_t value1; // Primary identifier (depends on type)
    uint64_t value2; // Secondary identifier / hash extension
    uint64_t frame;  // Parent mba_t identity, or packed address extents for mop_a
    int32_t size;    // Full SDK size, including NOSIZE and aggregate widths
    uint16_t type;   // mopt_t (fits in 16 bits)
    uint16_t valnum; // Zero is unknown; different numbers remain distinct
    uint8_t properties;
    bool complete = true; // Incomplete traversal keys are never cached

    static MopKey from_mop(const mop_t &mop, AstBuildReport *report = nullptr);

    // Compute hash for minsn_t (used for mop_d)
    static uint64_t hash_insn(const minsn_t *ins, AstBuildReport *report = nullptr);

    bool operator<(const MopKey &other) const
    {
        if (complete != other.complete)
            return complete < other.complete;
        // Compare hash first (most discriminating)
        if (hash != other.hash)
            return hash < other.hash;
        if (type != other.type)
            return type < other.type;
        if (value1 != other.value1)
            return value1 < other.value1;
        if (value2 != other.value2)
            return value2 < other.value2;
        if (size != other.size)
            return size < other.size;
        if (frame != other.frame)
            return frame < other.frame;
        if (valnum != other.valnum)
            return valnum < other.valnum;
        return properties < other.properties;
    }

    bool operator==(const MopKey &other) const
    {
        // Fast path: compare hash first (single comparison covers most cases)
        if (hash != other.hash)
            return false;
        // Full comparison for hash collision resolution
        return complete == other.complete && type == other.type && value1 == other.value1 &&
               value2 == other.value2 && size == other.size && frame == other.frame &&
               valnum == other.valnum && properties == other.properties;
    }

    // Hash function for unordered_map
    struct Hash
    {
        size_t operator()(const MopKey &k) const noexcept
        {
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
class AstBuilderContext
{
  public:
    AstBuilderContext()
    {
        // Reserve reasonable capacity to avoid rehashing
        mop_to_ast_.reserve(64);
    }

    // Check if mop is already in context
    SIMD_FORCE_INLINE bool has(const MopKey &key) const
    {
        return key.complete && mop_to_ast_.find(key) != mop_to_ast_.end();
    }

    // Get existing AST by key
    SIMD_FORCE_INLINE AstPtr get(const MopKey &key) const
    {
        if (!key.complete)
            return nullptr;
        auto p = mop_to_ast_.find(key);
        return (p != mop_to_ast_.end()) ? p->second : nullptr;
    }

    // Reuse a cached AST only when its copied SDK operand is structurally
    // equal to the source operand. A key collision may reduce deduplication,
    // but it must never merge two distinct value snapshots.
    SIMD_FORCE_INLINE AstPtr get_exact(const MopKey &key, const mop_t &source) const
    {
        AstPtr cached = get(key);
        return cached && mops_equal_strict(cached->mop, source) ? cached : nullptr;
    }

    // Add new AST to context
    SIMD_FORCE_INLINE void add(const MopKey &key, AstPtr ast)
    {
        if (key.complete)
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
AstPtr minsn_to_ast(const minsn_t *ins, AstBuildReport *report = nullptr);

//--------------------------------------------------------------------------
// Reverse conversion - AST back to microcode
//--------------------------------------------------------------------------

// Create new minsn_t from AST and variable bindings
// bindings maps variable names to actual mop_t values
minsn_t *ast_to_minsn(AstPtr ast, const std::map<std::string, mop_t> &bindings, mblock_t *blk,
                      ea_t ea);

// Create mop_t from AST leaf
mop_t ast_leaf_to_mop(AstLeafPtr leaf, const std::map<std::string, mop_t> &bindings,
                      int constant_size = 0);

} // namespace ast
} // namespace chernobog
