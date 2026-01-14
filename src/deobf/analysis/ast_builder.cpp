#include "ast_builder.h"
#include "../../common/simd.h"

namespace chernobog {
namespace ast {

//--------------------------------------------------------------------------
// MopKey implementation - OPTIMIZED
// Uses pre-computed hash to eliminate string allocations and enable O(1) lookup
//--------------------------------------------------------------------------

// Hash an instruction structure recursively (for mop_d operands)
uint64_t MopKey::hash_insn(const minsn_t* ins) {
    if (!ins) return 0;
    
    // Combine opcode, operand info, and recursive structure
    uint64_t h = simd::hash_u64(static_cast<uint64_t>(ins->opcode));
    
    // Hash left operand
    if (ins->l.t != mop_z) {
        MopKey left_key = from_mop(ins->l);
        h = simd::hash_combine(h, left_key.hash);
    }
    
    // Hash right operand
    if (ins->r.t != mop_z) {
        MopKey right_key = from_mop(ins->r);
        h = simd::hash_combine(h, right_key.hash);
    }
    
    // Include destination size
    h = simd::hash_combine(h, static_cast<uint64_t>(ins->d.size));
    
    return h;
}

MopKey MopKey::from_mop(const mop_t& mop) {
    MopKey key;
    key.type = static_cast<uint16_t>(mop.t);
    key.size = static_cast<uint16_t>(mop.size);
    key.value1 = 0;
    key.value2 = 0;
    key._pad = 0;

    switch (mop.t) {
        case mop_n:  // Number constant
            if (mop.nnn) {
                key.value1 = mop.nnn->value;
                // Include original value for constants to distinguish different occurrences
                key.value2 = mop.nnn->org_value;
            }
            break;

        case mop_r:  // Register
            key.value1 = mop.r;
            break;

        case mop_S:  // Stack variable
            if (mop.s) {
                key.value1 = static_cast<uint64_t>(mop.s->off);
            }
            break;

        case mop_v:  // Global variable
            key.value1 = mop.g;
            break;

        case mop_l:  // Local variable
            if (mop.l) {
                key.value1 = mop.l->idx;
                key.value2 = mop.l->off;
            }
            break;

        case mop_d:  // Result of another instruction
            // OPTIMIZED: Hash instruction structure instead of string
            if (mop.d) {
                key.value1 = hash_insn(mop.d);
                // Use secondary hash for collision resistance
                key.value2 = simd::hash_combine(
                    static_cast<uint64_t>(mop.d->opcode),
                    static_cast<uint64_t>(mop.d->ea)
                );
            }
            break;

        case mop_b:  // Block reference
            key.value1 = mop.b;
            break;

        case mop_a:  // Address operand
            if (mop.a) {
                MopKey inner = from_mop(*mop.a);
                key.value1 = inner.hash;  // Use inner hash
                key.value2 = inner.value1;
            }
            break;

        case mop_h:  // Helper function
            if (mop.helper) {
                key.value1 = simd::hash_bytes(mop.helper, strlen(mop.helper));
            }
            break;

        case mop_str:  // String
            if (mop.cstr) {
                key.value1 = simd::hash_bytes(mop.cstr, strlen(mop.cstr));
            }
            break;

        default:
            break;
    }

    // Compute final hash combining all fields
    key.hash = simd::hash_u64(key.type);
    key.hash = simd::hash_combine(key.hash, simd::hash_u64(key.size));
    key.hash = simd::hash_combine(key.hash, simd::hash_u64(key.value1));
    key.hash = simd::hash_combine(key.hash, simd::hash_u64(key.value2));

    return key;
}

//--------------------------------------------------------------------------
// AstBuilderContext implementation - OPTIMIZED
// Uses unordered_map with pre-computed hash for O(1) lookup
//--------------------------------------------------------------------------
AstPtr AstBuilderContext::get_or_create(const mop_t& mop) {
    MopKey key = MopKey::from_mop(mop);
    
    // O(1) lookup with pre-computed hash
    auto it = mop_to_ast_.find(key);
    if (it != mop_to_ast_.end()) {
        return it->second;
    }

    // Will be created by caller and added
    return nullptr;
}

//--------------------------------------------------------------------------
// AstCache implementation - OPTIMIZED
// Uses unordered_map with pre-computed hash for O(1) lookup
// Features:
//   - Prefetching hints for hot path
//   - Batch eviction to amortize cost
//   - Lock-free read path (future: reader-writer lock)
//--------------------------------------------------------------------------
AstCache& AstCache::instance() {
    static AstCache inst;
    return inst;
}

AstPtr AstCache::get(const MopKey& key) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Prefetch likely bucket location based on hash
    size_t bucket = cache_.bucket(key);
    if (bucket < cache_.bucket_count()) {
        // Prefetch bucket memory for faster iteration
        auto bucket_begin = cache_.begin(bucket);
        if (bucket_begin != cache_.end(bucket)) {
            SIMD_PREFETCH_READ(&(*bucket_begin));
        }
    }

    auto it = cache_.find(key);
    if (SIMD_LIKELY(it != cache_.end())) {
        hit_count_++;
        // Return a mutable copy (the cached one is frozen)
        return it->second->clone();
    }

    miss_count_++;
    return nullptr;
}

void AstCache::put(const MopKey& key, AstPtr ast) {
    std::lock_guard<std::mutex> lock(mutex_);

    evict_if_needed();

    // Freeze and cache
    ast->freeze();
    cache_.emplace(key, std::move(ast));
}

void AstCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
    hit_count_ = 0;
    miss_count_ = 0;
}

void AstCache::evict_if_needed() {
    // Simple eviction: remove EVICTION_BATCH entries when full
    // Use batch eviction to amortize the cost of resizing
    if (SIMD_UNLIKELY(cache_.size() >= MAX_CACHE_SIZE)) {
        // Remove entries from the front (pseudo-FIFO)
        auto it = cache_.begin();
        for (size_t i = 0; i < EVICTION_BATCH && it != cache_.end(); i++) {
            it = cache_.erase(it);
        }
    }
}

//--------------------------------------------------------------------------
// Internal conversion functions
//--------------------------------------------------------------------------
static AstPtr mop_to_ast_internal(const mop_t& mop, AstBuilderContext& ctx, bool use_cache);

// Convert instruction operand (which may be another instruction)
static AstPtr convert_mop_d(const minsn_t* ins, AstBuilderContext& ctx) {
    if (!ins || !is_mba_opcode(ins->opcode)) {
        return nullptr;
    }

    // Convert left operand
    AstPtr left = nullptr;
    if (ins->l.t != mop_z) {
        left = mop_to_ast_internal(ins->l, ctx, false);
        if (!left) {
            // Create a leaf for non-convertible operand
            left = std::make_shared<AstLeaf>(ins->l);
        }
    }

    // Convert right operand (for binary ops)
    AstPtr right = nullptr;
    if (ins->r.t != mop_z) {
        right = mop_to_ast_internal(ins->r, ctx, false);
        if (!right) {
            right = std::make_shared<AstLeaf>(ins->r);
        }
    }

    // Create node
    auto node = std::make_shared<AstNode>(ins->opcode, left, right);
    node->ea = ins->ea;
    node->dest_size = ins->d.size;
    node->dst_mop = ins->d;

    return node;
}

static AstPtr mop_to_ast_internal(const mop_t& mop, AstBuilderContext& ctx, bool use_cache) {
    if (mop.t == mop_z) {
        return nullptr;
    }

    MopKey key = MopKey::from_mop(mop);

    // Check context first (deduplication)
    if (ctx.has(key)) {
        return ctx.get(key);
    }

    // NOTE: Global cache is DISABLED because freeze() erases mop fields,
    // and the cloned AST nodes have mop_z which breaks pattern matching.
    // The mop field is needed to verify implicit equalities (e.g., x_0 == x_0).
    // TODO: Fix caching to preserve or restore mop fields after cloning.
    /*
    if (use_cache) {
        AstPtr cached = AstCache::instance().get(key);
        if (cached) {
            ctx.add(key, cached);
            return cached;
        }
    }
    */

    AstPtr result = nullptr;

    switch (mop.t) {
        case mop_n: {
            // Numeric constant
            if (!mop.nnn) {
                // Fallback to leaf if nnn is null
                result = std::make_shared<AstLeaf>(mop);
                break;
            }
            auto c = std::make_shared<AstConstant>(mop.nnn->value, mop.size);
            c->mop = mop;
            c->dest_size = mop.size;
            result = c;
            break;
        }

        case mop_d: {
            // Result of another instruction - recurse
            if (!mop.d) {
                // Fallback to leaf if d is null
                result = std::make_shared<AstLeaf>(mop);
                break;
            }
            result = convert_mop_d(mop.d, ctx);
            if (result) {
                result->mop = mop;
            }
            break;
        }

        case mop_r:    // Register
        case mop_S:    // Stack variable
        case mop_v:    // Global variable
        case mop_l:    // Local variable
        case mop_b:    // Block reference
        case mop_a:    // Address
        case mop_h:    // Helper
        case mop_str:  // String
        default: {
            // Create leaf node
            auto leaf = std::make_shared<AstLeaf>(mop);
            result = leaf;
            break;
        }
    }

    if (result) {
        result->dest_size = mop.size;
        ctx.add(key, result);

        // NOTE: Global cache put is DISABLED - see note above about mop erasing
        /*
        if (use_cache) {
            AstCache::instance().put(key, result->clone());
        }
        */
    }

    return result;
}

//--------------------------------------------------------------------------
// Public conversion functions
//--------------------------------------------------------------------------
AstPtr mop_to_ast(const mop_t& mop) {
    AstBuilderContext ctx;
    return mop_to_ast_internal(mop, ctx, true);
}

AstPtr mop_to_ast_with_context(const mop_t& mop, AstBuilderContext& ctx) {
    return mop_to_ast_internal(mop, ctx, false);
}

AstPtr minsn_to_ast(const minsn_t* ins) {
    if (!ins || !is_mba_opcode(ins->opcode)) {
        return nullptr;
    }

    AstBuilderContext ctx;

    // Convert left operand
    AstPtr left = nullptr;
    if (ins->l.t != mop_z) {
        left = mop_to_ast_internal(ins->l, ctx, true);
        if (!left) {
            left = std::make_shared<AstLeaf>(ins->l);
        }
    }

    // Convert right operand
    AstPtr right = nullptr;
    if (ins->r.t != mop_z) {
        right = mop_to_ast_internal(ins->r, ctx, true);
        if (!right) {
            right = std::make_shared<AstLeaf>(ins->r);
        }
    }

    // Create root node
    auto node = std::make_shared<AstNode>(ins->opcode, left, right);
    node->ea = ins->ea;
    node->dest_size = ins->d.size;
    node->dst_mop = ins->d;
    node->mop = ins->d;

    return node;
}

AstPtr minsn_to_ast_with_context(const minsn_t* ins, AstBuilderContext& ctx) {
    if (!ins || !is_mba_opcode(ins->opcode)) {
        return nullptr;
    }

    // Convert left operand
    AstPtr left = nullptr;
    if (ins->l.t != mop_z) {
        left = mop_to_ast_internal(ins->l, ctx, false);
        if (!left) {
            left = std::make_shared<AstLeaf>(ins->l);
        }
    }

    // Convert right operand
    AstPtr right = nullptr;
    if (ins->r.t != mop_z) {
        right = mop_to_ast_internal(ins->r, ctx, false);
        if (!right) {
            right = std::make_shared<AstLeaf>(ins->r);
        }
    }

    // Create root node
    auto node = std::make_shared<AstNode>(ins->opcode, left, right);
    node->ea = ins->ea;
    node->dest_size = ins->d.size;
    node->dst_mop = ins->d;
    node->mop = ins->d;

    return node;
}

//--------------------------------------------------------------------------
// Reverse conversion - AST to microcode
//--------------------------------------------------------------------------
mop_t ast_leaf_to_mop(AstLeafPtr leaf, const std::map<std::string, mop_t>& bindings) {
    if (!leaf) {
        return mop_t();
    }

    // Check if it's a constant FIRST - constants in replacements should use
    // their literal values, not values captured from the pattern
    if (leaf->is_constant()) {
        auto constant = std::static_pointer_cast<AstConstant>(leaf);
        mop_t result;
        // Use a reasonable default size if dest_size is 0
        int size = leaf->dest_size > 0 ? leaf->dest_size : 4;
        result.make_number(constant->value, size);
        return result;
    }

    // Check if it's a named variable with a binding
    auto it = bindings.find(leaf->name);
    if (it != bindings.end()) {
        return it->second;
    }

    // Return the original mop if available
    if (leaf->mop.t != mop_z) {
        return leaf->mop;
    }

    // Can't resolve
    return mop_t();
}

minsn_t* ast_to_minsn(AstPtr ast,
                      const std::map<std::string, mop_t>& bindings,
                      mblock_t* blk,
                      ea_t ea) {
    if (!ast) {
        return nullptr;
    }

    // Handle leaf nodes
    if (ast->is_leaf()) {
        // Leaf nodes can't be converted to instructions directly
        // They represent operands, not operations
        return nullptr;
    }

    // Must be a node
    auto node = std::static_pointer_cast<AstNode>(ast);

    // Create new instruction
    minsn_t* ins = new minsn_t(ea);
    ins->opcode = node->opcode;

    // Convert left operand
    if (node->left) {
        if (node->left->is_leaf()) {
            ins->l = ast_leaf_to_mop(std::static_pointer_cast<AstLeaf>(node->left), bindings);
        } else {
            // Nested operation - need to create sub-instruction
            auto sub_node = std::static_pointer_cast<AstNode>(node->left);
            minsn_t* sub_ins = ast_to_minsn(node->left, bindings, blk, ea);
            if (sub_ins) {
                ins->l.create_from_insn(sub_ins);
                delete sub_ins;
            }
        }
    }

    // Convert right operand
    if (node->right) {
        if (node->right->is_leaf()) {
            ins->r = ast_leaf_to_mop(std::static_pointer_cast<AstLeaf>(node->right), bindings);
        } else {
            auto sub_node = std::static_pointer_cast<AstNode>(node->right);
            minsn_t* sub_ins = ast_to_minsn(node->right, bindings, blk, ea);
            if (sub_ins) {
                ins->r.create_from_insn(sub_ins);
                delete sub_ins;
            }
        }
    }

    // Set destination size
    ins->d.size = node->dest_size > 0 ? node->dest_size : 8;

    // Ensure operand sizes are valid (mop_t default constructor leaves size uninitialized)
    if (ins->l.t == mop_z) {
        ins->l.size = 0;
    }
    if (ins->r.t == mop_z) {
        ins->r.size = 0;
    }

    return ins;
}

//--------------------------------------------------------------------------
// Cache management
//--------------------------------------------------------------------------
void clear_ast_caches() {
    AstCache::instance().clear();
}

AstCacheStats get_ast_cache_stats() {
    AstCacheStats stats;
    stats.cache_size = AstCache::instance().size();
    stats.hit_count = AstCache::instance().hits();
    stats.miss_count = AstCache::instance().misses();

    size_t total = stats.hit_count + stats.miss_count;
    stats.hit_rate = (total > 0) ? (double)stats.hit_count / total : 0.0;

    return stats;
}

} // namespace ast
} // namespace chernobog
