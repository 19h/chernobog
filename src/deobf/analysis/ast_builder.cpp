#include "ast_builder.h"
#include <functional>

namespace chernobog {
namespace ast {

//--------------------------------------------------------------------------
// MopKey implementation
//--------------------------------------------------------------------------
MopKey MopKey::from_mop(const mop_t& mop) {
    MopKey key;
    key.type = mop.t;
    key.size = mop.size;
    key.value1 = 0;
    key.value2 = 0;

    switch (mop.t) {
        case mop_n:  // Number constant
            key.value1 = mop.nnn->value;
            // Include original value for constants to distinguish different occurrences
            key.value2 = mop.nnn->org_value;
            break;

        case mop_r:  // Register
            key.value1 = mop.r;
            break;

        case mop_S:  // Stack variable
            key.value1 = static_cast<uint64_t>(mop.s->off);
            break;

        case mop_v:  // Global variable
            key.value1 = mop.g;
            break;

        case mop_l:  // Local variable
            key.value1 = mop.l->idx;
            key.value2 = mop.l->off;
            break;

        case mop_d:  // Result of another instruction
            // Use string representation for complex operands
            key.str_value = mop.d->dstr();
            break;

        case mop_b:  // Block reference
            key.value1 = mop.b;
            break;

        case mop_a:  // Address operand
            if (mop.a) {
                MopKey inner = from_mop(*mop.a);
                key.value1 = inner.value1;
                key.value2 = inner.value2;
                key.str_value = "a:" + inner.str_value;
            }
            break;

        case mop_h:  // Helper function
            key.str_value = mop.helper ? mop.helper : "";
            break;

        case mop_str:  // String
            key.str_value = mop.cstr ? mop.cstr : "";
            break;

        default:
            break;
    }

    return key;
}

bool MopKey::operator<(const MopKey& other) const {
    if (type != other.type) return type < other.type;
    if (size != other.size) return size < other.size;
    if (value1 != other.value1) return value1 < other.value1;
    if (value2 != other.value2) return value2 < other.value2;
    return str_value < other.str_value;
}

bool MopKey::operator==(const MopKey& other) const {
    return type == other.type &&
           size == other.size &&
           value1 == other.value1 &&
           value2 == other.value2 &&
           str_value == other.str_value;
}

size_t MopKey::Hash::operator()(const MopKey& k) const {
    size_t h = std::hash<int>()(static_cast<int>(k.type));
    h ^= std::hash<int>()(k.size) << 1;
    h ^= std::hash<uint64_t>()(k.value1) << 2;
    h ^= std::hash<uint64_t>()(k.value2) << 3;
    h ^= std::hash<std::string>()(k.str_value) << 4;
    return h;
}

//--------------------------------------------------------------------------
// AstBuilderContext implementation
//--------------------------------------------------------------------------
AstPtr AstBuilderContext::get_or_create(const mop_t& mop) {
    MopKey key = MopKey::from_mop(mop);

    if (has(key)) {
        return get(key);
    }

    // Will be created by caller and added
    return nullptr;
}

bool AstBuilderContext::has(const MopKey& key) const {
    return mop_to_ast.count(key) > 0;
}

AstPtr AstBuilderContext::get(const MopKey& key) const {
    auto it = mop_to_ast.find(key);
    return (it != mop_to_ast.end()) ? it->second : nullptr;
}

void AstBuilderContext::add(const MopKey& key, AstPtr ast) {
    ast->ast_index = next_index++;
    mop_to_ast[key] = ast;
}

void AstBuilderContext::clear() {
    mop_to_ast.clear();
    next_index = 0;
}

//--------------------------------------------------------------------------
// AstCache implementation
//--------------------------------------------------------------------------
AstCache& AstCache::instance() {
    static AstCache instance;
    return instance;
}

AstPtr AstCache::get(const MopKey& key) {
    std::lock_guard<std::mutex> lock(mutex);

    auto it = cache.find(key);
    if (it != cache.end()) {
        hit_count++;
        // Return a mutable copy (the cached one is frozen)
        return it->second->clone();
    }

    miss_count++;
    return nullptr;
}

void AstCache::put(const MopKey& key, AstPtr ast) {
    std::lock_guard<std::mutex> lock(mutex);

    evict_if_needed();

    // Freeze and cache
    ast->freeze();
    cache[key] = ast;
}

void AstCache::clear() {
    std::lock_guard<std::mutex> lock(mutex);
    cache.clear();
    hit_count = 0;
    miss_count = 0;
}

size_t AstCache::size() const {
    return cache.size();
}

void AstCache::evict_if_needed() {
    // Simple eviction: remove 10% of entries when full
    if (cache.size() >= MAX_CACHE_SIZE) {
        size_t to_remove = MAX_CACHE_SIZE / 10;
        auto it = cache.begin();
        for (size_t i = 0; i < to_remove && it != cache.end(); i++) {
            it = cache.erase(it);
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

    // Check global cache
    if (use_cache) {
        AstPtr cached = AstCache::instance().get(key);
        if (cached) {
            ctx.add(key, cached);
            return cached;
        }
    }

    AstPtr result = nullptr;

    switch (mop.t) {
        case mop_n: {
            // Numeric constant
            auto c = std::make_shared<AstConstant>(mop.nnn->value, mop.size);
            c->mop = mop;
            c->dest_size = mop.size;
            result = c;
            break;
        }

        case mop_d: {
            // Result of another instruction - recurse
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

        // Add to global cache
        if (use_cache) {
            AstCache::instance().put(key, result->clone());
        }
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

    // Check if it's a named variable with a binding
    auto it = bindings.find(leaf->name);
    if (it != bindings.end()) {
        return it->second;
    }

    // Check if it's a constant
    if (leaf->is_constant()) {
        auto constant = std::static_pointer_cast<AstConstant>(leaf);
        mop_t result;
        result.make_number(constant->value, leaf->dest_size);
        return result;
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
