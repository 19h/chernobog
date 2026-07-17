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
// Internal conversion functions
//--------------------------------------------------------------------------
static AstPtr mop_to_ast_internal(const mop_t& mop, AstBuilderContext& ctx);

// Convert instruction operand (which may be another instruction)
static AstPtr convert_mop_d(const minsn_t* ins, AstBuilderContext& ctx) {
    if (!ins || !is_mba_opcode(ins->opcode)) {
        return nullptr;
    }

    // Convert left operand
    AstPtr left = nullptr;
    if (ins->l.t != mop_z) {
        left = mop_to_ast_internal(ins->l, ctx);
        if (!left) {
            // Create a leaf for non-convertible operand
            left = std::make_shared<AstLeaf>(ins->l);
        }
    }

    // Convert right operand (for binary ops)
    AstPtr right = nullptr;
    if (ins->r.t != mop_z) {
        right = mop_to_ast_internal(ins->r, ctx);
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

static AstPtr mop_to_ast_internal(const mop_t& mop, AstBuilderContext& ctx) {
    if (mop.t == mop_z) {
        return nullptr;
    }

    MopKey key = MopKey::from_mop(mop);

    // Check context first (deduplication)
    if (ctx.has(key)) {
        return ctx.get(key);
    }

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

    }

    return result;
}

//--------------------------------------------------------------------------
// Public conversion functions
//--------------------------------------------------------------------------
AstPtr minsn_to_ast(const minsn_t* ins) {
    if (!ins || !is_mba_opcode(ins->opcode)) {
        return nullptr;
    }

    AstBuilderContext ctx;

    // Convert left operand
    AstPtr left = nullptr;
    if (ins->l.t != mop_z) {
        left = mop_to_ast_internal(ins->l, ctx);
        if (!left) {
            left = std::make_shared<AstLeaf>(ins->l);
        }
    }

    // Convert right operand
    AstPtr right = nullptr;
    if (ins->r.t != mop_z) {
        right = mop_to_ast_internal(ins->r, ctx);
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
mop_t ast_leaf_to_mop(AstLeafPtr leaf,
                      const std::map<std::string, mop_t>& bindings,
                      int constant_size) {
    if (!leaf) {
        return mop_t();
    }

    // Check if it's a constant FIRST - constants in replacements should use
    // their literal values, not values captured from the pattern
    if (leaf->is_constant()) {
        auto constant = std::static_pointer_cast<AstConstant>(leaf);
        mop_t result;
        // Replacement literals must use the width of the expression being
        // replaced. Declaration defaults are only a fallback for callers
        // that do not have an enclosing result width.
        int size = constant_size > 0 ? constant_size
                 : leaf->dest_size > 0 ? leaf->dest_size : 4;
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
            ins->l = ast_leaf_to_mop(std::static_pointer_cast<AstLeaf>(node->left),
                                     bindings, node->dest_size);
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
            ins->r = ast_leaf_to_mop(std::static_pointer_cast<AstLeaf>(node->right),
                                     bindings, node->dest_size);
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

} // namespace ast
} // namespace chernobog
