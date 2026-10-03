#include "ast_builder.h"
#include "../../common/simd.h"
#include <set>

namespace chernobog
{
namespace ast
{

namespace
{
class StructureAudit
{
    AstBuildReport &report_;
    std::set<const void *> active_;

    bool reject(AstBuildStatus status)
    {
        report_.status = status;
        return false;
    }
    bool enter(const void *identity, size_t depth)
    {
        report_.maximum_depth = std::max(report_.maximum_depth, depth);
        if (depth > ast_depth_limit)
            return reject(AstBuildStatus::DepthLimit);
        if (report_.visits >= ast_visit_limit)
            return reject(AstBuildStatus::VisitLimit);
        ++report_.visits;
        if (!active_.insert(identity).second)
            return reject(AstBuildStatus::Cycle);
        return true;
    }
    bool text(const char *value)
    {
        if (!value)
            return reject(AstBuildStatus::MalformedOperand);
        size_t bytes = 0;
        while (bytes < ast_text_limit && value[bytes])
            ++bytes;
        if (bytes == ast_text_limit || bytes + 1 > ast_total_text_limit - report_.text_bytes)
            return reject(AstBuildStatus::TextLimit);
        report_.text_bytes += bytes + 1; // Include the terminator copied by the SDK
        return true;
    }
    bool container(size_t count)
    {
        if (count > ast_visit_limit - report_.visits)
            return reject(AstBuildStatus::VisitLimit);
        report_.visits += count;
        return true;
    }
    bool location(const argloc_t &value)
    {
        return !value.is_scattered() || container(value.scattered().size());
    }

  public:
    explicit StructureAudit(AstBuildReport &report) : report_(report) { report_ = {}; }
    bool instruction(const minsn_t *ins, size_t depth)
    {
        if (!ins)
            return reject(AstBuildStatus::NullInstruction);
        if (!enter(ins, depth))
            return false;
        ++report_.instructions;
        const bool okay =
            operand(ins->l, depth) && operand(ins->r, depth) && operand(ins->d, depth);
        active_.erase(ins);
        return okay;
    }
    bool operand(const mop_t &mop, size_t depth)
    {
        if (mop.t == mop_z)
            return true;
        if (!enter(&mop, depth))
            return false;
        bool okay = true;
        switch (mop.t)
        {
        case mop_r:
        case mop_v:
        case mop_b:
            break;
        case mop_n:
            okay = mop.nnn || reject(AstBuildStatus::MalformedOperand);
            break;
        case mop_S:
            okay = mop.s || reject(AstBuildStatus::MalformedOperand);
            break;
        case mop_l:
            okay = mop.l || reject(AstBuildStatus::MalformedOperand);
            break;
        case mop_d:
            okay = instruction(mop.d, depth + 1);
            break;
        case mop_a:
            okay = mop.a ? operand(*mop.a, depth + 1) : reject(AstBuildStatus::MalformedOperand);
            break;
        case mop_h:
            okay = text(mop.helper);
            break;
        case mop_str:
            okay = text(mop.cstr);
            break;
        case mop_f:
            if (!mop.f)
                okay = reject(AstBuildStatus::MalformedOperand);
            else
            {
                okay = container(mop.f->args.size()) && container(mop.f->retregs.size()) &&
                       container(mop.f->fti_attrs.size()) && location(mop.f->return_argloc);
                if (okay)
                    for (const auto &arg : mop.f->args)
                        if (!text(arg.name.c_str()) || !location(arg.argloc) ||
                            !operand(arg, depth + 1))
                        {
                            okay = false;
                            break;
                        }
                if (okay)
                    for (const auto &reg : mop.f->retregs)
                        if (!operand(reg, depth + 1))
                        {
                            okay = false;
                            break;
                        }
            }
            break;
        case mop_p:
            okay = mop.pair ? operand(mop.pair->lop, depth + 1) && operand(mop.pair->hop, depth + 1)
                            : reject(AstBuildStatus::MalformedOperand);
            break;
        case mop_c:
            if (!mop.c)
                okay = reject(AstBuildStatus::MalformedOperand);
            else
            {
                okay = container(mop.c->values.size()) && container(mop.c->targets.size());
                if (okay)
                    for (const auto &values : mop.c->values)
                        if (!container(values.size()))
                        {
                            okay = false;
                            break;
                        }
            }
            break;
        case mop_fn:
            okay = mop.fpc || reject(AstBuildStatus::MalformedOperand);
            break;
        case mop_sc:
            okay = mop.scif ? text(mop.scif->name.c_str()) && location(*mop.scif)
                            : reject(AstBuildStatus::MalformedOperand);
            break;
        default:
            okay = reject(AstBuildStatus::UnsupportedOperand);
            break;
        }
        active_.erase(&mop);
        return okay;
    }
};

MopKey mop_key_unchecked(const mop_t &mop);
uint64_t hash_insn_unchecked(const minsn_t *ins);
} // namespace

const char *ast_build_status_name(AstBuildStatus status)
{
    switch (status)
    {
    case AstBuildStatus::Complete:
        return "complete";
    case AstBuildStatus::NullInstruction:
        return "null_instruction";
    case AstBuildStatus::UnsupportedOperand:
        return "unsupported_operand_payload";
    case AstBuildStatus::MalformedOperand:
        return "malformed_operand_payload";
    case AstBuildStatus::Cycle:
        return "cyclic_operand_payload";
    case AstBuildStatus::DepthLimit:
        return "ast_depth_limit";
    case AstBuildStatus::VisitLimit:
        return "ast_visit_limit";
    case AstBuildStatus::TextLimit:
        return "ast_text_limit";
    }
    return "unknown";
}

bool validate_ast_structure(const minsn_t *ins, AstBuildReport *report)
{
    AstBuildReport local;
    StructureAudit audit(report ? *report : local);
    return audit.instruction(ins, 0);
}

MopKey MopKey::from_mop(const mop_t &mop, AstBuildReport *report)
{
    AstBuildReport local;
    StructureAudit audit(report ? *report : local);
    if (!audit.operand(mop, 0))
    {
        MopKey rejected{};
        rejected.complete = false;
        return rejected;
    }
    return mop_key_unchecked(mop);
}

uint64_t MopKey::hash_insn(const minsn_t *ins, AstBuildReport *report)
{
    return validate_ast_structure(ins, report) ? hash_insn_unchecked(ins) : 0;
}

//--------------------------------------------------------------------------
// MopKey implementation - OPTIMIZED
// Uses pre-computed hash to eliminate string allocations and enable O(1) lookup
//--------------------------------------------------------------------------

// Hash an instruction structure recursively (for mop_d operands)
namespace
{
uint64_t hash_insn_unchecked(const minsn_t *ins)
{
    if (!ins)
        return 0;

    // Combine opcode, operand info, and recursive structure
    uint64_t h = simd::hash_u64(static_cast<uint64_t>(ins->opcode));

    // Hash left operand
    if (ins->l.t != mop_z)
    {
        MopKey left_key = mop_key_unchecked(ins->l);
        h = simd::hash_combine(h, left_key.hash);
    }

    // Hash right operand
    if (ins->r.t != mop_z)
    {
        MopKey right_key = mop_key_unchecked(ins->r);
        h = simd::hash_combine(h, right_key.hash);
    }

    // Include destination size
    h = simd::hash_combine(h, static_cast<uint64_t>(ins->d.size));
    h = simd::hash_combine(h, static_cast<uint64_t>(ins->d.valnum));
    h = simd::hash_combine(h, static_cast<uint64_t>(ins->d.oprops));
    h = simd::hash_combine(h, static_cast<uint64_t>(ins->iprops));

    return h;
}

MopKey mop_key_unchecked(const mop_t &mop)
{
    MopKey key{};
    key.type = static_cast<uint16_t>(mop.t);
    key.size = mop.size;
    key.valnum = mop.valnum;
    key.properties = mop.oprops;

    switch (mop.t)
    {
    case mop_n: // Number constant
        if (mop.nnn)
        {
            key.value1 = mop.nnn->value;
            // Include original value for constants to distinguish different occurrences
            key.value2 = mop.nnn->org_value;
        }
        break;

    case mop_r: // Register
        key.value1 = mop.r;
        break;

    case mop_S: // Stack variable
        if (mop.s)
        {
            key.value1 = static_cast<uint64_t>(mop.s->off);
            key.frame = reinterpret_cast<uintptr_t>(mop.s->mba);
        }
        break;

    case mop_v: // Global variable
        key.value1 = mop.g;
        break;

    case mop_l: // Local variable
        if (mop.l)
        {
            key.value1 = mop.l->idx;
            key.value2 = mop.l->off;
            key.frame = reinterpret_cast<uintptr_t>(mop.l->mba);
        }
        break;

    case mop_d: // Result of another instruction
        // OPTIMIZED: Hash instruction structure instead of string
        if (mop.d)
        {
            key.value1 = hash_insn_unchecked(mop.d);
            // Use secondary hash for collision resistance
            key.value2 = simd::hash_combine(static_cast<uint64_t>(mop.d->opcode),
                                            static_cast<uint64_t>(mop.d->ea));
        }
        break;

    case mop_b: // Block reference
        key.value1 = mop.b;
        break;

    case mop_a: // Address operand
        if (mop.a)
        {
            MopKey inner = mop_key_unchecked(*mop.a);
            key.value1 = inner.hash; // Use inner hash
            key.value2 = inner.value1;
            // Address access extents are part of SDK operand identity. Without
            // them, AST deduplication can erase a strict matcher difference.
            key.frame =
                uint64_t(uint32_t(mop.a->insize)) | (uint64_t(uint32_t(mop.a->outsize)) << 32);
        }
        break;

    case mop_h: // Helper function
        if (mop.helper)
        {
            key.value1 = simd::hash_bytes(mop.helper, strlen(mop.helper));
        }
        break;

    case mop_str: // String
        if (mop.cstr)
        {
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
    key.hash = simd::hash_combine(key.hash, simd::hash_u64(key.frame));
    key.hash = simd::hash_combine(key.hash, simd::hash_u64(key.valnum));
    key.hash = simd::hash_combine(key.hash, simd::hash_u64(key.properties));

    return key;
}
} // namespace

//--------------------------------------------------------------------------
// Internal conversion functions
//--------------------------------------------------------------------------
static AstPtr mop_to_ast_internal(const mop_t &mop, AstBuilderContext &ctx);

// Convert instruction operand (which may be another instruction)
static AstPtr convert_mop_d(const minsn_t *ins, AstBuilderContext &ctx)
{
    if (!ins || !is_mba_opcode(ins->opcode))
    {
        return nullptr;
    }

    // Convert left operand
    AstPtr left = nullptr;
    if (ins->l.t != mop_z)
    {
        left = mop_to_ast_internal(ins->l, ctx);
        if (!left)
        {
            // Create a leaf for non-convertible operand
            left = std::make_shared<AstLeaf>(ins->l);
        }
    }

    // Convert right operand (for binary ops)
    AstPtr right = nullptr;
    if (ins->r.t != mop_z)
    {
        right = mop_to_ast_internal(ins->r, ctx);
        if (!right)
        {
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

static AstPtr mop_to_ast_internal(const mop_t &mop, AstBuilderContext &ctx)
{
    if (mop.t == mop_z)
    {
        return nullptr;
    }

    // The public entry point audited the complete immutable operand tree.
    MopKey key = mop_key_unchecked(mop);

    // The compact key is an index, not an exact structural identity. The
    // copied operand on the candidate AST guards against nested-key collisions.
    if (AstPtr cached = ctx.get_exact(key, mop))
        return cached;

    AstPtr result = nullptr;

    switch (mop.t)
    {
    case mop_n:
    {
        // Numeric constant
        if (!mop.nnn)
        {
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

    case mop_d:
    {
        // Result of another instruction - recurse
        if (!mop.d)
        {
            // Fallback to leaf if d is null
            result = std::make_shared<AstLeaf>(mop);
            break;
        }
        result = convert_mop_d(mop.d, ctx);
        if (result)
        {
            result->mop = mop;
        }
        break;
    }

    case mop_r:   // Register
    case mop_S:   // Stack variable
    case mop_v:   // Global variable
    case mop_l:   // Local variable
    case mop_b:   // Block reference
    case mop_a:   // Address
    case mop_h:   // Helper
    case mop_str: // String
    default:
    {
        // Create leaf node
        auto leaf = std::make_shared<AstLeaf>(mop);
        result = leaf;
        break;
    }
    }

    if (result)
    {
        result->dest_size = mop.size;
        ctx.add(key, result);
    }

    return result;
}

//--------------------------------------------------------------------------
// Public conversion functions
//--------------------------------------------------------------------------
AstPtr minsn_to_ast(const minsn_t *ins, AstBuildReport *report)
{
    if (!validate_ast_structure(ins, report))
        return nullptr;
    if (!ins || !is_mba_opcode(ins->opcode))
    {
        return nullptr;
    }

    AstBuilderContext ctx;

    // Convert left operand
    AstPtr left = nullptr;
    if (ins->l.t != mop_z)
    {
        left = mop_to_ast_internal(ins->l, ctx);
        if (!left)
        {
            left = std::make_shared<AstLeaf>(ins->l);
        }
    }

    // Convert right operand
    AstPtr right = nullptr;
    if (ins->r.t != mop_z)
    {
        right = mop_to_ast_internal(ins->r, ctx);
        if (!right)
        {
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
mop_t ast_leaf_to_mop(AstLeafPtr leaf, const std::map<std::string, mop_t> &bindings,
                      int constant_size)
{
    if (!leaf)
    {
        return mop_t();
    }

    // Check if it's a constant FIRST - constants in replacements should use
    // their literal values, not values captured from the pattern
    if (leaf->is_constant())
    {
        auto constant = std::static_pointer_cast<AstConstant>(leaf);
        mop_t result;
        // Replacement literals must use the width of the expression being
        // replaced. Declaration defaults are only a fallback for callers
        // that do not have an enclosing result width.
        int size = constant_size > 0 ? constant_size : leaf->dest_size > 0 ? leaf->dest_size : 4;
        result.make_number(constant->value, size);
        return result;
    }

    // Check if it's a named variable with a binding
    auto it = bindings.find(leaf->name);
    if (it != bindings.end())
    {
        return it->second;
    }

    // Return the original mop if available
    if (leaf->mop.t != mop_z)
    {
        return leaf->mop;
    }

    // Can't resolve
    return mop_t();
}

minsn_t *ast_to_minsn(AstPtr ast, const std::map<std::string, mop_t> &bindings, mblock_t *blk,
                      ea_t ea)
{
    if (!ast)
    {
        return nullptr;
    }

    // Handle leaf nodes
    if (ast->is_leaf())
    {
        // Leaf nodes can't be converted to instructions directly
        // They represent operands, not operations
        return nullptr;
    }

    // Must be a node
    auto node = std::static_pointer_cast<AstNode>(ast);

    // Create new instruction
    minsn_t *ins = new minsn_t(ea);
    ins->opcode = node->opcode;

    // Convert left operand
    if (node->left)
    {
        if (node->left->is_leaf())
        {
            ins->l = ast_leaf_to_mop(std::static_pointer_cast<AstLeaf>(node->left), bindings,
                                     node->dest_size);
        }
        else
        {
            // Nested operation - need to create sub-instruction
            auto sub_node = std::static_pointer_cast<AstNode>(node->left);
            minsn_t *sub_ins = ast_to_minsn(node->left, bindings, blk, ea);
            if (sub_ins)
            {
                ins->l.create_from_insn(sub_ins);
                delete sub_ins;
            }
        }
    }

    // Convert right operand
    if (node->right)
    {
        if (node->right->is_leaf())
        {
            ins->r = ast_leaf_to_mop(std::static_pointer_cast<AstLeaf>(node->right), bindings,
                                     node->dest_size);
        }
        else
        {
            auto sub_node = std::static_pointer_cast<AstNode>(node->right);
            minsn_t *sub_ins = ast_to_minsn(node->right, bindings, blk, ea);
            if (sub_ins)
            {
                ins->r.create_from_insn(sub_ins);
                delete sub_ins;
            }
        }
    }

    // Set destination size
    ins->d.size = node->dest_size > 0 ? node->dest_size : 8;

    // Ensure operand sizes are valid (mop_t default constructor leaves size uninitialized)
    if (ins->l.t == mop_z)
    {
        ins->l.size = 0;
    }
    if (ins->r.t == mop_z)
    {
        ins->r.size = 0;
    }

    return ins;
}

} // namespace ast
} // namespace chernobog
