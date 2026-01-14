#include "ast.h"
#include "../../common/simd.h"
#include <sstream>
#include <algorithm>

namespace chernobog {
namespace ast {

//--------------------------------------------------------------------------
// MBA-related opcodes that can be converted to AST
//--------------------------------------------------------------------------
static const std::set<mcode_t> MBA_OPCODES = {
    m_add, m_sub, m_mul, m_udiv, m_sdiv, m_umod, m_smod,
    m_and, m_or, m_xor, m_shl, m_shr, m_sar,
    m_bnot, m_neg, m_lnot,
    m_low, m_high, m_xds, m_xdu,
    m_sets, m_seto, m_setp, m_setnz, m_setz,
    m_setae, m_setb, m_seta, m_setbe,
    m_setg, m_setge, m_setl, m_setle,
    m_cfadd, m_ofadd
};

bool is_mba_opcode(mcode_t op) {
    return MBA_OPCODES.count(op) > 0;
}

//--------------------------------------------------------------------------
// Size utilities
//--------------------------------------------------------------------------
uint64_t size_mask(int size) {
    switch (size) {
        case 1: return 0xFFULL;
        case 2: return 0xFFFFULL;
        case 4: return 0xFFFFFFFFULL;
        case 8: return 0xFFFFFFFFFFFFFFFFULL;
        default: return 0xFFFFFFFFFFFFFFFFULL;
    }
}

uint64_t twos_complement_sub_value(int size) {
    // Returns 2^n for subtraction patterns
    switch (size) {
        case 1: return 0x100ULL;
        case 2: return 0x10000ULL;
        case 4: return 0x100000000ULL;
        case 8: return 0ULL;  // Wraps around
        default: return 0ULL;
    }
}

//--------------------------------------------------------------------------
// Opcode name for debugging
//--------------------------------------------------------------------------
const char* opcode_name(mcode_t op) {
    switch (op) {
        case m_add: return "add";
        case m_sub: return "sub";
        case m_mul: return "mul";
        case m_udiv: return "udiv";
        case m_sdiv: return "sdiv";
        case m_umod: return "umod";
        case m_smod: return "smod";
        case m_and: return "and";
        case m_or: return "or";
        case m_xor: return "xor";
        case m_shl: return "shl";
        case m_shr: return "shr";
        case m_sar: return "sar";
        case m_bnot: return "bnot";
        case m_neg: return "neg";
        case m_lnot: return "lnot";
        case m_low: return "low";
        case m_high: return "high";
        case m_xds: return "xds";
        case m_xdu: return "xdu";
        case m_sets: return "sets";
        case m_seto: return "seto";
        case m_setp: return "setp";
        case m_setnz: return "setnz";
        case m_setz: return "setz";
        case m_setae: return "setae";
        case m_setb: return "setb";
        case m_seta: return "seta";
        case m_setbe: return "setbe";
        case m_setg: return "setg";
        case m_setge: return "setge";
        case m_setl: return "setl";
        case m_setle: return "setle";
        case m_cfadd: return "cfadd";
        case m_ofadd: return "ofadd";
        default: return "?";
    }
}

//--------------------------------------------------------------------------
// Mop comparison ignoring size - OPTIMIZED
// Uses equal_insns() for mop_d instead of expensive dstr() string comparison
//--------------------------------------------------------------------------
bool mops_equal_ignore_size(const mop_t& a, const mop_t& b) {
    // Fast path: type must match
    if (SIMD_UNLIKELY(a.t != b.t))
        return false;

    switch (a.t) {
        case mop_r:  // Register - single int comparison (hot path)
            return a.r == b.r;
        case mop_n:  // Number constant
            if (SIMD_UNLIKELY(!a.nnn || !b.nnn)) return a.nnn == b.nnn;
            return a.nnn->value == b.nnn->value;
        case mop_S:  // Stack variable
            if (SIMD_UNLIKELY(!a.s || !b.s)) return a.s == b.s;
            return a.s->off == b.s->off;
        case mop_v:  // Global variable - single uint64 comparison
            return a.g == b.g;
        case mop_l:  // Local variable
            if (SIMD_UNLIKELY(!a.l || !b.l)) return a.l == b.l;
            return (a.l->idx == b.l->idx) & (a.l->off == b.l->off);
        case mop_d:  // Result of another instruction
            // OPTIMIZED: Use equal_insns() instead of expensive dstr() string comparison
            // dstr() creates a string allocation on every call - extremely slow
            if (SIMD_UNLIKELY(!a.d || !b.d)) return a.d == b.d;
            return a.d->equal_insns(*b.d, EQ_IGNSIZE);
        case mop_b:  // Block reference
            return a.b == b.b;
        case mop_f:  // Function call
            return false;  // Too complex to compare
        case mop_a:  // Address
            if (SIMD_UNLIKELY(!a.a || !b.a)) return a.a == b.a;
            return mops_equal_ignore_size(*a.a, *b.a);
        case mop_h:  // Helper function
            if (SIMD_UNLIKELY(!a.helper || !b.helper)) return a.helper == b.helper;
            return strcmp(a.helper, b.helper) == 0;
        case mop_str:  // String
            if (SIMD_UNLIKELY(!a.cstr || !b.cstr)) return a.cstr == b.cstr;
            return strcmp(a.cstr, b.cstr) == 0;
        case mop_z:  // Empty
            return true;
        default:
            return false;
    }
}

//--------------------------------------------------------------------------
// AstBase implementation
//--------------------------------------------------------------------------
AstBase::AstBase(const AstBase& other)
    : ast_index(other.ast_index)
    , dest_size(other.dest_size)
    , ea(other.ea)
    , mop(other.mop)
    , frozen(false)  // Copies are always mutable
{
}

void AstBase::freeze() {
    frozen = true;

    // CRITICAL: Clear mop fields to prevent crashes during static destruction.
    // When the AstCache destructor runs during program exit, IDA's internal
    // structures are already freed. The mop_t objects contain pointers to
    // these structures, so we must clear them before caching.
    mop.erase();

    // Recursively freeze children if this is a node
    if (auto node = dynamic_cast<AstNode*>(this)) {
        node->dst_mop.erase();
        if (node->left) {
            node->left->freeze();
        }
        if (node->right) {
            node->right->freeze();
        }
    }
}

AstPtr AstBase::ensure_mutable() {
    if (!frozen) {
        return shared_from_this();
    }
    return clone();
}

//--------------------------------------------------------------------------
// AstNode implementation
//--------------------------------------------------------------------------
AstNode::AstNode(mcode_t op, AstPtr l, AstPtr r)
    : opcode(op)
    , left(l)
    , right(r)
{
}

AstNode::AstNode(const AstNode& other)
    : AstBase(other)
    , opcode(other.opcode)
    , left(other.left ? other.left->clone() : nullptr)
    , right(other.right ? other.right->clone() : nullptr)
    , dst_mop(other.dst_mop)
{
}

AstPtr AstNode::clone() const {
    return std::make_shared<AstNode>(*this);
}

std::vector<std::string> AstNode::get_depth_signature(int depth) const {
    if (depth <= 0) {
        return {};
    }

    if (depth == 1) {
        // Return just the opcode at depth 1
        return {std::to_string(static_cast<int>(opcode))};
    }

    // Get signatures from children at depth-1
    std::vector<std::string> result;

    if (left) {
        auto left_sig = left->get_depth_signature(depth - 1);
        result.insert(result.end(), left_sig.begin(), left_sig.end());
    } else {
        result.push_back("N");  // No node
    }

    if (right) {
        auto right_sig = right->get_depth_signature(depth - 1);
        result.insert(result.end(), right_sig.begin(), right_sig.end());
    } else {
        result.push_back("N");  // No node (unary op or missing)
    }

    return result;
}

bool AstNode::equals(const AstBase& other) const {
    if (!other.is_node())
        return false;

    const AstNode& o = static_cast<const AstNode&>(other);
    if (opcode != o.opcode)
        return false;

    // Compare children
    if ((left == nullptr) != (o.left == nullptr))
        return false;
    if (left && !left->equals(*o.left))
        return false;

    if ((right == nullptr) != (o.right == nullptr))
        return false;
    if (right && !right->equals(*o.right))
        return false;

    return true;
}

std::string AstNode::to_string() const {
    std::ostringstream ss;
    ss << opcode_name(opcode) << "(";
    if (left) {
        ss << left->to_string();
    }
    if (right) {
        ss << ", " << right->to_string();
    }
    ss << ")";
    return ss.str();
}

void AstNode::reset_mops() {
    mop = mop_t();
    dst_mop = mop_t();
    if (left) {
        if (auto node = std::dynamic_pointer_cast<AstNode>(left)) {
            node->reset_mops();
        } else if (auto leaf = std::dynamic_pointer_cast<AstLeaf>(left)) {
            leaf->mop = mop_t();
        }
    }
    if (right) {
        if (auto node = std::dynamic_pointer_cast<AstNode>(right)) {
            node->reset_mops();
        } else if (auto leaf = std::dynamic_pointer_cast<AstLeaf>(right)) {
            leaf->mop = mop_t();
        }
    }
}

bool AstNode::check_pattern_and_copy_mops(AstPtr candidate) {
    // Reset mops before matching
    reset_mops();

    // Try to match structure and copy mops
    if (!copy_mops_from_ast(candidate)) {
        return false;
    }

    // Verify implicit equalities (same variable name = same value)
    return check_implicit_equalities();
}

bool AstNode::copy_mops_from_ast(AstPtr other) {
    if (!other || !other->is_node())
        return false;

    auto other_node = std::static_pointer_cast<AstNode>(other);

    // Opcode must match exactly
    if (opcode != other_node->opcode)
        return false;

    // Copy mops from this level
    mop = other_node->mop;
    dst_mop = other_node->dst_mop;
    dest_size = other_node->dest_size;
    ea = other_node->ea;

    // Recurse on left child
    if (left) {
        if (!other_node->left)
            return false;

        if (left->is_node()) {
            auto left_node = std::static_pointer_cast<AstNode>(left);
            if (!left_node->copy_mops_from_ast(other_node->left))
                return false;
        } else {
            // Leaf node - copy mop directly
            auto left_leaf = std::static_pointer_cast<AstLeaf>(left);
            if (!other_node->left->is_leaf())
                return false;

            // If pattern leaf is a constant, verify the candidate's value matches
            if (left_leaf->is_constant()) {
                auto const_leaf = std::static_pointer_cast<AstConstant>(left);
                // Candidate must be a number constant with matching value
                if (other_node->left->mop.t != mop_n || !other_node->left->mop.nnn)
                    return false;
                uint64_t expected = const_leaf->value;
                uint64_t actual = other_node->left->mop.nnn->value;
                uint64_t mask = size_mask(other_node->left->mop.size);
                if ((expected & mask) != (actual & mask))
                    return false;
            }

            left_leaf->mop = other_node->left->mop;
            left_leaf->dest_size = other_node->left->dest_size;
            left_leaf->ea = other_node->left->ea;
        }
    }

    // Recurse on right child
    if (right) {
        if (!other_node->right)
            return false;

        if (right->is_node()) {
            auto right_node = std::static_pointer_cast<AstNode>(right);
            if (!right_node->copy_mops_from_ast(other_node->right))
                return false;
        } else {
            auto right_leaf = std::static_pointer_cast<AstLeaf>(right);
            if (!other_node->right->is_leaf())
                return false;

            // If pattern leaf is a constant, verify the candidate's value matches
            if (right_leaf->is_constant()) {
                auto const_leaf = std::static_pointer_cast<AstConstant>(right);
                // Candidate must be a number constant with matching value
                if (other_node->right->mop.t != mop_n || !other_node->right->mop.nnn)
                    return false;
                uint64_t expected = const_leaf->value;
                uint64_t actual = other_node->right->mop.nnn->value;
                uint64_t mask = size_mask(other_node->right->mop.size);
                if ((expected & mask) != (actual & mask))
                    return false;
            }

            right_leaf->mop = other_node->right->mop;
            right_leaf->dest_size = other_node->right->dest_size;
            right_leaf->ea = other_node->right->ea;
        }
    } else if (other_node->right) {
        // Pattern has no right child but candidate does
        return false;
    }

    return true;
}

bool AstNode::check_implicit_equalities() const {
    // Get all leaves and check that same-named variables have equal mops
    auto leaves = get_leaf_list();
    std::map<std::string, mop_t> seen;

    for (const auto& leaf : leaves) {
        if (leaf->name.empty())
            continue;

        auto it = seen.find(leaf->name);
        if (it != seen.end()) {
            // Same variable name seen before - check equality
            if (!mops_equal_ignore_size(it->second, leaf->mop)) {
                return false;
            }
        } else {
            seen[leaf->name] = leaf->mop;
        }
    }

    return true;
}

void AstNode::collect_leaves(std::vector<AstLeafPtr>& out) const {
    if (left) {
        if (left->is_leaf()) {
            out.push_back(std::static_pointer_cast<AstLeaf>(left));
        } else if (left->is_node()) {
            std::static_pointer_cast<AstNode>(left)->collect_leaves(out);
        }
    }
    if (right) {
        if (right->is_leaf()) {
            out.push_back(std::static_pointer_cast<AstLeaf>(right));
        } else if (right->is_node()) {
            std::static_pointer_cast<AstNode>(right)->collect_leaves(out);
        }
    }
}

std::vector<AstLeafPtr> AstNode::get_leaf_list() const {
    std::vector<AstLeafPtr> result;
    collect_leaves(result);
    return result;
}

std::map<std::string, AstLeafPtr> AstNode::get_leafs_by_name() const {
    std::map<std::string, AstLeafPtr> result;
    auto leaves = get_leaf_list();
    for (const auto& leaf : leaves) {
        if (!leaf->name.empty()) {
            result[leaf->name] = leaf;
        }
    }
    return result;
}

//--------------------------------------------------------------------------
// AstLeaf implementation
//--------------------------------------------------------------------------
AstLeaf::AstLeaf(const std::string& n)
    : name(n)
{
}

AstLeaf::AstLeaf(const mop_t& m)
    : name(name_from_mop(m))
{
    mop = m;
    dest_size = m.size;
}

AstLeaf::AstLeaf(const AstLeaf& other)
    : AstBase(other)
    , name(other.name)
{
}

AstPtr AstLeaf::clone() const {
    return std::make_shared<AstLeaf>(*this);
}

std::vector<std::string> AstLeaf::get_depth_signature(int depth) const {
    (void)depth;  // Unused - leaves always return "L"
    return {"L"};
}

bool AstLeaf::equals(const AstBase& other) const {
    if (!other.is_leaf() || other.is_constant())
        return false;

    const AstLeaf& o = static_cast<const AstLeaf&>(other);
    return name == o.name;
}

std::string AstLeaf::to_string() const {
    return name;
}

std::string AstLeaf::name_from_mop(const mop_t& m) {
    std::ostringstream ss;
    switch (m.t) {
        case mop_r:
            ss << "r" << m.r;
            break;
        case mop_S:
            if (m.s) ss << "s" << std::hex << m.s->off;
            else ss << "s_null";
            break;
        case mop_v:
            ss << "g" << std::hex << m.g;
            break;
        case mop_l:
            if (m.l) ss << "l" << m.l->idx << "_" << m.l->off;
            else ss << "l_null";
            break;
        case mop_n:
            if (m.nnn) ss << "n" << std::hex << m.nnn->value;
            else ss << "n_null";
            break;
        case mop_d:
            if (m.d) ss << "d_" << m.d->dstr();
            else ss << "d_null";
            break;
        default:
            ss << "m" << static_cast<int>(m.t);
            break;
    }
    return ss.str();
}

//--------------------------------------------------------------------------
// AstConstant implementation
//--------------------------------------------------------------------------
AstConstant::AstConstant(uint64_t v, int size)
    : AstLeaf("")
    , value(v)
{
    dest_size = size;
    name = std::to_string(v);
}

AstConstant::AstConstant(const std::string& n, uint64_t v)
    : AstLeaf("")
    , value(v)
    , const_name(n)
{
    name = n;
}

AstConstant::AstConstant(const AstConstant& other)
    : AstLeaf(other)
    , value(other.value)
    , const_name(other.const_name)
{
}

AstPtr AstConstant::clone() const {
    return std::make_shared<AstConstant>(*this);
}

std::vector<std::string> AstConstant::get_depth_signature(int depth) const {
    (void)depth;  // Unused - constants always return "C"
    return {"C"};
}

bool AstConstant::equals(const AstBase& other) const {
    if (!other.is_constant())
        return false;

    const AstConstant& o = static_cast<const AstConstant&>(other);

    // Named constants match by name
    if (!const_name.empty() && !o.const_name.empty()) {
        return const_name == o.const_name;
    }

    // Value constants match by value
    return value == o.value;
}

std::string AstConstant::to_string() const {
    if (!const_name.empty()) {
        return const_name;
    }
    std::ostringstream ss;
    ss << "0x" << std::hex << value;
    return ss.str();
}

//--------------------------------------------------------------------------
// Non-mutating pattern match implementation - OPTIMIZED
// Matches pattern against candidate without modifying either AST
//--------------------------------------------------------------------------

// Internal recursive match function
static bool match_pattern_internal(const AstBase* pattern, const AstBase* candidate, 
                                   MatchBindings& bindings) {
    if (!pattern || !candidate) {
        return pattern == candidate;
    }
    
    // Handle leaf patterns
    if (pattern->is_leaf()) {
        if (pattern->is_constant()) {
            // Constant pattern - candidate must be a constant with matching value
            auto pat_const = static_cast<const AstConstant*>(pattern);
            
            // Candidate must have a number operand
            if (candidate->mop.t != mop_n || !candidate->mop.nnn) {
                return false;
            }
            
            // Named constants (like c_minus_1) - just capture binding
            if (!pat_const->const_name.empty()) {
                bindings.add(pat_const->const_name.c_str(), candidate->mop, 
                            candidate->dest_size, candidate->ea);
                return true;
            }
            
            // Value constants must match
            uint64_t expected = pat_const->value;
            uint64_t actual = candidate->mop.nnn->value;
            uint64_t mask = size_mask(candidate->mop.size);
            return (expected & mask) == (actual & mask);
        }
        
        // Variable leaf - capture binding
        auto pat_leaf = static_cast<const AstLeaf*>(pattern);
        
        // Check if this variable was already bound
        const mop_t* existing = bindings.find(pat_leaf->name);
        if (existing) {
            // Same variable must have same value (implicit equality)
            return mops_equal_ignore_size(*existing, candidate->mop);
        }
        
        // New binding
        bindings.add(pat_leaf->name.c_str(), candidate->mop, 
                    candidate->dest_size, candidate->ea);
        return true;
    }
    
    // Pattern is a node - candidate must also be a node
    if (!candidate->is_node()) {
        return false;
    }
    
    auto pat_node = static_cast<const AstNode*>(pattern);
    auto cand_node = static_cast<const AstNode*>(candidate);
    
    // Opcode must match
    if (pat_node->opcode != cand_node->opcode) {
        return false;
    }
    
    // Match left operand
    if (pat_node->left) {
        if (!cand_node->left) return false;
        if (!match_pattern_internal(pat_node->left.get(), cand_node->left.get(), bindings)) {
            return false;
        }
    }
    
    // Match right operand
    if (pat_node->right) {
        if (!cand_node->right) return false;
        if (!match_pattern_internal(pat_node->right.get(), cand_node->right.get(), bindings)) {
            return false;
        }
    } else if (cand_node->right) {
        // Pattern has no right but candidate does
        return false;
    }
    
    return true;
}

bool match_pattern(const AstBase* pattern, const AstBase* candidate, 
                   MatchBindings& bindings) {
    bindings.clear();
    return match_pattern_internal(pattern, candidate, bindings);
}

} // namespace ast
} // namespace chernobog
