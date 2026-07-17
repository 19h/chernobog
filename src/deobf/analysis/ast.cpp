#include "ast.h"
#include "../../common/simd.h"
#include "../../common/bitvector.h"
#include <sstream>

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
    return chernobog::bitvector::mask(size);
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
// Strict mop comparison - optimized for common leaf kinds
// Uses equal_insns() for mop_d instead of expensive dstr() string comparison
//--------------------------------------------------------------------------
bool mops_equal_strict(const mop_t& a, const mop_t& b) {
    // Fast path: type must match
    if (SIMD_UNLIKELY(a.t != b.t || a.size != b.size))
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
            return a.d->equal_insns(*b.d, 0);
        case mop_b:  // Block reference
            return a.b == b.b;
        case mop_f:  // Function call
            return false;  // Too complex to compare
        case mop_a:  // Address
            if (SIMD_UNLIKELY(!a.a || !b.a)) return a.a == b.a;
            return mops_equal_strict(*a.a, *b.a);
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
    : dest_size(other.dest_size)
    , ea(other.ea)
    , mop(other.mop)
{
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
                const mop_t* existing = bindings.find(pat_const->const_name);
                if (existing) {
                    return mops_equal_strict(*existing, candidate->mop);
                }
                return bindings.add(pat_const->const_name.c_str(), candidate->mop,
                                    candidate->dest_size, candidate->ea);
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
            return mops_equal_strict(*existing, candidate->mop);
        }
        
        // New binding
        return bindings.add(pat_leaf->name.c_str(), candidate->mop,
                            candidate->dest_size, candidate->ea);
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
    
    // Operand arity must match exactly. Keep a binding-count checkpoint so a
    // failed branch cannot leak captures into the commuted alternative.
    if (static_cast<bool>(pat_node->left) != static_cast<bool>(cand_node->left) ||
        static_cast<bool>(pat_node->right) != static_cast<bool>(cand_node->right)) {
        return false;
    }

    const size_t saved_count = bindings.count;
    const auto match_operands = [&](const AstBase* candidate_left,
                                    const AstBase* candidate_right) {
        if (pat_node->left &&
            !match_pattern_internal(pat_node->left.get(), candidate_left, bindings)) {
            return false;
        }
        if (pat_node->right &&
            !match_pattern_internal(pat_node->right.get(), candidate_right, bindings)) {
            return false;
        }
        return true;
    };

    if (match_operands(cand_node->left.get(), cand_node->right.get())) {
        return true;
    }
    bindings.count = saved_count;

    // These microcode operations are commutative over fixed-width bit-vectors.
    // Try the swapped form lazily instead of pre-generating factorially many
    // pattern variants at registry initialization.
    const bool commutative = pat_node->right &&
        (pat_node->opcode == m_add || pat_node->opcode == m_mul ||
         pat_node->opcode == m_and || pat_node->opcode == m_or ||
         pat_node->opcode == m_xor);
    if (commutative &&
        match_operands(cand_node->right.get(), cand_node->left.get())) {
        return true;
    }

    bindings.count = saved_count;
    return false;
}

bool match_pattern(const AstBase* pattern, const AstBase* candidate, 
                   MatchBindings& bindings) {
    bindings.clear();
    return match_pattern_internal(pattern, candidate, bindings);
}

} // namespace ast
} // namespace chernobog
