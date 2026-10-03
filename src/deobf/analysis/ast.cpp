#include "ast.h"
#include "../../common/simd.h"
#include "../../common/bitvector.h"
#include <sstream>

namespace chernobog
{
namespace ast
{

//--------------------------------------------------------------------------
// MBA-related opcodes that can be converted to AST
//--------------------------------------------------------------------------
static const std::set<mcode_t> MBA_OPCODES = {
    m_add,  m_sub,   m_mul,  m_udiv,  m_sdiv, m_umod,  m_smod,  m_and,   m_or,
    m_xor,  m_shl,   m_shr,  m_sar,   m_bnot, m_neg,   m_lnot,  m_low,   m_high,
    m_xds,  m_xdu,   m_sets, m_seto,  m_setp, m_setnz, m_setz,  m_setae, m_setb,
    m_seta, m_setbe, m_setg, m_setge, m_setl, m_setle, m_cfadd, m_ofadd};

bool is_mba_opcode(mcode_t op) { return MBA_OPCODES.count(op) > 0; }

//--------------------------------------------------------------------------
// Size utilities
//--------------------------------------------------------------------------
uint64_t size_mask(int size) { return chernobog::bitvector::mask(size); }

//--------------------------------------------------------------------------
// Opcode name for debugging
//--------------------------------------------------------------------------
const char *opcode_name(mcode_t op)
{
    switch (op)
    {
    case m_add:
        return "add";
    case m_sub:
        return "sub";
    case m_mul:
        return "mul";
    case m_udiv:
        return "udiv";
    case m_sdiv:
        return "sdiv";
    case m_umod:
        return "umod";
    case m_smod:
        return "smod";
    case m_and:
        return "and";
    case m_or:
        return "or";
    case m_xor:
        return "xor";
    case m_shl:
        return "shl";
    case m_shr:
        return "shr";
    case m_sar:
        return "sar";
    case m_bnot:
        return "bnot";
    case m_neg:
        return "neg";
    case m_lnot:
        return "lnot";
    case m_low:
        return "low";
    case m_high:
        return "high";
    case m_xds:
        return "xds";
    case m_xdu:
        return "xdu";
    case m_sets:
        return "sets";
    case m_seto:
        return "seto";
    case m_setp:
        return "setp";
    case m_setnz:
        return "setnz";
    case m_setz:
        return "setz";
    case m_setae:
        return "setae";
    case m_setb:
        return "setb";
    case m_seta:
        return "seta";
    case m_setbe:
        return "setbe";
    case m_setg:
        return "setg";
    case m_setge:
        return "setge";
    case m_setl:
        return "setl";
    case m_setle:
        return "setle";
    case m_cfadd:
        return "cfadd";
    case m_ofadd:
        return "ofadd";
    default:
        return "?";
    }
}

//--------------------------------------------------------------------------
// Strict value-snapshot comparison, including nested operand metadata.
// Bounded recursion rejects cyclic or excessively large comparisons.
//--------------------------------------------------------------------------
struct OperandDifference
{
    MatchFailureKind kind = MatchFailureKind::None;
    uint64_t expected = 0, actual = 0;
    bool has_values = false;
};

static bool mops_equal_strict_internal(const mop_t &a, const mop_t &b, unsigned depth,
                                       unsigned &visited, OperandDifference *difference = nullptr)
{
    const auto reject = [&](MatchFailureKind kind, uint64_t expected = 0, uint64_t actual = 0,
                            bool has_values = false)
    {
        if (difference)
            *difference = {kind, expected, actual, has_values};
        return false;
    };
    const auto equal = [&](auto expected, auto actual, MatchFailureKind kind)
    { return expected == actual || reject(kind, uint64_t(expected), uint64_t(actual), true); };
    const auto null_payload = [&](const void *expected, const void *actual)
    { return expected == actual || reject(MatchFailureKind::NullPayload); };
    if (SIMD_UNLIKELY(depth > 64 || ++visited > 512))
        return reject(MatchFailureKind::ComparisonBudget);
    if (!equal(a.t, b.t, MatchFailureKind::OperandKind) ||
        !equal(a.size, b.size, MatchFailureKind::OperandWidth) ||
        !equal(a.valnum, b.valnum, MatchFailureKind::ValueNumber) ||
        !equal(a.oprops, b.oprops, MatchFailureKind::OperandProperties))
        return false;

    switch (a.t)
    {
    case mop_r: // Register - single int comparison (hot path)
        return equal(a.r, b.r, MatchFailureKind::RegisterIdentity);
    case mop_n: // Number constant
        if (SIMD_UNLIKELY(!a.nnn || !b.nnn))
            return null_payload(a.nnn, b.nnn);
        return equal(a.nnn->value, b.nnn->value, MatchFailureKind::NumberValue);
    case mop_S: // Stack variable
        if (SIMD_UNLIKELY(!a.s || !b.s))
            return null_payload(a.s, b.s);
        if (a.s->mba != b.s->mba)
            return reject(MatchFailureKind::FrameOwner);
        return equal(a.s->off, b.s->off, MatchFailureKind::StackOffset);
    case mop_v: // Global variable - single uint64 comparison
        return equal(a.g, b.g, MatchFailureKind::GlobalAddress);
    case mop_l: // Local variable
        if (SIMD_UNLIKELY(!a.l || !b.l))
            return null_payload(a.l, b.l);
        if (a.l->mba != b.l->mba)
            return reject(MatchFailureKind::FrameOwner);
        return equal(a.l->idx, b.l->idx, MatchFailureKind::LocalIndex) &&
               equal(a.l->off, b.l->off, MatchFailureKind::LocalOffset);
    case mop_d: // Result of another instruction
        if (SIMD_UNLIKELY(!a.d || !b.d))
            return null_payload(a.d, b.d);
        return equal(a.d->opcode, b.d->opcode, MatchFailureKind::NestedOpcode) &&
               equal(a.d->iprops, b.d->iprops, MatchFailureKind::InstructionProps) &&
               (a.d->opcode != m_ldx || equal(a.d->ea, b.d->ea, MatchFailureKind::LoadSource)) &&
               mops_equal_strict_internal(a.d->d, b.d->d, depth + 1, visited, difference) &&
               mops_equal_strict_internal(a.d->l, b.d->l, depth + 1, visited, difference) &&
               mops_equal_strict_internal(a.d->r, b.d->r, depth + 1, visited, difference);
    case mop_b: // Block reference
        return equal(a.b, b.b, MatchFailureKind::BlockIdentity);
    case mop_f:                                              // Function call
        return reject(MatchFailureKind::UnsupportedOperand); // Too complex to compare
    case mop_a:                                              // Address
        if (SIMD_UNLIKELY(!a.a || !b.a))
            return null_payload(a.a, b.a);
        if (!equal(a.a->insize, b.a->insize, MatchFailureKind::AddressInputSize) ||
            !equal(a.a->outsize, b.a->outsize, MatchFailureKind::AddressOutputSize))
            return false;
        return mops_equal_strict_internal(*a.a, *b.a, depth + 1, visited, difference);
    case mop_h: // Helper function
        if (SIMD_UNLIKELY(!a.helper || !b.helper))
            return null_payload(a.helper, b.helper);
        return strcmp(a.helper, b.helper) == 0 || reject(MatchFailureKind::TextValue);
    case mop_str: // String
        if (SIMD_UNLIKELY(!a.cstr || !b.cstr))
            return null_payload(a.cstr, b.cstr);
        return strcmp(a.cstr, b.cstr) == 0 || reject(MatchFailureKind::TextValue);
    case mop_z: // Empty
        return true;
    default:
        return reject(MatchFailureKind::UnsupportedOperand);
    }
}

bool mops_equal_strict(const mop_t &a, const mop_t &b, MatchFailure *failure)
{
    unsigned visited = 0;
    OperandDifference difference;
    const bool equal =
        mops_equal_strict_internal(a, b, 0, visited, failure ? &difference : nullptr);
    if (failure)
        *failure = {difference.kind,       0,    {}, {}, difference.expected, difference.actual,
                    difference.has_values, false};
    return equal;
}

//--------------------------------------------------------------------------
// AstBase implementation
//--------------------------------------------------------------------------
AstBase::AstBase(const AstBase &other) : dest_size(other.dest_size), ea(other.ea), mop(other.mop) {}

//--------------------------------------------------------------------------
// AstNode implementation
//--------------------------------------------------------------------------
AstNode::AstNode(mcode_t op, AstPtr l, AstPtr r) : opcode(op), left(l), right(r) {}

AstNode::AstNode(const AstNode &other)
    : AstBase(other), opcode(other.opcode), left(other.left ? other.left->clone() : nullptr),
      right(other.right ? other.right->clone() : nullptr), dst_mop(other.dst_mop)
{
}

AstPtr AstNode::clone() const { return std::make_shared<AstNode>(*this); }

//--------------------------------------------------------------------------
// AstLeaf implementation
//--------------------------------------------------------------------------
AstLeaf::AstLeaf(const std::string &n) : name(n) {}

AstLeaf::AstLeaf(const mop_t &m) : name(name_from_mop(m))
{
    mop = m;
    dest_size = m.size;
}

AstLeaf::AstLeaf(const AstLeaf &other) : AstBase(other), name(other.name) {}

AstPtr AstLeaf::clone() const { return std::make_shared<AstLeaf>(*this); }

std::string AstLeaf::name_from_mop(const mop_t &m)
{
    std::ostringstream ss;
    switch (m.t)
    {
    case mop_r:
        ss << "r" << m.r;
        break;
    case mop_S:
        if (m.s)
            ss << "s" << std::hex << m.s->off;
        else
            ss << "s_null";
        break;
    case mop_v:
        ss << "g" << std::hex << m.g;
        break;
    case mop_l:
        if (m.l)
            ss << "l" << m.l->idx << "_" << m.l->off;
        else
            ss << "l_null";
        break;
    case mop_n:
        if (m.nnn)
            ss << "n" << std::hex << m.nnn->value;
        else
            ss << "n_null";
        break;
    case mop_d:
        if (m.d)
            ss << "d_" << m.d->dstr();
        else
            ss << "d_null";
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
AstConstant::AstConstant(uint64_t v, int size) : AstLeaf(""), value(v)
{
    dest_size = size;
    name = std::to_string(v);
}

AstConstant::AstConstant(const std::string &n, uint64_t v) : AstLeaf(""), value(v), const_name(n)
{
    name = n;
}

AstConstant::AstConstant(const AstConstant &other)
    : AstLeaf(other), value(other.value), const_name(other.const_name)
{
}

AstPtr AstConstant::clone() const { return std::make_shared<AstConstant>(*this); }

//--------------------------------------------------------------------------
// Non-mutating pattern match implementation - OPTIMIZED
// Matches pattern against candidate without modifying either AST
//--------------------------------------------------------------------------

// Internal recursive match function
struct MatchTrace
{
    MatchFailure *failure = nullptr;
    size_t matched_nodes = 0;
    std::string pattern_path, candidate_path;
    bool path_truncated = false;

    bool reject(MatchFailureKind kind, uint64_t expected = 0, uint64_t actual = 0,
                bool has_values = false)
    {
        if (failure &&
            (failure->kind == MatchFailureKind::None || matched_nodes > failure->matched_nodes))
            *failure = {kind,     matched_nodes, pattern_path, candidate_path,
                        expected, actual,        has_values,   path_truncated};
        return false;
    }
    bool accept()
    {
        ++matched_nodes;
        return true;
    }
};

struct MatchPathScope
{
    MatchTrace &trace;
    size_t pattern_size, candidate_size;
    bool truncated;
    MatchPathScope(MatchTrace &value, char pattern, char candidate)
        : trace(value), pattern_size(value.pattern_path.size()),
          candidate_size(value.candidate_path.size()), truncated(value.path_truncated)
    {
        if (!trace.failure)
            return;
        if (pattern_size < match_path_byte_limit)
            trace.pattern_path.push_back(pattern);
        else
            trace.path_truncated = true;
        if (candidate_size < match_path_byte_limit)
            trace.candidate_path.push_back(candidate);
        else
            trace.path_truncated = true;
    }
    ~MatchPathScope()
    {
        trace.pattern_path.resize(pattern_size);
        trace.candidate_path.resize(candidate_size);
        trace.path_truncated = truncated;
    }
};

static bool match_pattern_internal(const AstBase *pattern, const AstBase *candidate,
                                   MatchBindings &bindings, MatchTrace &trace)
{
    if (!pattern || !candidate)
    {
        return pattern == candidate ? trace.accept() : trace.reject(MatchFailureKind::NullTree);
    }

    const auto capture = [&](const std::string &name)
    {
        const mop_t *existing = bindings.find(name);
        if (existing)
        {
            OperandDifference difference;
            unsigned visited = 0;
            if (!mops_equal_strict_internal(*existing, candidate->mop, 0, visited, &difference))
                return trace.reject(difference.kind, difference.expected, difference.actual,
                                    difference.has_values);
            return trace.accept();
        }
        return bindings.add(name.c_str(), candidate->mop, candidate->dest_size, candidate->ea)
                   ? trace.accept()
                   : trace.reject(MatchFailureKind::BindingCapacity);
    };

    // Handle leaf patterns
    if (pattern->is_leaf())
    {
        if (pattern->is_constant())
        {
            // Constant pattern - candidate must be a constant with matching value
            auto pat_const = static_cast<const AstConstant *>(pattern);

            // Candidate must have a number operand
            if (candidate->mop.t != mop_n)
            {
                return trace.reject(MatchFailureKind::NumericRequired, mop_n, candidate->mop.t,
                                    true);
            }
            if (!candidate->mop.nnn)
                return trace.reject(MatchFailureKind::NullPayload);

            // Named constants (like c_minus_1) - just capture binding
            if (!pat_const->const_name.empty())
            {
                return capture(pat_const->const_name);
            }

            // Value constants must match
            uint64_t expected = pat_const->value;
            uint64_t actual = candidate->mop.nnn->value;
            uint64_t mask = size_mask(candidate->mop.size);
            return (expected & mask) == (actual & mask)
                       ? trace.accept()
                       : trace.reject(MatchFailureKind::ConstantValue, expected & mask,
                                      actual & mask, true);
        }

        // Variable leaf - capture binding
        auto pat_leaf = static_cast<const AstLeaf *>(pattern);

        return capture(pat_leaf->name);
    }

    // Pattern is a node - candidate must also be a node
    if (!candidate->is_node())
    {
        return trace.reject(MatchFailureKind::NodeRequired);
    }

    auto pat_node = static_cast<const AstNode *>(pattern);
    auto cand_node = static_cast<const AstNode *>(candidate);

    // Opcode must match
    if (pat_node->opcode != cand_node->opcode)
    {
        return trace.reject(MatchFailureKind::Opcode, pat_node->opcode, cand_node->opcode, true);
    }

    // Operand arity must match exactly. Keep a binding-count checkpoint so a
    // failed branch cannot leak captures into the commuted alternative.
    if (static_cast<bool>(pat_node->left) != static_cast<bool>(cand_node->left) ||
        static_cast<bool>(pat_node->right) != static_cast<bool>(cand_node->right))
    {
        const auto arity = [](const AstNode *node)
        { return unsigned(bool(node->left)) | (unsigned(bool(node->right)) << 1); };
        return trace.reject(MatchFailureKind::Arity, arity(pat_node), arity(cand_node), true);
    }

    trace.accept();
    const size_t saved_count = bindings.count;
    const size_t saved_nodes = trace.matched_nodes;
    const auto match_operands =
        [&](const AstBase *candidate_left, const AstBase *candidate_right, bool swapped)
    {
        if (pat_node->left)
        {
            MatchPathScope path(trace, 'L', swapped ? 'R' : 'L');
            if (!match_pattern_internal(pat_node->left.get(), candidate_left, bindings, trace))
                return false;
        }
        if (pat_node->right)
        {
            MatchPathScope path(trace, 'R', swapped ? 'L' : 'R');
            if (!match_pattern_internal(pat_node->right.get(), candidate_right, bindings, trace))
                return false;
        }
        return true;
    };

    if (match_operands(cand_node->left.get(), cand_node->right.get(), false))
    {
        return true;
    }
    bindings.count = saved_count;
    trace.matched_nodes = saved_nodes;

    // These microcode operations are commutative over fixed-width bit-vectors.
    // Try the swapped form lazily instead of pre-generating factorially many
    // pattern variants at registry initialization.
    const bool commutative =
        pat_node->right &&
        (pat_node->opcode == m_add || pat_node->opcode == m_mul || pat_node->opcode == m_and ||
         pat_node->opcode == m_or || pat_node->opcode == m_xor);
    if (commutative && match_operands(cand_node->right.get(), cand_node->left.get(), true))
    {
        return true;
    }

    bindings.count = saved_count;
    trace.matched_nodes = saved_nodes;
    return false;
}

const char *match_failure_kind_name(MatchFailureKind kind)
{
    static constexpr const char *names[] = {
        "none",
        "null_tree",
        "numeric_required",
        "node_required",
        "opcode",
        "arity",
        "constant_value",
        "operand_kind",
        "operand_width",
        "value_number",
        "operand_properties",
        "null_payload",
        "register_identity",
        "number_value",
        "frame_owner",
        "stack_offset",
        "global_address",
        "local_index",
        "local_offset",
        "nested_opcode",
        "instruction_props",
        "load_source",
        "address_input_size",
        "address_output_size",
        "block_identity",
        "text_value",
        "unsupported_mop",
        "comparison_budget",
        "binding_capacity",
    };
    const auto index = static_cast<size_t>(kind);
    return index < std::size(names) ? names[index] : "invalid";
}

std::string match_failure_detail(const MatchFailure &failure)
{
    if (failure.kind == MatchFailureKind::None)
        return {};
    std::ostringstream out;
    out << "match_failed;kind=" << match_failure_kind_name(failure.kind) << ";p="
        << (failure.pattern_path.empty() ? "-"
                                         : failure.pattern_path.substr(0, match_path_byte_limit))
        << ";c="
        << (failure.candidate_path.empty()
                ? "-"
                : failure.candidate_path.substr(0, match_path_byte_limit))
        << ";nodes=" << failure.matched_nodes;
    if (failure.has_values)
        out << ";e=0x" << std::hex << failure.expected << ";a=0x" << failure.actual;
    out << ";cut="
        << int(failure.path_truncated || failure.pattern_path.size() > match_path_byte_limit ||
               failure.candidate_path.size() > match_path_byte_limit);
    return out.str();
}

bool match_pattern(const AstBase *pattern, const AstBase *candidate, MatchBindings &bindings,
                   MatchFailure *failure)
{
    bindings.clear();
    if (failure)
        *failure = {};
    MatchTrace trace;
    trace.failure = failure;
    const bool matched = match_pattern_internal(pattern, candidate, bindings, trace);
    if (matched && failure)
        *failure = {};
    return matched;
}

} // namespace ast
} // namespace chernobog
