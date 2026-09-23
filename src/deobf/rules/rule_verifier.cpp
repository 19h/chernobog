#include "rule_verifier.h"
#include "../../common/bitvector.h"
#include "../../common/solver_evidence.hpp"
#include <array>
#include <atomic>
#include <cstdint>
#include <utility>
#include <vector>

namespace chernobog
{
namespace rules
{

using namespace ast;

namespace
{
struct InstanceCounters
{
    std::atomic<size_t> verified{0}, disproved{0}, unsupported{0}, unknown{0};
} instance_stats;
// This translator deliberately does not use AST deduplication or printed
// operand names: the proof must see the original typed microcode on both sides.
struct InstanceTranslator
{
    z3::context &context;
    std::unordered_map<std::string, z3::expr> variables;
    size_t visited = 0;
    std::string error;

    std::optional<z3::expr> reject(const char *reason)
    {
        error = reason;
        return {};
    }

    std::optional<z3::expr> operand(const mop_t &value, unsigned depth)
    {
        if (depth > 64 || ++visited > 512)
            return reject("expression budget exceeded");
        if (!bitvector::valid_byte_width(value.size) || value.probably_floating() ||
            value.is_udt() || value.is_undef_val())
            return reject("unsupported operand width or value properties");
        const unsigned bits = unsigned(value.size * 8);
        if (value.t == mop_n && value.nnn)
            // uint64 is unsigned long long, which is distinct from uint64_t on LP64 targets and
            // makes every bv_val() overload an equally ranked conversion. Name the width exactly.
            return context.bv_val(std::uint64_t(value.nnn->value), bits);
        if (value.t == mop_d && value.d)
        {
            if (value.size != value.d->d.size)
                return reject("nested result width mismatch");
            return instruction(value.d, depth + 1);
        }
        std::string identity = std::to_string(value.t) + ":" + std::to_string(value.size) + ":";
        switch (value.t)
        {
        case mop_r:
            identity += std::to_string(value.r);
            break;
        case mop_v:
            identity += std::to_string(value.g);
            break;
        case mop_S:
            if (!value.s)
                return reject("missing stack operand");
            identity += std::to_string(reinterpret_cast<uintptr_t>(value.s->mba)) + ":" +
                        std::to_string(value.s->off);
            break;
        case mop_l:
            if (!value.l)
                return reject("missing local operand");
            identity += std::to_string(reinterpret_cast<uintptr_t>(value.l->mba)) + ":" +
                        std::to_string(value.l->idx) + ":" + std::to_string(value.l->off);
            break;
        default:
            return reject("unsupported operand or memory effect");
        }
        auto found = variables.find(identity);
        if (found != variables.end())
            return found->second;
        const auto symbol = context.bv_const(("instance:" + identity).c_str(), bits);
        return variables.emplace(identity, symbol).first->second;
    }

    std::optional<z3::expr> instruction(const minsn_t *value, unsigned depth = 0)
    {
        if (!value || depth > 64 || ++visited > 512)
            return reject("expression budget exceeded");
        if (!bitvector::valid_byte_width(value->d.size) || value->is_fpinsn() ||
            value->d.probably_floating() || value->d.is_udt() || value->d.is_undef_val() ||
            value->is_mbarrier() || value->is_assert() || value->is_persistent() ||
            !value->is_combinable() || !value->is_propagatable())
            return reject("unsupported instruction width or effects");
        switch (value->opcode)
        {
        case m_mov:
        case m_bnot:
        case m_neg:
        case m_xdu:
        case m_xds:
        case m_low:
        case m_high:
        case m_add:
        case m_sub:
        case m_mul:
        case m_and:
        case m_or:
        case m_xor:
            break;
        default:
            return reject("unsupported instruction opcode or effects");
        }
        auto left = operand(value->l, depth + 1);
        if (!left)
            return {};
        const unsigned bits = unsigned(value->d.size * 8);
        const unsigned left_bits = left->get_sort().bv_size();
        const bool binary = value->opcode == m_add || value->opcode == m_sub ||
                            value->opcode == m_mul || value->opcode == m_and ||
                            value->opcode == m_or || value->opcode == m_xor;
        if (!binary && value->r.t != mop_z)
            return reject("unexpected unary right operand");
        if (value->opcode == m_xdu || value->opcode == m_xds)
        {
            if (left_bits > bits)
                return reject("extension narrows its input");
            return value->opcode == m_xdu ? z3::zext(*left, bits - left_bits)
                                          : z3::sext(*left, bits - left_bits);
        }
        if (value->opcode == m_low || value->opcode == m_high)
        {
            if (left_bits < bits)
                return reject("extraction widens its input");
            return value->opcode == m_low ? left->extract(bits - 1, 0)
                                          : left->extract(left_bits - 1, left_bits - bits);
        }
        if (left_bits != bits)
            return reject("implicit left width conversion");
        if (value->opcode == m_mov)
            return left;
        if (value->opcode == m_bnot)
            return ~*left;
        if (value->opcode == m_neg)
            return -*left;
        auto right = operand(value->r, depth + 1);
        if (!right)
            return {};
        if (right->get_sort().bv_size() != bits)
            return reject("implicit right width conversion");
        switch (value->opcode)
        {
        case m_add:
            return *left + *right;
        case m_sub:
            return *left - *right;
        case m_mul:
            return *left * *right;
        case m_and:
            return *left & *right;
        case m_or:
            return *left | *right;
        case m_xor:
            return *left ^ *right;
        default:
            return reject("unsupported instruction opcode");
        }
    }
};
} // namespace

InstanceVerificationStats instance_verification_stats()
{
    return {instance_stats.verified.load(), instance_stats.disproved.load(),
            instance_stats.unsupported.load(), instance_stats.unknown.load()};
}
void reset_instance_verification_stats()
{
    instance_stats.verified = 0;
    instance_stats.disproved = 0;
    instance_stats.unsupported = 0;
    instance_stats.unknown = 0;
}

RuleVerificationResult RuleVerifier::verify_instance(const minsn_t *original,
                                                     const minsn_t *replacement)
{
    const auto result = verify_instance_impl(original, replacement);
    switch (result.status)
    {
    case RuleVerificationStatus::VERIFIED:
        ++instance_stats.verified;
        break;
    case RuleVerificationStatus::DISPROVED:
        ++instance_stats.disproved;
        break;
    case RuleVerificationStatus::UNSUPPORTED:
        ++instance_stats.unsupported;
        break;
    case RuleVerificationStatus::UNKNOWN:
        ++instance_stats.unknown;
        break;
    }
    return result;
}

RuleVerificationResult RuleVerifier::verify_instance_impl(const minsn_t *original,
                                                          const minsn_t *replacement)
{
    solver_evidence::SiteScope query_site(original ? uint64_t(original->ea) : UINT64_MAX);
    if (!original || !replacement || original->d.size != replacement->d.size)
        return {RuleVerificationStatus::UNSUPPORTED, 0, "missing tree or unequal output widths"};
    const unsigned bits =
        bitvector::valid_byte_width(original->d.size) ? unsigned(original->d.size * 8) : 0;
    try
    {
        InstanceTranslator translator{context_, {}, 0, {}};
        const auto before = translator.instruction(original);
        if (!before)
            return {RuleVerificationStatus::UNSUPPORTED, bits, translator.error};
        const auto after = translator.instruction(replacement);
        if (!after)
            return {RuleVerificationStatus::UNSUPPORTED, bits, translator.error};
        const z3::expr equality = (*before == *after).simplify();
        if (equality.is_true())
            return {RuleVerificationStatus::VERIFIED, bits, "typed instance equivalent"};
        solver_.reset();
        z3::params parameters(context_);
        parameters.set("timeout", timeout_ms_);
        if (resource_limit_ != 0)
            parameters.set("rlimit", resource_limit_);
        solver_.set(parameters);
        solver_.add(!equality);
        const std::string parameters_text = "timeout_ms=" + std::to_string(timeout_ms_) +
                                            ";rlimit=" + std::to_string(resource_limit_);
        const auto result = solver_evidence::check(solver_, "typed-MBA replacement mismatch",
                                                   parameters_text.c_str());
        if (result == z3::unsat)
            return {RuleVerificationStatus::VERIFIED, bits,
                    "typed instance mismatch unsatisfiable"};
        if (result == z3::sat)
            return {RuleVerificationStatus::DISPROVED, bits,
                    "typed instance counterexample exists"};
        return {RuleVerificationStatus::UNKNOWN, bits, solver_.reason_unknown()};
    }
    catch (const z3::exception &exception)
    {
        return {RuleVerificationStatus::UNKNOWN, bits, exception.msg()};
    }
}

const char *rule_verification_status_name(RuleVerificationStatus status)
{
    switch (status)
    {
    case RuleVerificationStatus::VERIFIED:
        return "verified";
    case RuleVerificationStatus::DISPROVED:
        return "disproved";
    case RuleVerificationStatus::UNSUPPORTED:
        return "unsupported";
    case RuleVerificationStatus::UNKNOWN:
        return "unknown";
    }
    return "unknown";
}

RuleVerifier::RuleVerifier(unsigned timeout_ms, unsigned resource_limit)
    : solver_(context_), timeout_ms_(timeout_ms), resource_limit_(resource_limit)
{
}

std::optional<uint64_t> RuleVerifier::constant_value(const AstConstant &constant,
                                                     std::string &error) const
{
    if (constant.const_name.empty())
        return constant.value;

    if (constant.const_name == "c_minus_1")
        return UINT64_MAX;
    if (constant.const_name == "c_minus_2")
        return UINT64_MAX - uint64_t{1};

    error = "unsupported named constant '" + constant.const_name + "'";
    return std::nullopt;
}

std::optional<z3::expr> RuleVerifier::translate(const AstBase *expression, unsigned bit_width,
                                                const std::string &symbol_prefix,
                                                VariableMap &variables, std::string &error)
{
    if (!expression)
    {
        error = "null AST expression";
        return std::nullopt;
    }

    if (expression->is_constant())
    {
        const auto &constant = static_cast<const AstConstant &>(*expression);
        auto value = constant_value(constant, error);
        if (!value)
            return std::nullopt;
        return context_.bv_val(*value, bit_width);
    }

    if (expression->is_leaf())
    {
        const auto &leaf = static_cast<const AstLeaf &>(*expression);
        auto existing = variables.find(leaf.name);
        if (existing != variables.end())
            return existing->second;

        const std::string symbol = symbol_prefix + leaf.name;
        z3::expr variable = context_.bv_const(symbol.c_str(), bit_width);
        auto inserted = variables.emplace(leaf.name, variable);
        return inserted.first->second;
    }

    const auto &node = static_cast<const AstNode &>(*expression);
    auto left = translate(node.left.get(), bit_width, symbol_prefix, variables, error);
    if (!left)
        return std::nullopt;

    if (node.opcode == m_bnot)
        return ~*left;
    if (node.opcode == m_neg)
        return -*left;

    if (!node.right)
    {
        error = std::string("unsupported unary opcode ") + opcode_name(node.opcode);
        return std::nullopt;
    }

    auto right = translate(node.right.get(), bit_width, symbol_prefix, variables, error);
    if (!right)
        return std::nullopt;

    switch (node.opcode)
    {
    case m_add:
        return *left + *right;
    case m_sub:
        return *left - *right;
    case m_mul:
        return *left * *right;
    case m_and:
        return *left & *right;
    case m_or:
        return *left | *right;
    case m_xor:
        return *left ^ *right;
    default:
        error = std::string("unsupported binary opcode ") + opcode_name(node.opcode);
        return std::nullopt;
    }
}

RuleVerificationResult RuleVerifier::verify(const AstPtr &pattern, const AstPtr &replacement)
{
    if (!pattern || !replacement)
    {
        return {RuleVerificationStatus::UNSUPPORTED, 0, "pattern or replacement is null"};
    }

    try
    {
        static constexpr std::array<unsigned, 4> BIT_WIDTHS = {8, 16, 32, 64};
        std::vector<std::pair<unsigned, z3::expr>> mismatches;
        mismatches.reserve(BIT_WIDTHS.size());

        for (unsigned bit_width : BIT_WIDTHS)
        {
            VariableMap variables;
            std::string error;
            const std::string prefix = "w" + std::to_string(bit_width) + "_";
            auto lhs = translate(pattern.get(), bit_width, prefix, variables, error);
            auto rhs = translate(replacement.get(), bit_width, prefix, variables, error);
            if (!lhs || !rhs)
            {
                return {RuleVerificationStatus::UNSUPPORTED, bit_width, std::move(error)};
            }

            z3::expr equality = (*lhs == *rhs).simplify();
            if (equality.is_true())
                continue;
            if (equality.is_false())
            {
                return {RuleVerificationStatus::DISPROVED, bit_width,
                        "simplification produced a counterexample-independent mismatch"};
            }
            mismatches.emplace_back(bit_width, !equality);
        }

        if (mismatches.empty())
        {
            return {RuleVerificationStatus::VERIFIED, 64, "equivalent at 8, 16, 32, and 64 bits"};
        }

        z3::expr_vector disjunction(context_);
        for (const auto &mismatch : mismatches)
            disjunction.push_back(mismatch.second);

        solver_.reset();
        z3::params parameters(context_);
        parameters.set("timeout", timeout_ms_);
        if (resource_limit_ != 0)
            parameters.set("rlimit", resource_limit_);
        solver_.set(parameters);
        solver_.add(z3::mk_or(disjunction));

        z3::check_result result = solver_evidence::check(solver_, "catalog identity mismatch");
        if (result == z3::sat)
        {
            const z3::model model = solver_.get_model();
            for (const auto &mismatch : mismatches)
            {
                if (model.eval(mismatch.second, true).is_true())
                {
                    return {RuleVerificationStatus::DISPROVED, mismatch.first,
                            "counterexample exists"};
                }
            }
            return {RuleVerificationStatus::DISPROVED, 0,
                    "counterexample exists at an unidentified width"};
        }
        if (result == z3::unknown)
        {
            return {RuleVerificationStatus::UNKNOWN, 0, solver_.reason_unknown()};
        }
    }
    catch (const z3::exception &exception)
    {
        return {RuleVerificationStatus::UNKNOWN, 0, exception.msg()};
    }

    return {RuleVerificationStatus::VERIFIED, 64, "equivalent at 8, 16, 32, and 64 bits"};
}

} // namespace rules
} // namespace chernobog
