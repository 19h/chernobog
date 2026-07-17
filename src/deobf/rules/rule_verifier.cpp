#include "rule_verifier.h"
#include <array>
#include <utility>
#include <vector>

namespace chernobog {
namespace rules {

using namespace ast;

const char* rule_verification_status_name(RuleVerificationStatus status)
{
    switch ( status )
    {
        case RuleVerificationStatus::VERIFIED: return "verified";
        case RuleVerificationStatus::DISPROVED: return "disproved";
        case RuleVerificationStatus::UNSUPPORTED: return "unsupported";
        case RuleVerificationStatus::UNKNOWN: return "unknown";
    }
    return "unknown";
}

RuleVerifier::RuleVerifier(unsigned timeout_ms)
    : solver_(context_)
    , timeout_ms_(timeout_ms)
{
}

std::optional<uint64_t> RuleVerifier::constant_value(
    const AstConstant& constant,
    std::string& error) const
{
    if ( constant.const_name.empty() )
        return constant.value;

    if ( constant.const_name == "c_minus_1" )
        return UINT64_MAX;
    if ( constant.const_name == "c_minus_2" )
        return UINT64_MAX - uint64_t{1};

    error = "unsupported named constant '" + constant.const_name + "'";
    return std::nullopt;
}

std::optional<z3::expr> RuleVerifier::translate(const AstBase* expression,
                                                unsigned bit_width,
                                                const std::string& symbol_prefix,
                                                VariableMap& variables,
                                                std::string& error)
{
    if ( !expression )
    {
        error = "null AST expression";
        return std::nullopt;
    }

    if ( expression->is_constant() )
    {
        const auto& constant = static_cast<const AstConstant&>(*expression);
        auto value = constant_value(constant, error);
        if ( !value )
            return std::nullopt;
        return context_.bv_val(*value, bit_width);
    }

    if ( expression->is_leaf() )
    {
        const auto& leaf = static_cast<const AstLeaf&>(*expression);
        auto existing = variables.find(leaf.name);
        if ( existing != variables.end() )
            return existing->second;

        const std::string symbol = symbol_prefix + leaf.name;
        z3::expr variable = context_.bv_const(symbol.c_str(), bit_width);
        auto inserted = variables.emplace(leaf.name, variable);
        return inserted.first->second;
    }

    const auto& node = static_cast<const AstNode&>(*expression);
    auto left = translate(node.left.get(), bit_width, symbol_prefix,
                          variables, error);
    if ( !left )
        return std::nullopt;

    if ( node.opcode == m_bnot )
        return ~*left;
    if ( node.opcode == m_neg )
        return -*left;

    if ( !node.right )
    {
        error = std::string("unsupported unary opcode ") + opcode_name(node.opcode);
        return std::nullopt;
    }

    auto right = translate(node.right.get(), bit_width, symbol_prefix,
                           variables, error);
    if ( !right )
        return std::nullopt;

    switch ( node.opcode )
    {
        case m_add: return *left + *right;
        case m_sub: return *left - *right;
        case m_mul: return *left * *right;
        case m_and: return *left & *right;
        case m_or: return *left | *right;
        case m_xor: return *left ^ *right;
        default:
            error = std::string("unsupported binary opcode ") + opcode_name(node.opcode);
            return std::nullopt;
    }
}

RuleVerificationResult RuleVerifier::verify(const AstPtr& pattern,
                                            const AstPtr& replacement)
{
    if ( !pattern || !replacement )
    {
        return {RuleVerificationStatus::UNSUPPORTED, 0,
                "pattern or replacement is null"};
    }

    try
    {
        static constexpr std::array<unsigned, 4> BIT_WIDTHS = {8, 16, 32, 64};
        std::vector<std::pair<unsigned, z3::expr>> mismatches;
        mismatches.reserve(BIT_WIDTHS.size());

        for ( unsigned bit_width : BIT_WIDTHS )
        {
            VariableMap variables;
            std::string error;
            const std::string prefix = "w" + std::to_string(bit_width) + "_";
            auto lhs = translate(pattern.get(), bit_width, prefix,
                                 variables, error);
            auto rhs = translate(replacement.get(), bit_width, prefix,
                                 variables, error);
            if ( !lhs || !rhs )
            {
                return {RuleVerificationStatus::UNSUPPORTED, bit_width,
                        std::move(error)};
            }

            z3::expr equality = (*lhs == *rhs).simplify();
            if ( equality.is_true() )
                continue;
            if ( equality.is_false() )
            {
                return {RuleVerificationStatus::DISPROVED, bit_width,
                        "simplification produced a counterexample-independent mismatch"};
            }
            mismatches.emplace_back(bit_width, !equality);
        }

        if ( mismatches.empty() )
        {
            return {RuleVerificationStatus::VERIFIED, 64,
                    "equivalent at 8, 16, 32, and 64 bits"};
        }

        z3::expr_vector disjunction(context_);
        for ( const auto& mismatch : mismatches )
            disjunction.push_back(mismatch.second);

        solver_.reset();
        z3::params parameters(context_);
        parameters.set("timeout", timeout_ms_);
        solver_.set(parameters);
        solver_.add(z3::mk_or(disjunction));

        z3::check_result result = solver_.check();
        if ( result == z3::sat )
        {
            const z3::model model = solver_.get_model();
            for ( const auto& mismatch : mismatches )
            {
                if ( model.eval(mismatch.second, true).is_true() )
                {
                    return {RuleVerificationStatus::DISPROVED, mismatch.first,
                            "counterexample exists"};
                }
            }
            return {RuleVerificationStatus::DISPROVED, 0,
                    "counterexample exists at an unidentified width"};
        }
        if ( result == z3::unknown )
        {
            return {RuleVerificationStatus::UNKNOWN, 0,
                    solver_.reason_unknown()};
        }
    }
    catch ( const z3::exception& exception )
    {
        return {RuleVerificationStatus::UNKNOWN, 0, exception.msg()};
    }

    return {RuleVerificationStatus::VERIFIED, 64,
            "equivalent at 8, 16, 32, and 64 bits"};
}

} // namespace rules
} // namespace chernobog
