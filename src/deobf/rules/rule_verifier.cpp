#include "rule_verifier.h"
#include "../../common/bitvector.h"
#include "../../common/solver_evidence.hpp"
#include <array>
#include <cstdint>
#include <mutex>
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
    std::mutex mutex;
    InstanceVerificationStats values;
} instance_stats;
// This translator deliberately does not use AST deduplication or printed
// operand names: the proof must see the original typed microcode on both sides.
struct InstanceTranslator
{
    struct Load
    {
        std::string branch;
        z3::expr selector, address;
        unsigned bits;
        ea_t source;
    };
    z3::context &context;
    std::unordered_map<std::string, z3::expr> variables;
    size_t visited = 0;
    std::string error;
    std::vector<Load> loads;
    bool load_address = false;
    bool implicit_memory = false;

    std::optional<z3::expr> reject(const char *reason)
    {
        error = reason;
        return {};
    }

    std::optional<z3::expr> operand(const mop_t &value, unsigned depth, const std::string &branch)
    {
        if (depth > 64 || ++visited > 512)
            return reject("expression budget exceeded");
        if (load_address && value.oprops != 0)
            return reject("unsupported load-address operand properties");
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
            return instruction(value.d, depth + 1, branch);
        }
        std::string identity = std::to_string(value.t) + ":" + std::to_string(value.size) + ":" +
                               std::to_string(value.valnum) + ":";
        switch (value.t)
        {
        case mop_r:
            identity += std::to_string(value.r);
            break;
        case mop_v:
            if (load_address)
                return reject("implicit memory in load address");
            implicit_memory = true;
            identity += std::to_string(value.g);
            break;
        case mop_S:
            if (load_address)
                return reject("implicit memory in load address");
            implicit_memory = true;
            if (!value.s)
                return reject("missing stack operand");
            identity += std::to_string(reinterpret_cast<uintptr_t>(value.s->mba)) + ":" +
                        std::to_string(value.s->off);
            break;
        case mop_l:
            if (load_address)
                return reject("implicit memory in load address");
            implicit_memory = true;
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

    std::optional<z3::expr> instruction(const minsn_t *value, unsigned depth = 0,
                                        const std::string &branch = {})
    {
        if (!value || depth > 64 || ++visited > 512)
            return reject("expression budget exceeded");
        if (depth != 0 && value->d.t != mop_z)
            return reject("nested instruction has explicit destination");
        if (load_address && (value->iprops != 0 || value->d.oprops != 0))
            return reject("unsupported load-address instruction properties");
        if (!bitvector::valid_byte_width(value->d.size) || value->is_fpinsn() ||
            value->d.probably_floating() || value->d.is_udt() || value->d.is_undef_val() ||
            value->is_mbarrier() || value->is_assert() || value->is_persistent() ||
            !value->is_combinable() || !value->is_propagatable())
            return reject("unsupported instruction width or effects");
        if (value->opcode == m_ldx)
        {
            if (load_address)
                return reject("nested memory read in load address");
            // Explicit selector/offset loads may remain opaque value inputs only
            // when every occurrence, binary branch, address, width and source EA
            // survives. No equality between separate reads is assumed, including
            // aliased addresses or externally changing memory.
            if (value->iprops != 0 || value->d.oprops != 0 || value->l.oprops != 0 ||
                value->r.oprops != 0 || value->l.size != 2 ||
                (value->r.size != 4 && value->r.size != 8))
                return reject("unsupported explicit load width or properties");
            struct AddressScope
            {
                bool &active;
                explicit AddressScope(bool &flag) : active(flag) { active = true; }
                ~AddressScope() { active = false; }
            } address_scope(load_address);
            auto selector = operand(value->l, depth + 1, branch);
            if (!selector)
                return {};
            auto address = operand(value->r, depth + 1, branch);
            if (!address)
                return {};
            const unsigned bits = unsigned(value->d.size * 8);
            const std::string symbol = "instance:read:" + std::to_string(loads.size());
            loads.push_back({branch, *selector, *address, bits, value->ea});
            return context.bv_const(symbol.c_str(), bits);
        }
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
        case m_lnot:
        case m_sets:
        case m_cfadd:
        case m_ofadd:
        case m_seto:
        case m_setp:
        case m_setnz:
        case m_setz:
        case m_setae:
        case m_setb:
        case m_seta:
        case m_setbe:
        case m_setg:
        case m_setge:
        case m_setl:
        case m_setle:
            break;
        default:
            return reject("unsupported instruction opcode or effects");
        }
        const bool comparison = value->opcode >= m_setnz && value->opcode <= m_setle;
        const bool flag = value->opcode == m_cfadd || value->opcode == m_ofadd ||
                          value->opcode == m_seto || value->opcode == m_setp;
        const bool binary = comparison || flag || value->opcode == m_add ||
                            value->opcode == m_sub || value->opcode == m_mul ||
                            value->opcode == m_and || value->opcode == m_or ||
                            value->opcode == m_xor;
        auto left = operand(value->l, depth + 1, binary ? branch + "L" : branch);
        if (!left)
            return {};
        const unsigned bits = unsigned(value->d.size * 8);
        const unsigned left_bits = left->get_sort().bv_size();
        if (!binary && value->r.t != mop_z)
            return reject("unexpected unary right operand");
        const auto boolean_value = [&](const z3::expr &condition)
        { return z3::ite(condition, context.bv_val(1, bits), context.bv_val(0, bits)); };
        if (value->opcode == m_lnot)
            return boolean_value(*left == 0);
        if (value->opcode == m_sets || comparison || flag)
        {
            if (bits != 8)
                return reject("comparison result must be one byte");
            if (value->opcode == m_sets)
                return boolean_value(left->extract(left_bits - 1, left_bits - 1) == 1);
            auto right = operand(value->r, depth + 1, branch + "R");
            if (!right)
                return {};
            if (right->get_sort().bv_size() != left_bits)
                return reject("comparison operand widths differ");
            if (flag)
            {
                const z3::expr sum = *left + *right;
                const z3::expr difference = *left - *right;
                if (value->opcode == m_cfadd)
                    return boolean_value(z3::ult(sum, *left));
                if (value->opcode == m_ofadd)
                    return boolean_value(((~(*left ^ *right)) & (*left ^ sum))
                                             .extract(left_bits - 1, left_bits - 1) == 1);
                if (value->opcode == m_seto)
                    return boolean_value(((*left ^ *right) & (*left ^ difference))
                                             .extract(left_bits - 1, left_bits - 1) == 1);
                // Integer SETP tests even parity of the low byte of l-r.
                // Floating unordered SETP is excluded by is_fpinsn() above.
                z3::expr parity = difference.extract(0, 0);
                for (unsigned bit = 1; bit < 8; ++bit)
                    parity = parity ^ difference.extract(bit, bit);
                return boolean_value(parity == 0);
            }
            switch (value->opcode)
            {
            case m_setnz:
                return boolean_value(*left != *right);
            case m_setz:
                return boolean_value(*left == *right);
            case m_setae:
                return boolean_value(z3::uge(*left, *right));
            case m_setb:
                return boolean_value(z3::ult(*left, *right));
            case m_seta:
                return boolean_value(z3::ugt(*left, *right));
            case m_setbe:
                return boolean_value(z3::ule(*left, *right));
            case m_setg:
                return boolean_value(*left > *right);
            case m_setge:
                return boolean_value(*left >= *right);
            case m_setl:
                return boolean_value(*left < *right);
            case m_setle:
                return boolean_value(*left <= *right);
            default:
                return reject("unsupported comparison opcode");
            }
        }
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
        auto right = operand(value->r, depth + 1, branch + "R");
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
    const std::lock_guard<std::mutex> guard(instance_stats.mutex);
    return instance_stats.values;
}
void reset_instance_verification_stats()
{
    const std::lock_guard<std::mutex> guard(instance_stats.mutex);
    instance_stats.values = {};
}

RuleVerificationResult RuleVerifier::verify_instance(const minsn_t *original,
                                                     const minsn_t *replacement)
{
    const auto result = verify_instance_impl(original, replacement);
    const std::lock_guard<std::mutex> guard(instance_stats.mutex);
    auto &stats = instance_stats.values;
    switch (result.status)
    {
    case RuleVerificationStatus::VERIFIED:
        ++stats.verified;
        break;
    case RuleVerificationStatus::DISPROVED:
        ++stats.disproved;
        break;
    case RuleVerificationStatus::UNSUPPORTED:
        ++stats.unsupported;
        break;
    case RuleVerificationStatus::UNKNOWN:
        ++stats.unknown;
        break;
    }
    if (result.status != RuleVerificationStatus::VERIFIED)
    {
        if (result.detail.size() <= 256)
        {
            for (auto &entry : stats.rejection_reasons)
                if (entry.status == result.status && entry.bit_width == result.bit_width &&
                    entry.detail == result.detail)
                {
                    ++entry.count;
                    return result;
                }
            if (stats.rejection_reasons.size() < 32)
            {
                stats.rejection_reasons.push_back(
                    {result.status, result.bit_width, result.detail, 1});
                return result;
            }
        }
        ++stats.unrecorded_rejections;
    }
    return result;
}

RuleVerificationResult RuleVerifier::verify_constant(const minsn_t *original, uint64_t value)
{
    if (!original)
        return verify_instance(nullptr, nullptr);
    // Borrow the numeric payload for this synchronous query. No SDK heap
    // allocation or recursive operand copy is needed for the proposal.
    struct ConstantProposal : minsn_t
    {
        explicit ConstantProposal(ea_t ea) : minsn_t(ea) {}
        ~ConstantProposal() { l.zero(); }
    } replacement(original->ea);
    mnumber_t number(value);
    replacement.opcode = m_mov;
    replacement.iprops = original->iprops;
    replacement.d.size = original->d.size;
    replacement.d.oprops = original->d.oprops;
    replacement.l.t = mop_n;
    replacement.l.size = original->d.size;
    replacement.l.nnn = &number;
    return verify_instance(original, &replacement);
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
        InstanceTranslator translator{context_, {}, 0, {}, {}, false, false};
        const auto before = translator.instruction(original);
        if (!before)
            return {RuleVerificationStatus::UNSUPPORTED, bits, translator.error};
        const auto original_loads = std::move(translator.loads);
        translator.loads.clear();
        const auto after = translator.instruction(replacement);
        if (!after)
            return {RuleVerificationStatus::UNSUPPORTED, bits, translator.error};
        if (original_loads.size() != translator.loads.size())
            return {RuleVerificationStatus::UNSUPPORTED, bits,
                    "explicit memory read count changed"};
        if (!original_loads.empty() && translator.implicit_memory)
            return {RuleVerificationStatus::UNSUPPORTED, bits,
                    "explicit loads mixed with implicit memory operands"};
        for (size_t index = 0; index < original_loads.size(); ++index)
        {
            const auto &old = original_loads[index];
            const auto &now = translator.loads[index];
            if (old.branch != now.branch)
                return {RuleVerificationStatus::UNSUPPORTED, bits,
                        "explicit memory read branch changed"};
            if (old.bits != now.bits || old.source != now.source ||
                !z3::eq(old.selector, now.selector) || !z3::eq(old.address, now.address))
                return {RuleVerificationStatus::UNSUPPORTED, bits,
                        "explicit memory read address width or source changed"};
        }
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
