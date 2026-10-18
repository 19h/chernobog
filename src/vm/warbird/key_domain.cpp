#include "key_domain.hpp"
#include <algorithm>
#include <set>
#include <map>
#include <functional>

namespace chernobog::warbird
{
namespace
{
class FiniteCover
{
    size_t limit;
    size_t evaluations = 0;
    std::map<unsigned, std::vector<z3::expr>> memo;
    z3::params params;
    bool add(std::vector<z3::expr> &to, const z3::expr &value)
    {
        if (std::none_of(to.begin(), to.end(), [&](const auto &old) { return z3::eq(old, value); }))
            to.push_back(value);
        return to.size() <= limit;
    }

  public:
    FiniteCover(z3::context &ctx, size_t maximum) : limit(maximum), params(ctx)
    {
        params.set("max_steps", 1000u);
    }
    bool collect(const z3::expr &expression, std::vector<z3::expr> &out, unsigned depth = 0)
    {
        if (depth > 128 || memo.size() > 4096 || evaluations > 10000)
            return false;
        auto found = memo.find(expression.id());
        if (found != memo.end())
        {
            out = found->second;
            return !out.empty();
        }
        if (expression.is_numeral() || expression.is_true() || expression.is_false())
            out.push_back(expression);
        else if (expression.is_app() && expression.decl().decl_kind() == Z3_OP_ITE)
        {
            std::vector<z3::expr> left, right;
            if (!collect(expression.arg(1), left, depth + 1) ||
                !collect(expression.arg(2), right, depth + 1))
                return false;
            for (const auto &v : left)
                if (!add(out, v))
                    return false;
            for (const auto &v : right)
                if (!add(out, v))
                    return false;
        }
        else
        {
            if (!expression.is_app() || expression.decl().decl_kind() == Z3_OP_UNINTERPRETED ||
                (!expression.is_bv() && !expression.is_bool()))
                return false;
            std::vector<std::vector<z3::expr>> operands;
            for (unsigned i = 0; i < expression.num_args(); ++i)
            {
                std::vector<z3::expr> values;
                if (!collect(expression.arg(i), values, depth + 1))
                    return false;
                operands.push_back(std::move(values));
            }
            z3::expr_vector args(expression.ctx());
            std::function<bool(size_t)> evaluate = [&](size_t index)
            {
                if (index < operands.size())
                {
                    for (const auto &v : operands[index])
                    {
                        args.push_back(v);
                        if (!evaluate(index + 1))
                            return false;
                        args.pop_back();
                    }
                    return true;
                }
                if (++evaluations > 10000)
                    return false;
                auto value = expression.decl()(args).simplify(params);
                return (value.is_numeral() || value.is_true() || value.is_false()) &&
                       add(out, value);
            };
            if (!evaluate(0))
                return false;
        }
        memo.emplace(expression.id(), out);
        return true;
    }
};
}
KeyDomain resolve_key_domain(const z3::expr &key, const z3::expr &domain, size_t max_values,
                             unsigned timeout_ms, unsigned resource_limit)
{
    KeyDomain result;
    if (&key.ctx() != &domain.ctx() || !key.is_bv() || key.get_sort().bv_size() != 64 ||
        !domain.is_bool() || max_values == 0 || max_values > 64 || timeout_ms == 0 ||
        resource_limit == 0)
        return result;
    if (domain.is_false())
    {
        result.status = KeyDomainStatus::UNSATISFIABLE;
        return result;
    }
    std::vector<z3::expr> leaves;
    if (FiniteCover(key.ctx(), max_values).collect(key, leaves))
    {
        for (const auto &leaf : leaves)
        {
            uint64_t value = 0;
            if (!leaf.is_numeral_u64(value))
                return result;
            result.values.push_back(value);
        }
        std::sort(result.values.begin(), result.values.end());
        result.status = KeyDomainStatus::COMPLETE;
        return result;
    }
    auto &ctx = key.ctx();
    z3::solver solver(ctx);
    solver.set("timeout", timeout_ms);
    solver.set("rlimit", resource_limit);
    solver.add(domain);
    for (size_t n = 0; n <= max_values; ++n)
    {
        ++result.queries;
        const auto check = solver.check();
        if (check == z3::unsat)
        {
            result.status =
                result.values.empty() ? KeyDomainStatus::UNSATISFIABLE : KeyDomainStatus::COMPLETE;
            std::sort(result.values.begin(), result.values.end());
            return result;
        }
        if (check != z3::sat)
        {
            result.status = KeyDomainStatus::SOLVER_UNKNOWN;
            return result;
        }
        if (n == max_values)
        {
            result.status = KeyDomainStatus::VALUE_LIMIT;
            return result;
        }
        uint64_t value = 0;
        if (!solver.get_model().eval(key, true).is_numeral_u64(value))
        {
            result.status = KeyDomainStatus::SOLVER_UNKNOWN;
            return result;
        }
        result.values.push_back(value);
        solver.add(key != ctx.bv_val(value, 64));
    }
    return result;
}
}
