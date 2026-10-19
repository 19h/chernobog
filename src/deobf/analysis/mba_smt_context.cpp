#include "mba_smt_context.hpp"

#include <algorithm>
#include <set>
#include <unordered_map>

namespace chernobog::mba_smt
{
namespace
{
constexpr size_t max_path_conditions = 16;

bool bounded(const Term &value, size_t &remaining, unsigned depth = 0)
{
    if (!value || remaining == 0 || depth > limits::expression_depth)
    {
        return false;
    }
    --remaining;
    if (value->bits < 8 || value->bits > 64 || value->bits % 8 != 0)
    {
        return false;
    }
    return (!value->left || bounded(value->left, remaining, depth + 1)) &&
           (!value->right || bounded(value->right, remaining, depth + 1));
}

bool bounded(const Term &value)
{
    size_t remaining = limits::expression_visits;
    return bounded(value, remaining);
}

template <typename TranslateVariable>
Term translate(const Term &value, const TranslateVariable &translate_variable,
               std::unordered_map<const Expression *, Term> &translated)
{
    if (!value)
    {
        return {};
    }
    const auto found = translated.find(value.get());
    if (found != translated.end())
    {
        return found->second;
    }

    Term result;
    if (value->op == Op::Variable)
    {
        result = translate_variable(value);
    }
    else if (value->op == Op::Constant)
    {
        result = value;
    }
    else
    {
        const Term left = translate(value->left, translate_variable, translated);
        const Term right = translate(value->right, translate_variable, translated);
        if (left && (!value->right || right))
        {
            result = expression(value->op, left, right, value->bits);
        }
    }
    translated.emplace(value.get(), result);
    return result;
}
} // namespace

ScalarContext::ScalarContext(std::vector<unsigned> local_widths)
    : widths_(std::move(local_widths)), next_symbol_(std::make_shared<size_t>(0))
{
    reset();
}

Term ScalarContext::value(int local) const
{
    const auto found = bindings_.find(local);
    return found == bindings_.end() ? Term{} : found->second;
}

bool ScalarContext::derived(int local) const { return derived_.count(local) != 0; }

void ScalarContext::assign(int local, Term value)
{
    if (local < 0 || size_t(local) >= widths_.size() || !widths_[local])
    {
        return;
    }
    if (!value || value->bits != widths_[local] || !bounded(value))
    {
        forget(local);
        return;
    }
    bindings_[local] = std::move(value);
    derived_.insert(local);
}

void ScalarContext::forget(int local)
{
    if (local >= 0 && size_t(local) < widths_.size() && widths_[local])
    {
        bindings_[local] = variable((*next_symbol_)++, widths_[local]);
        derived_.erase(local);
    }
}

void ScalarContext::reset()
{
    bindings_.clear();
    derived_.clear();
    conditions_.clear();
    for (size_t local = 0; local < widths_.size(); ++local)
    {
        forget(int(local));
    }
}

void ScalarContext::assume(Term condition, bool taken)
{
    if (!bounded(condition) || conditions_.size() >= max_path_conditions)
    {
        return;
    }
    Term predicate =
        expression(taken ? Op::NotEqual : Op::Equal, condition, constant(0, condition->bits), 8);
    if (bounded(predicate))
    {
        conditions_.push_back(std::move(predicate));
    }
}

void ScalarContext::merge_from(const ScalarContext &other)
{
    if (next_symbol_ != other.next_symbol_ || widths_ != other.widths_)
    {
        reset();
        return;
    }
    for (const auto &[local, value] : bindings_)
    {
        const Term incoming = other.value(local);
        if (!incoming || key(value) != key(incoming))
        {
            forget(local);
        }
    }

    std::set<std::string> incoming_conditions;
    for (const Term &condition : other.conditions_)
    {
        incoming_conditions.insert(key(condition));
    }
    conditions_.erase(std::remove_if(conditions_.begin(), conditions_.end(),
                                     [&](const Term &condition)
                                     { return incoming_conditions.count(key(condition)) == 0; }),
                      conditions_.end());
}

const ScalarContext::Bindings &ScalarContext::bindings() const { return bindings_; }

const std::vector<Term> &ScalarContext::conditions() const { return conditions_; }

ContextQuery::ContextQuery(const ScalarContext &context, Term value, bool include_conditions)
{
    if (!bounded(value))
    {
        return;
    }
    std::unordered_map<const Expression *, Term> translated;
    const auto lower_variable = [&](const Term &input) -> Term
    {
        auto found = symbols_.find(size_t(input->value));
        if (found == symbols_.end())
        {
            if (originals_.size() + 1 >= limits::storage_regions)
            {
                return {};
            }
            const size_t index = originals_.size();
            found = symbols_.emplace(size_t(input->value), index).first;
            originals_.push_back(input);
            program_.widths.push_back(input->bits);
        }
        return program_.widths[found->second] == input->bits ? variable(found->second, input->bits)
                                                             : Term{};
    };
    const Term lowered = translate(value, lower_variable, translated);
    if (!lowered)
    {
        return;
    }

    Term condition;
    if (include_conditions)
    {
        for (const Term &predicate : context.conditions())
        {
            const Term next = translate(predicate, lower_variable, translated);
            if (!next)
            {
                return;
            }
            condition = condition ? expression(Op::And, condition, next, 8) : next;
        }
    }

    // Offer only values that use symbols already needed by the query. Adding
    // unrelated locals would expand both the search and the solver domain.
    for (const auto &[local, available] : context.bindings())
    {
        if (program_.available.size() >= limits::synthesis_inputs)
        {
            break;
        }
        const Term input = lower(available);
        if (input)
        {
            program_.available.push_back(input);
        }
    }

    const size_t destination = program_.widths.size();
    program_.widths.push_back(value->bits);
    program_.blocks.resize(condition ? 2 : 1);
    if (condition)
    {
        program_.blocks.front().edges.push_back({1, condition, false});
    }
    program_.blocks.back().statements.push_back(Statement::assign(destination, lowered));
    program_.targets.emplace_back(block(), 0);
    valid_ = validate(program_);
}

bool ContextQuery::valid() const { return valid_; }

const Program &ContextQuery::program() const { return program_; }

size_t ContextQuery::block() const
{
    return program_.blocks.empty() ? 0 : program_.blocks.size() - 1;
}

Term ContextQuery::lower(const Term &value) const
{
    if (!bounded(value))
    {
        return {};
    }
    std::unordered_map<const Expression *, Term> translated;
    return translate(
        value,
        [&](const Term &input) -> Term
        {
            const auto found = symbols_.find(size_t(input->value));
            if (found == symbols_.end() || originals_[found->second]->bits != input->bits)
            {
                return {};
            }
            return variable(found->second, input->bits);
        },
        translated);
}

Term ContextQuery::restore(const Term &value) const
{
    if (!bounded(value))
    {
        return {};
    }
    std::unordered_map<const Expression *, Term> translated;
    return translate(
        value,
        [&](const Term &input) -> Term
        {
            return input->value < originals_.size() && originals_[input->value]->bits == input->bits
                       ? originals_[input->value]
                       : Term{};
        },
        translated);
}
} // namespace chernobog::mba_smt
