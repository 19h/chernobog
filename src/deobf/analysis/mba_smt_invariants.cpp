#include "mba_smt_internal.hpp"

#include <algorithm>
#include <utility>

namespace chernobog::mba_smt::detail
{
InvariantInference::InvariantInference(SymbolicProgram &symbolic_program)
    : symbolic_(symbolic_program), session_(symbolic_program.session)
{
}

void InvariantInference::add_template(Term candidate)
{
    if (templates_.size() >= session_.options.max_invariants)
    {
        return;
    }

    if (template_keys_.insert(key(candidate)).second)
    {
        templates_.push_back(std::move(candidate));
    }
}

void InvariantInference::collect_definition_templates()
{
    const auto &program = symbolic_.program;
    for (const Block &block : program.blocks)
    {
        for (const Edge &edge : block.edges)
        {
            if (!edge.condition)
            {
                continue;
            }

            add_template(edge.condition);
            add_template(expression(Op::Equal, edge.condition, constant(0, edge.condition->bits)));
        }

        for (const Statement &statement : block.statements)
        {
            if (statement.kind == Statement::Kind::Havoc)
            {
                continue;
            }

            if (statement.kind == Statement::Kind::Store)
            {
                if (polynomial_degree(statement.value) <= limits::invariant_degree &&
                    variables(statement.value).size() <= limits::invariant_variables)
                {
                    const Term stored = load(statement.address, statement.value->bits);
                    add_template(expression(Op::Equal, stored, statement.value));
                }
                continue;
            }

            Term destination =
                variable(statement.destination, program.widths[statement.destination]);
            if (statement.offset != 0)
            {
                destination =
                    expression(Op::High, destination, {}, destination->bits - statement.offset);
            }
            if (destination->bits != statement.value->bits)
            {
                destination = expression(Op::Low, destination, {}, statement.value->bits);
            }

            // This is only a proposal. An assignment in one block does not
            // establish the relation at another block or after a loop step.
            if (polynomial_degree(statement.value) <= limits::invariant_degree &&
                variables(statement.value).size() <= limits::invariant_variables)
            {
                add_template(expression(Op::Equal, destination, statement.value));
            }

            const Term &value = statement.value;
            if (value->right && value->right->op == Op::Constant)
            {
                const uint64_t mask = value->right->value;
                if (value->op == Op::And)
                {
                    const Term cleared_bits =
                        expression(Op::And, destination, constant(~mask, destination->bits));
                    add_template(
                        expression(Op::Equal, cleared_bits, constant(0, destination->bits)));
                }
                else if (value->op == Op::Or)
                {
                    const Term set_bits =
                        expression(Op::And, destination, constant(mask, destination->bits));
                    add_template(
                        expression(Op::Equal, set_bits, constant(mask, destination->bits)));
                }
            }
        }
    }
}

void InvariantInference::collect_scalar_templates()
{
    const auto &program = symbolic_.program;
    std::vector<Term> values;
    std::unordered_set<std::string> seen;
    const auto add_value = [&](Term value)
    {
        if (values.size() < 2 * limits::synthesis_inputs && seen.insert(key(value)).second)
        {
            values.push_back(std::move(value));
        }
    };

    for (const Block &block : program.blocks)
    {
        for (const Statement &statement : block.statements)
        {
            if (statement.kind == Statement::Kind::Store)
            {
                add_value(load(statement.address, statement.value->bits));
            }
        }
    }
    for (const Term &available : program.available)
    {
        add_value(available);
    }
    for (size_t index = 0; index < program.widths.size(); ++index)
    {
        add_value(variable(index, program.widths[index]));
    }

    for (const Term &left : values)
    {
        add_template(expression(Op::Equal, left, constant(0, left->bits)));

        for (const Term &right : values)
        {
            if (left->bits != right->bits || key(left) == key(right))
            {
                continue;
            }

            add_template(expression(Op::Equal, left, right));
            add_template(expression(Op::Equal, left, expression(Op::Mul, right, right)));
        }
    }
}

bool InvariantInference::prune(size_t target, const SymbolicState &incoming, const z3::expr &domain)
{
    auto &candidates = invariants_[target];
    if (candidates.empty())
    {
        return false;
    }

    z3::solver solver(session_.context);
    solver.add(domain && !symbolic_.conjunction(candidates, incoming));
    const auto result = session_.check(solver, "MBA inductive facts mismatch");

    if (result == z3::unsat)
    {
        return false;
    }

    if (result == z3::unknown)
    {
        session_.statistics.invariants_rejected += candidates.size();
        candidates.clear();
        return true;
    }

    const z3::model counterexample = solver.get_model();
    const size_t previous_count = candidates.size();
    const auto contradicted = [&](const Term &candidate)
    {
        const auto predicate = symbolic_.evaluate(candidate, incoming) != 0;
        return !counterexample.eval(predicate, true).is_true();
    };

    candidates.erase(std::remove_if(candidates.begin(), candidates.end(), contradicted),
                     candidates.end());
    session_.statistics.invariants_rejected += previous_count - candidates.size();
    return previous_count != candidates.size();
}

bool InvariantInference::check_transitions()
{
    bool removed_candidate = false;
    for (size_t source = 0; source < symbolic_.program.blocks.size(); ++source)
    {
        for (const Edge &edge : symbolic_.program.blocks[source].edges)
        {
            if (!session_.has_budget())
            {
                return true;
            }

            const auto entry_facts =
                symbolic_.conjunction(invariants_[source], symbolic_.block_entry(source));
            const auto domain = entry_facts && symbolic_.edge_condition(source, edge);
            if (prune(edge.target, symbolic_.block_exit(source), domain))
            {
                removed_candidate = true;
            }
        }
    }
    return removed_candidate;
}

BlockInvariants InvariantInference::run()
{
    const auto &program = symbolic_.program;
    if (program.blocks.size() == 1 && program.blocks.front().edges.empty())
    {
        return BlockInvariants(1);
    }

    collect_definition_templates();
    collect_scalar_templates();

    invariants_.assign(program.blocks.size(), templates_);
    session_.statistics.invariant_candidates += templates_.size() * invariants_.size();

    while (session_.has_budget())
    {
        const bool entry_changed = prune(program.entry, symbolic_.block_entry(program.entry),
                                         session_.context.bool_val(true));
        const bool edges_changed = check_transitions();

        if (!entry_changed && !edges_changed && session_.has_budget())
        {
            for (const auto &block_invariants : invariants_)
            {
                session_.statistics.invariants += block_invariants.size();
            }
            return std::move(invariants_);
        }
    }

    // No intermediate annotation set is a proof. A timeout during elimination
    // discards every fact, including candidates that survived earlier rounds.
    return BlockInvariants(program.blocks.size());
}
} // namespace chernobog::mba_smt::detail
