#include "mba_smt_internal.hpp"

#include <algorithm>
#include <utility>

namespace chernobog::mba_smt::detail
{
namespace
{
constexpr size_t max_boolean_variables = 4;

bool collect_ast_ids(const z3::expr &root, std::unordered_set<unsigned> &identifiers)
{
    std::vector<z3::expr> pending{root};
    while (!pending.empty())
    {
        const z3::expr current = pending.back();
        pending.pop_back();

        const unsigned identifier = Z3_get_ast_id(current.ctx(), current);
        if (!identifiers.insert(identifier).second)
        {
            continue;
        }
        if (identifiers.size() > limits::expression_visits || !current.is_app())
        {
            return false;
        }

        for (unsigned argument = 0; argument < current.num_args(); ++argument)
        {
            pending.push_back(current.arg(argument));
        }
    }
    return true;
}
} // namespace

CandidateSynthesis::CandidateSynthesis(SymbolicProgram &symbolic_program,
                                       const BlockInvariants &invariants, size_t block,
                                       size_t statement)
    : symbolic_(symbolic_program), session_(symbolic_program.session),
      original_(symbolic_program.program.blocks.at(block).statements.at(statement).value),
      state_(symbolic_program.before_statement(block, statement)),
      domain_(
          symbolic_program.conjunction(invariants.at(block), symbolic_program.block_entry(block))),
      original_value_(symbolic_program.evaluate(original_, state_)), original_key_(key(original_)),
      bit_width_(original_->bits), operation_limit_(std::min(limits::replacement_operations,
                                                             std::max<size_t>(1, cost(original_))))
{
}

void CandidateSynthesis::collect_inputs()
{
    std::unordered_set<std::string> seen;

    for (const Term &available : symbolic_.program.available)
    {
        Term input = available;
        if (input->bits < bit_width_)
        {
            input = expression(Op::ZeroExtend, input, {}, bit_width_);
        }
        else if (input->bits > bit_width_)
        {
            input = expression(Op::Low, input, {}, bit_width_);
        }

        if (inputs_.size() < limits::synthesis_inputs && seen.insert(key(input)).second)
        {
            inputs_.push_back(input);
        }
    }

    const auto &widths = symbolic_.program.widths;
    for (size_t index = 0; index < widths.size() && inputs_.size() < limits::synthesis_inputs;
         ++index)
    {
        if (widths[index] != bit_width_)
        {
            continue;
        }

        const Term input = variable(index, bit_width_);
        if (seen.insert(key(input)).second)
        {
            inputs_.push_back(input);
        }
    }
}

bool CandidateSynthesis::initialize_samples()
{
    z3::solver solver(session_.context);
    solver.add(domain_);
    if (session_.check(solver, "MBA synthesis seed") != z3::sat)
    {
        return false;
    }

    samples_.push_back(solver.get_model());
    return true;
}

bool CandidateSynthesis::acceptable_cost(const Term &candidate) const
{
    const size_t candidate_cost = cost(candidate);
    const size_t original_cost = cost(original_);
    if (candidate_cost > operation_limit_ || candidate_cost > original_cost)
    {
        return false;
    }

    // Give equal-cost expressions one stable direction, preventing cycles
    // when the same expression is visited at a later optimization maturity.
    return candidate_cost < original_cost || key(candidate) < original_key_;
}

Term CandidateSynthesis::search_linear_mba()
{
    std::unordered_set<unsigned> original_nodes;
    if (!collect_ast_ids(original_value_, original_nodes))
    {
        return {};
    }

    std::vector<Term> inputs;
    z3::expr_vector source_terms(session_.context);
    for (const Term &input : inputs_)
    {
        const z3::expr value = symbolic_.evaluate(input, state_);
        if (original_nodes.count(Z3_get_ast_id(value.ctx(), value)) != 0)
        {
            inputs.push_back(input);
            source_terms.push_back(value);
        }
    }
    if (inputs.empty() || inputs.size() > max_boolean_variables)
    {
        return {};
    }

    const size_t assignment_count = size_t{1} << inputs.size();
    const uint64_t word_mask = bit_width_ == 64 ? UINT64_MAX : (uint64_t{1} << bit_width_) - 1;
    std::vector<uint64_t> truth_values(assignment_count);
    std::vector<uint64_t> coefficients(assignment_count);
    z3::params simplifier(session_.context);
    simplifier.set("max_steps", 10000u);

    for (size_t assignment = 0; assignment < assignment_count; ++assignment)
    {
        if (!session_.has_budget())
        {
            return {};
        }

        z3::expr_vector replacements(session_.context);
        for (size_t input = 0; input < inputs.size(); ++input)
        {
            const uint64_t value = (assignment & (size_t{1} << input)) != 0 ? word_mask : 0;
            replacements.push_back(session_.context.bv_val(value, bit_width_));
        }

        z3::expr instantiated = original_value_;
        instantiated = instantiated.substitute(source_terms, replacements).simplify(simplifier);
        if (!instantiated.is_numeral_u64(truth_values[assignment]))
        {
            return {};
        }
    }

    // For linear MBAs, all-zero/all-one evaluations determine coefficients
    // of the conjunction basis. Nonlinear inputs can fit the same table; the
    // final full-width proof is therefore required in every case.
    coefficients[0] = truth_values[0];
    Term candidate = coefficients[0] != 0 ? constant(coefficients[0], bit_width_) : Term{};
    for (size_t subset = 1; subset < assignment_count; ++subset)
    {
        uint64_t coefficient = truth_values[0] - truth_values[subset];
        for (size_t proper_subset = (subset - 1) & subset; proper_subset != 0;
             proper_subset = (proper_subset - 1) & subset)
        {
            coefficient -= coefficients[proper_subset];
        }
        coefficient &= word_mask;
        coefficients[subset] = coefficient;
        if (coefficient == 0)
        {
            continue;
        }

        Term conjunction;
        for (size_t input = 0; input < inputs.size(); ++input)
        {
            if ((subset & (size_t{1} << input)) == 0)
            {
                continue;
            }
            conjunction =
                conjunction ? expression(Op::And, conjunction, inputs[input]) : inputs[input];
        }

        Term term = conjunction;
        if (coefficient != 1)
        {
            term = expression(Op::Mul, constant(coefficient, bit_width_), term);
        }
        candidate = candidate ? expression(Op::Add, candidate, term) : term;
    }

    if (!candidate)
    {
        candidate = constant(0, bit_width_);
    }
    if (!acceptable_cost(candidate))
    {
        return {};
    }

    z3::solver proof(session_.context);
    proof.add(domain_);
    proof.add(original_value_ != symbolic_.evaluate(candidate, state_));
    ++session_.statistics.candidates;
    const auto result = session_.check(proof, "MBA linear reconstruction mismatch");
    if (result == z3::unsat)
    {
        return candidate;
    }

    if (result == z3::sat)
    {
        ++session_.statistics.disproved;
    }
    else
    {
        ++session_.statistics.unknown;
    }
    return {};
}

Term CandidateSynthesis::instantiate_affine(const std::vector<Term> &basis,
                                            const std::vector<z3::expr> &coefficients,
                                            const z3::model &model) const
{
    Term candidate;
    for (size_t index = 0; index < coefficients.size(); ++index)
    {
        const uint64_t coefficient = model.eval(coefficients[index], true).get_numeral_uint64();
        if (coefficient == 0)
        {
            continue;
        }

        Term term;
        if (index == 0)
        {
            term = constant(coefficient, bit_width_);
        }
        else if (coefficient == 1)
        {
            term = basis[index - 1];
        }
        else
        {
            term = expression(Op::Mul, constant(coefficient, bit_width_), basis[index - 1]);
        }

        if (candidate)
        {
            candidate = expression(Op::Add, candidate, term);
        }
        else
        {
            candidate = term;
        }
    }

    return candidate ? candidate : constant(0, bit_width_);
}

Term CandidateSynthesis::fit_affine(const std::vector<Term> &basis)
{
    std::vector<z3::expr> coefficients;
    coefficients.reserve(basis.size() + 1);
    for (size_t index = 0; index <= basis.size(); ++index)
    {
        coefficients.push_back(session_.fresh_value(bit_width_));
    }

    z3::solver synthesis(session_.context);
    std::vector<z3::model> examples = samples_;

    for (unsigned round = 0; round < 8 && session_.has_budget(); ++round)
    {
        const z3::model &example = examples.back();
        z3::expr proposed_value = coefficients[0];
        for (size_t index = 0; index < basis.size(); ++index)
        {
            const auto input = symbolic_.evaluate(basis[index], state_);
            proposed_value = proposed_value + coefficients[index + 1] * example.eval(input, true);
        }
        synthesis.add(proposed_value == example.eval(original_value_, true));

        if (session_.check(synthesis, "MBA coefficient-hole synthesis") != z3::sat)
        {
            return {};
        }

        const Term candidate = instantiate_affine(basis, coefficients, synthesis.get_model());
        if (!acceptable_cost(candidate))
        {
            return {};
        }

        z3::solver proof(session_.context);
        proof.add(domain_);
        proof.add(original_value_ != symbolic_.evaluate(candidate, state_));
        ++session_.statistics.candidates;

        const auto result = session_.check(proof, "MBA fitted candidate mismatch");
        if (result == z3::unsat)
        {
            return candidate;
        }
        if (result == z3::unknown)
        {
            ++session_.statistics.unknown;
            return {};
        }

        ++session_.statistics.disproved;
        examples.push_back(proof.get_model());
    }

    return {};
}

Term CandidateSynthesis::search_affine()
{
    if (Term constant_candidate = fit_affine({}))
    {
        return constant_candidate;
    }

    for (const Term &input : inputs_)
    {
        if (!session_.has_budget())
        {
            return {};
        }
        if (Term candidate = fit_affine({input}))
        {
            return candidate;
        }
    }

    for (size_t first = 0; first < inputs_.size(); ++first)
    {
        for (size_t second = first + 1; second < inputs_.size(); ++second)
        {
            if (!session_.has_budget())
            {
                return {};
            }
            if (Term candidate = fit_affine({inputs_[first], inputs_[second]}))
            {
                return candidate;
            }
        }
    }

    return {};
}

bool CandidateSynthesis::should_stop_enumeration()
{
    return restart_requested_ || generated_ >= session_.options.max_candidates ||
           !session_.has_budget();
}

CandidateSynthesis::CandidateStatus CandidateSynthesis::consider(const Term &candidate,
                                                                 size_t operation_count)
{
    if (should_stop_enumeration())
    {
        return CandidateStatus::Exhausted;
    }

    ++generated_;
    if (!acceptable_cost(candidate))
    {
        return CandidateStatus::Rejected;
    }

    ++session_.statistics.candidates;
    const z3::expr candidate_value = symbolic_.evaluate(candidate, state_);
    std::string signature;
    bool matches_samples = true;

    for (const z3::model &sample : samples_)
    {
        const auto observed = sample.eval(candidate_value, true).simplify();
        const auto expected = sample.eval(original_value_, true).simplify();
        signature += observed.to_string() + ";";
        if (!z3::eq(observed, expected))
        {
            matches_samples = false;
        }
    }

    if (!signatures_.insert(signature).second)
    {
        return CandidateStatus::Rejected;
    }
    layers_.at(operation_count).push_back(candidate);
    if (!matches_samples)
    {
        return CandidateStatus::Rejected;
    }

    z3::solver solver(session_.context);
    solver.add(domain_);
    solver.add(original_value_ != candidate_value);
    const auto result = session_.check(solver, "MBA synthesis candidate mismatch");

    if (result == z3::unsat)
    {
        return CandidateStatus::Verified;
    }
    if (result == z3::sat)
    {
        samples_.push_back(solver.get_model());
        restart_requested_ = true;
        ++session_.statistics.disproved;
        return CandidateStatus::Counterexample;
    }

    ++session_.statistics.unknown;
    return CandidateStatus::Rejected;
}

Term CandidateSynthesis::enumerate_unary(size_t operation_count)
{
    for (const Term &input : layers_[operation_count - 1])
    {
        for (Op operation : {Op::Not, Op::Neg})
        {
            const Term candidate = expression(operation, input);
            if (consider(candidate, operation_count) == CandidateStatus::Verified)
            {
                return candidate;
            }
            if (should_stop_enumeration())
            {
                return {};
            }
        }

        for (unsigned shift_count : {1u, bit_width_ - 1, bit_width_, 255u})
        {
            for (Op operation : {Op::Shl, Op::Shr, Op::Sar})
            {
                const Term candidate = expression(operation, input, constant(shift_count, 8));
                if (consider(candidate, operation_count) == CandidateStatus::Verified)
                {
                    return candidate;
                }
                if (should_stop_enumeration())
                {
                    return {};
                }
            }
        }
    }

    return {};
}

Term CandidateSynthesis::enumerate_binary(size_t operation_count)
{
    for (size_t left_cost = 0; left_cost < operation_count; ++left_cost)
    {
        const size_t right_cost = operation_count - 1 - left_cost;
        for (const Term &left : layers_[left_cost])
        {
            for (const Term &right : layers_[right_cost])
            {
                for (Op operation : {Op::Add, Op::Sub, Op::Xor, Op::And, Op::Or, Op::Mul})
                {
                    const Term candidate = expression(operation, left, right);
                    if (consider(candidate, operation_count) == CandidateStatus::Verified)
                    {
                        return candidate;
                    }
                    if (should_stop_enumeration())
                    {
                        return {};
                    }
                }
            }
        }
    }

    return {};
}

Term CandidateSynthesis::search_grammar()
{
    std::set<uint64_t> literals{0, 1, UINT64_MAX};
    collect_literals(original_, bit_width_, literals);

    uint64_t observed_result = 0;
    if (samples_.front().eval(original_value_, true).is_numeral_u64(observed_result))
    {
        literals.insert(observed_result);
    }

    std::vector<Term> leaves = inputs_;
    for (uint64_t literal : literals)
    {
        leaves.push_back(constant(literal, bit_width_));
    }

    for (unsigned round = 0; round < 16 && session_.has_budget(); ++round)
    {
        layers_.assign(operation_limit_ + 1, {});
        signatures_.clear();
        generated_ = 0;
        restart_requested_ = false;

        for (const Term &leaf : leaves)
        {
            const size_t leaf_cost = std::min(operation_limit_, cost(leaf));
            if (consider(leaf, leaf_cost) == CandidateStatus::Verified)
            {
                return leaf;
            }
            if (should_stop_enumeration())
            {
                break;
            }
        }

        for (size_t operations = 1; operations <= operation_limit_ && !should_stop_enumeration();
             ++operations)
        {
            if (Term candidate = enumerate_unary(operations))
            {
                return candidate;
            }
            if (should_stop_enumeration())
            {
                break;
            }
            if (Term candidate = enumerate_binary(operations))
            {
                return candidate;
            }
        }

        if (!restart_requested_)
        {
            break;
        }
    }

    return {};
}

Term CandidateSynthesis::run()
{
    if (Term candidate = simplify_algebraic(symbolic_, state_, original_))
    {
        return candidate;
    }

    collect_inputs();
    if (!initialize_samples())
    {
        return {};
    }

    if (Term candidate = search_linear_mba())
    {
        return candidate;
    }

    if (Term candidate = search_affine())
    {
        return candidate;
    }

    return search_grammar();
}
} // namespace chernobog::mba_smt::detail
