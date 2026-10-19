#include "mba_smt.hpp"
#include "mba_smt_internal.hpp"
#include <algorithm>
#include <chrono>
#include <limits>
#include <set>
#include <stdexcept>
#include <unordered_set>
#include <utility>
#include <z3++.h>

namespace chernobog::mba_smt
{
namespace
{
bool valid_bit_width(unsigned bits)
{
    return bits >= 8 && bits <= 64 && bits % 8 == 0;
}

bool is_unary_operation(Op op)
{
    return op == Op::Not || op == Op::Neg || op == Op::Low || op == Op::High ||
           op == Op::ZeroExtend || op == Op::SignExtend;
}

bool is_comparison(Op op)
{
    return op == Op::Equal || op == Op::NotEqual || op == Op::UnsignedLess || op == Op::SignedLess;
}

bool validate_term(const Term &term, const Program &program, size_t &visits, unsigned depth = 0)
{
    if (!term || !valid_bit_width(term->bits) || ++visits > limits::expression_visits ||
        depth > limits::expression_depth)
    {
        return false;
    }

    if (term->op == Op::Constant)
    {
        return !term->left && !term->right;
    }
    if (term->op == Op::Variable)
    {
        return term->value < program.widths.size() &&
               program.widths[static_cast<size_t>(term->value)] == term->bits && !term->left &&
               !term->right;
    }

    if (!validate_term(term->left, program, visits, depth + 1))
    {
        return false;
    }

    const unsigned input_width = term->left->bits;
    if (term->op == Op::UnsignedDivide &&
        (!term->right || term->right->op != Op::Constant || term->right->value == 0))
    {
        return false;
    }
    if (term->op == Op::Load)
    {
        return input_width == program.address_bits && !term->right;
    }
    if (is_unary_operation(term->op))
    {
        if (term->right)
        {
            return false;
        }
        if (term->op == Op::Low || term->op == Op::High)
        {
            return input_width >= term->bits;
        }
        if (term->op == Op::ZeroExtend || term->op == Op::SignExtend)
        {
            return input_width <= term->bits;
        }
        return input_width == term->bits;
    }

    if (!validate_term(term->right, program, visits, depth + 1))
    {
        return false;
    }
    if (term->op == Op::UnsignedDivide && term->right->bits < 64 &&
        (term->right->value >> term->right->bits) != 0)
    {
        return false;
    }
    if (term->op == Op::Shl || term->op == Op::Shr || term->op == Op::Sar)
    {
        return input_width == term->bits && term->right->bits == 8;
    }

    const bool matching_inputs = input_width == term->right->bits;
    const bool valid_result = is_comparison(term->op) ? term->bits == 8 : input_width == term->bits;
    return matching_inputs && valid_result;
}

unsigned expression_degree(const Term &term)
{
    constexpr unsigned unsupported_degree = limits::invariant_degree + 1;

    if (!term)
    {
        return unsupported_degree;
    }
    if (term->op == Op::Constant)
    {
        return 0;
    }
    if (term->op == Op::Variable || term->op == Op::Load)
    {
        return 1;
    }
    if (term->op == Op::Low || term->op == Op::High)
    {
        return expression_degree(term->left) == 1 ? 1 : unsupported_degree;
    }
    if (term->op == Op::Neg)
    {
        return expression_degree(term->left);
    }
    if (term->op == Op::Add || term->op == Op::Sub)
    {
        return std::max(expression_degree(term->left), expression_degree(term->right));
    }
    if (term->op == Op::Mul)
    {
        const unsigned degree = expression_degree(term->left) + expression_degree(term->right);
        return std::min(degree, unsupported_degree);
    }
    return unsupported_degree;
}

void collect_term_literals(const Term &term, std::set<uint64_t> &values, unsigned bits)
{
    if (!term)
    {
        return;
    }
    if (term->op == Op::Constant && term->bits == bits)
    {
        values.insert(term->value);
    }
    collect_term_literals(term->left, values, bits);
    collect_term_literals(term->right, values, bits);
}
} // namespace

Term constant(uint64_t value, unsigned bits)
{
    return std::make_shared<Expression>(Expression{Op::Constant, bits, value, {}, {}});
}

Term variable(size_t index, unsigned bits)
{
    return std::make_shared<Expression>(Expression{Op::Variable, bits, uint64_t(index), {}, {}});
}

Term expression(Op op, Term left, Term right, unsigned bits)
{
    if (!bits)
    {
        bits = is_comparison(op) ? 8 : (left ? left->bits : 0);
    }
    return std::make_shared<Expression>(Expression{op, bits, 0, std::move(left), std::move(right)});
}

Term load(Term address, unsigned bits)
{
    return expression(Op::Load, std::move(address), {}, bits);
}

size_t cost(const Term &term)
{
    if (!term || term->op == Op::Constant || term->op == Op::Variable)
    {
        return 0;
    }
    const size_t operation_cost = term->op == Op::UnsignedDivide ? limits::division_cost : 1;
    return operation_cost + cost(term->left) + cost(term->right);
}

std::string key(const Term &term)
{
    if (!term)
    {
        return "_";
    }
    return std::to_string(unsigned(term->op)) + ":" + std::to_string(term->bits) + ":" +
           std::to_string(term->value) + "(" + key(term->left) + "," + key(term->right) + ")";
}

std::vector<size_t> variables(const Term &term)
{
    std::set<size_t> result;
    std::function<void(const Term &)> walk = [&](const Term &node)
    {
        if (!node)
        {
            return;
        }
        if (node->op == Op::Variable)
        {
            result.insert(size_t(node->value));
        }
        walk(node->left);
        walk(node->right);
    };
    walk(term);
    return {result.begin(), result.end()};
}

Statement Statement::assign(size_t destination, Term value)
{
    Statement statement;
    statement.destination = destination;
    statement.value = std::move(value);
    return statement;
}

Statement Statement::store(Term address, Term value)
{
    Statement statement;
    statement.kind = Kind::Store;
    statement.address = std::move(address);
    statement.value = std::move(value);
    return statement;
}

Statement Statement::havoc(std::vector<size_t> spoiled)
{
    Statement statement;
    statement.kind = Kind::Havoc;
    statement.spoiled = std::move(spoiled);
    return statement;
}

Options Options::deep()
{
    Options options;
    options.budget_ms = limits::deep_budget_ms;
    options.query_ms = 2000;
    options.resource_limit = 10000000;
    return options;
}

bool validate(const Program &program)
{
    if ((program.address_bits != 32 && program.address_bits != 64) || program.blocks.empty() ||
        program.entry >= program.blocks.size() || program.blocks.size() > limits::blocks ||
        program.widths.size() > limits::storage_regions)
    {
        return false;
    }
    for (auto bits : program.widths)
    {
        if (!valid_bit_width(bits))
        {
            return false;
        }
    }
    size_t instructions = 0;
    for (const auto &block : program.blocks)
    {
        instructions += block.statements.size();
        if (instructions > limits::statements)
        {
            return false;
        }
        for (const auto &statement : block.statements)
        {
            size_t visits = 0;
            if (statement.kind == Statement::Kind::Havoc)
            {
                for (auto id : statement.spoiled)
                {
                    if (id >= program.widths.size())
                    {
                        return false;
                    }
                }
                continue;
            }
            if (!validate_term(statement.value, program, visits))
            {
                return false;
            }
            if (statement.kind == Statement::Kind::Assign)
            {
                if (statement.destination >= program.widths.size() || statement.offset % 8 != 0 ||
                    statement.offset + statement.value->bits >
                        program.widths[statement.destination] ||
                    std::find(program.readonly.begin(), program.readonly.end(),
                              statement.destination) != program.readonly.end())
                {
                    return false;
                }
            }
            else if (!validate_term(statement.address, program, visits) ||
                     statement.address->bits != program.address_bits)
            {
                return false;
            }
        }
        for (const auto &e : block.edges)
        {
            size_t visits = 0;
            if (e.target >= program.blocks.size() ||
                (e.condition && !validate_term(e.condition, program, visits)))
            {
                return false;
            }
        }
    }
    for (auto id : program.readonly)
    {
        if (id >= program.widths.size())
        {
            return false;
        }
    }
    for (const auto &term : program.available)
    {
        size_t visits = 0;
        if (!validate_term(term, program, visits))
        {
            return false;
        }
    }
    return true;
}

namespace detail
{
bool validate_expression(const Term &term, const Program &program)
{
    size_t visits = 0;
    return validate_term(term, program, visits);
}

unsigned polynomial_degree(const Term &term)
{
    return expression_degree(term);
}

void collect_literals(const Term &term, unsigned bit_width, std::set<uint64_t> &values)
{
    collect_term_literals(term, values, bit_width);
}
} // namespace detail

struct Analysis::Impl
{
    Impl(Program input_program, Options options)
        : program(std::move(input_program)), session(std::move(options), statistics),
          symbolic(program, session)
    {
    }

    bool prepare()
    {
        if (preparation_attempted)
        {
            return invariants.has_value();
        }

        preparation_attempted = true;
        if (!session.has_budget() || !validate(program))
        {
            return false;
        }

        symbolic.build();
        detail::InvariantInference inference(symbolic);
        invariants = inference.run();
        return true;
    }

    bool is_rewrite_site(size_t block, size_t statement) const
    {
        if (program.blocks[block].statements[statement].kind != Statement::Kind::Assign)
        {
            return false;
        }

        if (program.targets.empty())
        {
            return true;
        }

        const auto site = std::make_pair(block, statement);
        return std::find(program.targets.begin(), program.targets.end(), site) !=
               program.targets.end();
    }

    std::vector<std::pair<size_t, size_t>> prioritized_sites() const
    {
        std::vector<std::pair<size_t, size_t>> sites;
        for (size_t block = 0; block < program.blocks.size(); ++block)
        {
            for (size_t statement = 0; statement < program.blocks[block].statements.size();
                 ++statement)
            {
                if (is_rewrite_site(block, statement))
                {
                    sites.emplace_back(block, statement);
                }
            }
        }

        std::stable_sort(sites.begin(), sites.end(),
                         [&](const auto &left, const auto &right)
                         {
                             const Term &left_value =
                                 program.blocks[left.first].statements[left.second].value;
                             const Term &right_value =
                                 program.blocks[right.first].statements[right.second].value;
                             return cost(left_value) > cost(right_value);
                         });
        return sites;
    }

    Program program;
    Statistics statistics;
    detail::SolverSession session;
    detail::SymbolicProgram symbolic;
    std::optional<detail::BlockInvariants> invariants;
    bool preparation_attempted = false;
};

Analysis::Analysis(Program program, Options options)
    : impl_(std::make_unique<Impl>(std::move(program), std::move(options)))
{
}

Analysis::~Analysis() = default;

std::vector<Proposal> Analysis::run()
{
    try
    {
        if (!impl_->prepare())
        {
            ++impl_->statistics.unsupported;
            return {};
        }

        for (const auto &[block, statement] : impl_->prioritized_sites())
        {
            if (!impl_->session.has_budget())
            {
                ++impl_->statistics.exhausted;
                return {};
            }

            detail::CandidateSynthesis synthesis(impl_->symbolic, *impl_->invariants, block,
                                                 statement);
            Term replacement = synthesis.run();
            if (!replacement)
            {
                continue;
            }

            const Verdict result = detail::verify_replacement(impl_->symbolic, *impl_->invariants,
                                                              block, statement, replacement);
            if (result == Verdict::Verified)
            {
                // Applying this proposal invalidates the entire snapshot.
                // Return one proposal so its owner must rebuild afterward.
                return {{block, statement, std::move(replacement)}};
            }
        }
    }
    catch (const std::exception &)
    {
        ++impl_->statistics.unsupported;
    }

    impl_->session.has_budget();
    return {};
}

Term Analysis::constant_value(size_t block, size_t statement)
{
    try
    {
        if (!impl_->prepare() || block >= impl_->program.blocks.size() ||
            statement >= impl_->program.blocks[block].statements.size() ||
            !impl_->is_rewrite_site(block, statement))
        {
            return {};
        }

        auto &symbolic = impl_->symbolic;
        auto &session = impl_->session;
        const auto &assignment = impl_->program.blocks[block].statements[statement];
        const auto &state = symbolic.before_statement(block, statement);
        const z3::expr value = symbolic.evaluate(assignment.value, state);
        z3::solver solver(session.context);
        solver.add(symbolic.conjunction(impl_->invariants->at(block), symbolic.block_entry(block)));
        if (session.check(solver, "MBA constant proposal feasibility") != z3::sat)
        {
            return {};
        }

        uint64_t literal = 0;
        if (!solver.get_model().eval(value, true).is_numeral_u64(literal))
        {
            return {};
        }
        const Term candidate = constant(literal, assignment.value->bits);
        ++impl_->statistics.candidates;
        if (detail::verify_replacement(symbolic, *impl_->invariants, block, statement, candidate) ==
            Verdict::Verified)
        {
            return candidate;
        }
    }
    catch (const std::exception &)
    {
        ++impl_->statistics.unsupported;
    }
    return {};
}

Verdict Analysis::verify(size_t block, size_t statement, const Term &replacement)
{
    try
    {
        if (!impl_->session.has_budget())
        {
            ++impl_->statistics.exhausted;
            return Verdict::Exhausted;
        }

        if (!impl_->prepare())
        {
            return Verdict::Unsupported;
        }

        return detail::verify_replacement(impl_->symbolic, *impl_->invariants, block, statement,
                                          replacement);
    }
    catch (const std::exception &)
    {
        ++impl_->statistics.unsupported;
        return Verdict::Unsupported;
    }
}

const Statistics &Analysis::statistics() const
{
    return impl_->statistics;
}
} // namespace chernobog::mba_smt
