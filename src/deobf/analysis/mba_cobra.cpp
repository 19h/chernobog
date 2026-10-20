#include "mba_cobra.hpp"
#include "mba_cobra_test_hooks.hpp"
#include <cobra/core/Budget.h>
#include <cobra/core/SignatureEval.h>
#include <cobra/core/Simplifier.h>
#include <algorithm>
#include <array>
#include <set>
#include <stdexcept>

namespace chernobog::mba_smt::cobra_backend
{
namespace
{
uint64_t mask(unsigned bits) { return bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1; }
bool same(const Term &a, const Term &b)
{
    if (!a || !b)
        return !a && !b;
    return a->op == b->op && a->bits == b->bits && a->value == b->value && same(a->left, b->left) &&
           same(a->right, b->right);
}
struct ShapeFailure
{
    size_t leaves = 0, nodes = 0;
};
struct MappingFailure
{
};
struct Region
{
    unsigned bits;
    size_t leaf_limit;
    size_t visits = 0;
    std::array<Term, 12> admitted_atoms{};
    size_t admitted_count = 0, lowered_nodes = 0;
    cobra::BudgetVector<Term> atoms;
    cobra::BudgetVector<std::string> names;
    void inspect(const Term &term, unsigned depth = 0)
    {
        cobra::budget::Checkpoint();
        if (!term || ++visits > 512 || depth > 64 || term->bits < 8 || term->bits > 64 ||
            term->bits % 8 || term->op == Op::Load)
            throw ShapeFailure{};
        if (term->op == Op::Constant || term->op == Op::Variable)
        {
            if (term->left || term->right)
                throw ShapeFailure{};
            return;
        }
        if (!term->left)
            throw ShapeFailure{};
        const bool unary = term->op == Op::Not || term->op == Op::Neg ||
                           term->op == Op::ZeroExtend || term->op == Op::SignExtend ||
                           term->op == Op::Low || term->op == Op::High;
        if (unary ? bool(term->right) : !term->right)
            throw ShapeFailure{};
        switch (term->op)
        {
        case Op::ZeroExtend:
        case Op::SignExtend:
            if (term->left->bits > term->bits)
                throw ShapeFailure{};
            break;
        case Op::Low:
        case Op::High:
            if (term->left->bits < term->bits)
                throw ShapeFailure{};
            break;
        case Op::Shl:
        case Op::Shr:
        case Op::Sar:
            if (term->left->bits != term->bits || term->right->bits != 8)
                throw ShapeFailure{};
            break;
        case Op::Equal:
        case Op::NotEqual:
        case Op::UnsignedLess:
        case Op::SignedLess:
            if (term->left->bits != term->right->bits || term->bits != 8)
                throw ShapeFailure{};
            break;
        case Op::Add:
        case Op::Sub:
        case Op::Mul:
        case Op::UnsignedDivide:
        case Op::And:
        case Op::Or:
        case Op::Xor:
        case Op::Not:
        case Op::Neg:
            if (term->left->bits != term->bits || (term->right && term->right->bits != term->bits))
                throw ShapeFailure{};
            break;
        default:
            throw ShapeFailure{};
        }
        if (term->left)
            inspect(term->left, depth + 1);
        if (term->right)
            inspect(term->right, depth + 1);
    }
    void admit_atom(const Term &term)
    {
        for (size_t i = 0; i < admitted_count; ++i)
            if (same(admitted_atoms[i], term))
                return;
        if (admitted_count >= leaf_limit)
            throw ShapeFailure{admitted_count + 1, lowered_nodes};
        admitted_atoms[admitted_count++] = term;
    }
    void admit(const Term &term)
    {
        cobra::budget::Checkpoint();
        if (++lowered_nodes > 512 || term->bits != bits)
            throw ShapeFailure{};
        switch (term->op)
        {
        case Op::Constant:
            return;
        case Op::Add:
        case Op::Mul:
        case Op::And:
        case Op::Or:
        case Op::Xor:
            admit(term->left);
            admit(term->right);
            return;
        case Op::Sub:
            if (++lowered_nodes > 512)
                throw ShapeFailure{};
            admit(term->left);
            admit(term->right);
            return;
        case Op::Not:
        case Op::Neg:
            admit(term->left);
            return;
        case Op::ZeroExtend:
            lowered_nodes += 2;
            if (lowered_nodes > 512)
                throw ShapeFailure{};
            admit_atom(term);
            return;
        case Op::Shl:
        case Op::Shr:
            if (term->right && term->right->op == Op::Constant)
            {
                if ((term->right->value & UINT64_C(255)) >= bits)
                    return;
                if (term->op == Op::Shl && ++lowered_nodes > 512)
                    throw ShapeFailure{};
                admit(term->left);
                return;
            }
            [[fallthrough]];
        default:
            admit_atom(term);
            return;
        }
    }
    void prepare_atoms(const Term &term)
    {
        admit(term);
        atoms.reserve(admitted_count);
        names.reserve(admitted_count);
        for (size_t i = 0; i < admitted_count; ++i)
        {
            atoms.push_back(admitted_atoms[i]);
            names.push_back("v" + std::to_string(i));
        }
    }
    std::unique_ptr<cobra::Expr> atom(const Term &term)
    {
        for (size_t i = 0; i < atoms.size(); ++i)
            if (same(atoms[i], term))
                return cobra::Expr::Variable(static_cast<uint32_t>(i));
        throw ShapeFailure{};
    }
    void used_atoms(const Term &term, cobra::BudgetSet<size_t> &support)
    {
        if (!term || term->op == Op::Constant)
            return;
        cobra::budget::Checkpoint();
        for (size_t i = 0; i < atoms.size(); ++i)
            if (same(term, atoms[i]))
            {
                support.insert(i);
                return;
            }
        used_atoms(term->left, support);
        used_atoms(term->right, support);
    }
    std::unique_ptr<cobra::Expr> lower(const Term &term)
    {
        cobra::budget::Checkpoint();
        if (term->bits != bits)
            throw ShapeFailure{};
        using E = cobra::Expr;
        switch (term->op)
        {
        case Op::Constant:
            return E::Constant(term->value & mask(bits));
        case Op::Variable:
            return atom(term);
        case Op::Add:
            return E::Add(lower(term->left), lower(term->right));
        case Op::Sub:
            return E::Add(lower(term->left), E::Negate(lower(term->right)));
        case Op::Mul:
            return E::Mul(lower(term->left), lower(term->right));
        case Op::And:
            return E::BitwiseAnd(lower(term->left), lower(term->right));
        case Op::Or:
            return E::BitwiseOr(lower(term->left), lower(term->right));
        case Op::Xor:
            return E::BitwiseXor(lower(term->left), lower(term->right));
        case Op::Not:
            return E::BitwiseNot(lower(term->left));
        case Op::Neg:
            return E::Negate(lower(term->left));
        case Op::ZeroExtend:
            return E::BitwiseAnd(atom(term), E::Constant(mask(term->left->bits)));
        case Op::Shl:
            if (term->right && term->right->op == Op::Constant)
                return (term->right->value & UINT64_C(255)) >= bits
                           ? E::Constant(0)
                           : E::Mul(
                                 lower(term->left),
                                 E::Constant(uint64_t{1} << (term->right->value & UINT64_C(255))));
            return atom(term);
        case Op::Shr:
            if (term->right && term->right->op == Op::Constant)
                return (term->right->value & UINT64_C(255)) >= bits
                           ? E::Constant(0)
                           : E::LogicalShr(lower(term->left), term->right->value & UINT64_C(255));
            return atom(term);
        default:
            return atom(term);
        }
    }
    Term restore(const cobra::Expr &expr, const cobra::BudgetVector<size_t> &mapping, size_t &nodes,
                 cobra::BudgetSet<size_t> &support, unsigned depth = 0)
    {
        cobra::budget::Checkpoint();
        if (++nodes > 512 || depth > 64)
            throw ShapeFailure{};
        using K = cobra::Expr::Kind;
        if (expr.kind == K::kConstant)
        {
            if (!expr.children.empty())
                throw ShapeFailure{};
            return constant(expr.constant_val, bits);
        }
        if (expr.kind == K::kVariable)
        {
            if (!expr.children.empty() || expr.var_index >= mapping.size())
                throw MappingFailure{};
            const size_t index = mapping[expr.var_index];
            support.insert(index);
            return atoms.at(index);
        }
        const bool unary = expr.kind == K::kNot || expr.kind == K::kNeg || expr.kind == K::kShr;
        if (expr.children.size() != (unary ? 1u : 2u) || !expr.children[0] ||
            (!unary && !expr.children[1]))
            throw ShapeFailure{};
        Term left = restore(*expr.children[0], mapping, nodes, support, depth + 1);
        Term right =
            unary ? Term{} : restore(*expr.children[1], mapping, nodes, support, depth + 1);
        Op op;
        switch (expr.kind)
        {
        case K::kAdd:
            op = Op::Add;
            break;
        case K::kMul:
            op = Op::Mul;
            break;
        case K::kAnd:
            op = Op::And;
            break;
        case K::kOr:
            op = Op::Or;
            break;
        case K::kXor:
            op = Op::Xor;
            break;
        case K::kNot:
            op = Op::Not;
            break;
        case K::kNeg:
            op = Op::Neg;
            break;
        case K::kShr:
            if (expr.constant_val >= bits)
                return constant(0, bits);
            return expression(Op::Shr, left, constant(expr.constant_val, 8), bits);
        default:
            throw ShapeFailure{};
        }
        if (op == Op::And)
        {
            const auto redundant = [](const Term &value, const Term &literal)
            {
                return value->op == Op::ZeroExtend && literal->op == Op::Constant &&
                       (literal->value & mask(value->left->bits)) == mask(value->left->bits);
            };
            if (redundant(left, right))
                return left;
            if (redundant(right, left))
                return right;
        }
        return expression(op, left, right, bits);
    }
};
size_t materialized_nodes(const Term &term, size_t &visits, unsigned depth = 0)
{
    if (!term)
        return 0;
    cobra::budget::Checkpoint();
    if (++visits > 512 || depth > 64)
        throw ShapeFailure{};
    return 1 + materialized_nodes(term->left, visits, depth + 1) +
           materialized_nodes(term->right, visits, depth + 1);
}
}
bool available() noexcept { return true; }
Outcome generate(const Term &original, const Request &request)
{
    Outcome outcome;
    bool clock_failed = false;
    const auto now = [&]() noexcept
    {
        try
        {
            return request.now ? request.now() : Clock::now();
        }
        catch (...)
        {
            clock_failed = true;
            return Clock::now();
        }
    };
    const auto started = now();
    auto phase_started = started;
    auto *phase = &outcome.extraction_ns;
    const auto enter = [&](uint64_t &next)
    {
        const auto time = now();
        *phase += static_cast<uint64_t>(std::max<int64_t>(
            0, std::chrono::duration_cast<std::chrono::nanoseconds>(time - phase_started).count()));
        phase_started = time;
        phase = &next;
    };
    const auto signal = [&](detail::CobraPhase current)
    {
        outcome.last_phase = unsigned(current) + 1;
        if (detail::cobra_test_hooks && detail::cobra_test_hooks->entered_phase)
        {
            detail::cobra_test_hooks->entered_phase(current);
            cobra::budget::Checkpoint(true);
        }
    };
    const auto allowance = request.scratch_bytes              ? request.scratch_bytes
                           : request.profile == Profile::Deep ? 268435456u
                                                              : 67108864u;
    std::shared_ptr<cobra::budget::Ledger> ledger;
    try
    {
        ledger = std::make_shared<cobra::budget::Ledger>(allowance);
        if (clock_failed)
            throw cobra::budget::Exhausted{cobra::budget::Reason::Callback};
        cobra::budget::Scope scope({request.deadline, request.cancelled, now, ledger});
        signal(detail::CobraPhase::Extraction);
        cobra::budget::Checkpoint(true);
        if (!original)
            throw ShapeFailure{};
        Region region{original->bits, request.profile == Profile::Deep ? size_t(12) : size_t(8)};
        region.inspect(original);
        outcome.input_nodes = region.visits;
        outcome.input_cost = cost(original);
        region.prepare_atoms(original);
        outcome.input_nodes = region.lowered_nodes;
        outcome.admitted = true;
        auto input = region.lower(original);
        outcome.raw_leaves = region.atoms.size();
        enter(outcome.invocation_ns);
        signal(detail::CobraPhase::Invocation);
        auto signature = cobra::EvaluateBooleanSignature(
            *input, static_cast<uint32_t>(region.atoms.size()), region.bits);
        cobra::Options options;
        options.bitwidth = region.bits;
        options.max_vars = static_cast<uint32_t>(region.leaf_limit);
        options.spot_check = true;
        auto result = cobra::Simplify(signature, region.names, input.get(), options);
        enter(outcome.reconstruction_ns);
        signal(detail::CobraPhase::Reconstruction);
        if (result)
            outcome.spot_check = result->verified;
        if (result && detail::cobra_test_hooks && detail::cobra_test_hooks->generated)
            detail::cobra_test_hooks->generated(*result);
        if (!result)
        {
            outcome.status = Status::Unsupported;
            outcome.reason = Reason::Upstream;
        }
        else if (result->kind == cobra::SimplifyOutcome::Kind::kSimplified && result->expr &&
                 result->verified)
        {
            if (result->real_vars.size() > region.atoms.size())
                throw MappingFailure{};
            cobra::BudgetVector<size_t> mapping;
            cobra::BudgetSet<std::string> seen;
            for (const auto &name : result->real_vars)
            {
                auto found = std::find(region.names.begin(), region.names.end(), name);
                if (found == region.names.end() || !seen.insert(name).second)
                    throw MappingFailure{};
                mapping.push_back(static_cast<size_t>(found - region.names.begin()));
            }
            outcome.raw_support = mapping.size();
            for (size_t i = 0; i < mapping.size(); ++i)
                outcome.raw_indices[i] = static_cast<unsigned>(mapping[i]);
            cobra::BudgetSet<size_t> support;
            size_t nodes = 0;
            Term candidate = region.restore(*result->expr, mapping, nodes, support);
            size_t restored_visits = 0;
            outcome.output_nodes = materialized_nodes(candidate, restored_visits);
            outcome.output_cost = cost(candidate);
            if (outcome.output_nodes > 512)
                throw ShapeFailure{};
            support.clear();
            region.used_atoms(candidate, support);
            outcome.canonical_support = support.size();
            outcome.spot_check = result->verified;
            if (cost(candidate) < cost(original))
            {
                outcome.candidate = std::move(candidate);
                outcome.status = Status::Candidate;
            }
            else
            {
                outcome.reason = Reason::Cost;
            }
        }
        cobra::budget::Checkpoint(true);
        outcome.timings_complete = true;
        enter(outcome.cleanup_ns);
        signal(detail::CobraPhase::Cleanup);
    }
    catch (const cobra::budget::Exhausted &error)
    {
        outcome.status = Status::Exhausted;
        using R = cobra::budget::Reason;
        outcome.reason = error.reason == R::Deadline       ? Reason::Deadline
                         : error.reason == R::Cancellation ? Reason::Cancellation
                         : error.reason == R::Callback     ? Reason::Callback
                                                           : Reason::Allocation;
    }
    catch (const MappingFailure &)
    {
        outcome.status = Status::Unsupported;
        outcome.reason = Reason::Mapping;
    }
    catch (const ShapeFailure &shape)
    {
        if (shape.leaves)
            outcome.raw_leaves = shape.leaves;
        if (shape.nodes)
            outcome.input_nodes = shape.nodes;
        outcome.status = Status::Unsupported;
        outcome.reason = Reason::Shape;
    }
    catch (const std::bad_alloc &)
    {
        outcome.status = Status::Exhausted;
        outcome.reason = Reason::Allocation;
    }
    catch (...)
    {
        outcome.status = Status::Failure;
        outcome.reason = Reason::Upstream;
    }
    // On exceptional exits, unwinding belongs to the last observed phase;
    // timings_complete distinguishes those samples from complete phase splits.
    if (phase != &outcome.cleanup_ns)
        enter(outcome.cleanup_ns);
    outcome.scratch_peak_bytes = ledger ? ledger->peak : 0;
    // All upstream temporaries have been destroyed before accepting the result.
    try
    {
        if (detail::cobra_test_hooks && detail::cobra_test_hooks->after_cleanup)
            detail::cobra_test_hooks->after_cleanup();
    }
    catch (...)
    {
        outcome.status = Status::Failure;
        outcome.reason = Reason::Upstream;
    }
    bool cancelled = false;
    try
    {
        cancelled = request.cancelled && request.cancelled();
    }
    catch (...)
    {
        outcome.status = Status::Failure;
        outcome.reason = Reason::Callback;
    }
    const auto finished = now();
    outcome.cleanup_ns += static_cast<uint64_t>(std::max<int64_t>(
        0, std::chrono::duration_cast<std::chrono::nanoseconds>(finished - phase_started).count()));
    outcome.elapsed_ns = static_cast<uint64_t>(std::max<int64_t>(
        0, std::chrono::duration_cast<std::chrono::nanoseconds>(finished - started).count()));
    if (cancelled || finished >= request.deadline)
    {
        outcome.status = Status::Exhausted;
        outcome.reason = cancelled ? Reason::Cancellation : Reason::Deadline;
        if (finished > request.deadline)
            outcome.overshoot_ns = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(finished - request.deadline)
                    .count());
    }
    if (clock_failed)
    {
        outcome.status = Status::Failure;
        outcome.reason = Reason::Callback;
        outcome.timings_complete = false;
        outcome.elapsed_ns = 0;
        outcome.extraction_ns = outcome.invocation_ns = outcome.reconstruction_ns =
            outcome.cleanup_ns = 0;
    }
    if (outcome.status != Status::Candidate)
        outcome.candidate.reset();
    return outcome;
}
} // namespace chernobog::mba_smt::cobra_backend
