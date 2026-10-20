#include "mba_cobra.hpp"
#include "mba_cobra_test_hooks.hpp"
#include <cobra/core/Budget.h>
#include <cobra/core/SignatureEval.h>
#include <cobra/core/Simplifier.h>
#include <algorithm>
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
};
struct MappingFailure
{
};
struct Region
{
    unsigned bits;
    size_t leaf_limit;
    size_t visits = 0;
    cobra::BudgetVector<Term> atoms;
    cobra::BudgetVector<std::string> names;
    void inspect(const Term &term, unsigned depth = 0)
    {
        cobra::budget::Checkpoint();
        if (!term || ++visits > 512 || depth > 64 || term->bits < 8 || term->bits > 64 ||
            term->bits % 8 || term->op == Op::Load)
            throw ShapeFailure{};
        if (term->left)
            inspect(term->left, depth + 1);
        if (term->right)
            inspect(term->right, depth + 1);
    }
    std::unique_ptr<cobra::Expr> atom(const Term &term)
    {
        for (size_t i = 0; i < atoms.size(); ++i)
            if (same(atoms[i], term))
                return cobra::Expr::Variable(static_cast<uint32_t>(i));
        if (atoms.size() >= leaf_limit)
            throw ShapeFailure{};
        const auto index = static_cast<uint32_t>(atoms.size());
        atoms.push_back(term);
        names.push_back("v" + std::to_string(index));
        return cobra::Expr::Variable(index);
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
                return term->right->value >= bits
                           ? E::Constant(0)
                           : E::Mul(lower(term->left),
                                    E::Constant(uint64_t{1} << term->right->value));
            return atom(term);
        case Op::Shr:
            if (term->right && term->right->op == Op::Constant)
                return term->right->value >= bits
                           ? E::Constant(0)
                           : E::LogicalShr(lower(term->left), term->right->value);
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
    const auto now = [&] { return request.now ? request.now() : Clock::now(); };
    const auto started = now();
    const auto allowance = request.scratch_bytes              ? request.scratch_bytes
                           : request.profile == Profile::Deep ? 268435456u
                                                              : 67108864u;
    std::shared_ptr<cobra::budget::Ledger> ledger;
    try
    {
        ledger = std::make_shared<cobra::budget::Ledger>(allowance);
        cobra::budget::Scope scope({request.deadline, request.cancelled, request.now, ledger});
        cobra::budget::Checkpoint(true);
        if (!original)
            throw ShapeFailure{};
        Region region{original->bits, request.profile == Profile::Deep ? size_t(12) : size_t(8)};
        region.inspect(original);
        outcome.input_nodes = region.visits;
        auto input = region.lower(original);
        outcome.raw_leaves = region.atoms.size();
        auto signature = cobra::EvaluateBooleanSignature(
            *input, static_cast<uint32_t>(region.atoms.size()), region.bits);
        cobra::Options options;
        options.bitwidth = region.bits;
        options.max_vars = static_cast<uint32_t>(region.leaf_limit);
        options.spot_check = true;
        auto result = cobra::Simplify(signature, region.names, input.get(), options);
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
            cobra::BudgetSet<size_t> support;
            size_t nodes = 0;
            Term candidate = region.restore(*result->expr, mapping, nodes, support);
            size_t restored_visits = 0;
            outcome.output_nodes = materialized_nodes(candidate, restored_visits);
            if (outcome.output_nodes > 512)
                throw ShapeFailure{};
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
    catch (const ShapeFailure &)
    {
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
    if (outcome.status != Status::Candidate)
        outcome.candidate.reset();
    return outcome;
}
} // namespace chernobog::mba_smt::cobra_backend
