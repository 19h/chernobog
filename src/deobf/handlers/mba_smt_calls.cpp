#include "mba_smt_calls.h"
#include "mba_smt_ctree.h"

#include <algorithm>
#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <set>

namespace chernobog::mba_smt
{
namespace
{
using Bindings = ScalarContext::Bindings;
using Clock = std::chrono::steady_clock;

constexpr size_t max_callees = 16;
constexpr size_t max_call_depth = 3;
constexpr size_t max_callee_bytes = 4096;
constexpr size_t max_expression_attempts = 128;
constexpr size_t max_propagation_rounds = 3;
constexpr unsigned normal_expression_budget_ms = 250;
constexpr unsigned deep_expression_budget_ms = 1000;

// Decompiling a callee can deliver another maturity callback. That callback
// must not start a second interprocedural pass or recursively visit its caller.
thread_local bool building_call_summaries = false;

unsigned integer_bits(const tinfo_t &type)
{
    if (!type.is_integral() || type.is_volatile() || type.is_enum())
    {
        return 0;
    }
    const size_t bytes = type.get_size();
    return bytes == 1 || bytes == 2 || bytes == 4 || bytes == 8 ? unsigned(bytes * 8) : 0;
}

Term resize_integer(Term value, unsigned bits, bool sign_extend)
{
    if (!value || value->bits == 0 || bits == 0)
    {
        return {};
    }
    if (value->op == Op::Constant)
    {
        const uint64_t source_mask =
            value->bits == 64 ? UINT64_MAX : (uint64_t{1} << value->bits) - 1;
        const uint64_t target_mask = bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1;
        uint64_t literal = value->value & source_mask;
        if (bits > value->bits && sign_extend && (literal & (uint64_t{1} << (value->bits - 1))))
        {
            literal |= ~source_mask;
        }
        return constant(literal & target_mask, bits);
    }
    if (bits == value->bits)
    {
        return value;
    }
    if (bits < value->bits)
    {
        return expression(Op::Low, value, {}, bits);
    }
    return expression(sign_extend ? Op::SignExtend : Op::ZeroExtend, value, {}, bits);
}

Term convert_integer(Term value, const tinfo_t &source, const tinfo_t &destination)
{
    const unsigned bits = integer_bits(destination);
    if (!value || bits == 0)
    {
        return {};
    }
    if (destination.is_bool())
    {
        return expression(Op::NotEqual, value, constant(0, value->bits), bits);
    }
    return resize_integer(value, bits, source.is_signed());
}

class CallBudget
{
  public:
    explicit CallBudget(FunctionBudget &budget) : budget_(budget), started_(Clock::now()) {}

    ~CallBudget() { budget_.spent_ns += elapsed_ns(); }

    unsigned remaining_ms() const
    {
        const uint64_t spent = (budget_.spent_ns + elapsed_ns()) / 1000000;
        return spent < budget_.limit_ms ? unsigned(budget_.limit_ms - spent) : 0;
    }

    bool available() const { return remaining_ms() != 0 && !user_cancelled(); }

    FunctionBudget &owner() { return budget_; }

    void exclude_decompiler_time(Clock::duration elapsed)
    {
        // Callee decompilation is a separate SDK operation. Its own optimizer
        // budgets are charged to that callee, rather than the current caller.
        decompiler_ns_ +=
            uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
    }

  private:
    uint64_t elapsed_ns() const
    {
        const uint64_t elapsed = uint64_t(
            std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - started_).count());
        return elapsed > decompiler_ns_ ? elapsed - decompiler_ns_ : 0;
    }

    FunctionBudget &budget_;
    Clock::time_point started_;
    uint64_t decompiler_ns_ = 0;
};

struct Summary
{
    std::vector<tinfo_t> parameters;
    tinfo_t return_type;
    Term result;
};

class PureFunctions;

// Translate only effect-free scalar expressions. Caller bindings refer to
// immutable value versions; callee bindings refer to formal parameters.
class CtreeTerms
{
  public:
    CtreeTerms(PureFunctions &functions, const Bindings &bindings,
               const ScalarContext *context = nullptr)
        : functions_(functions), bindings_(bindings), context_(context)
    {
    }

    Term translate(const cexpr_t *node, unsigned depth = 0);
    bool used_context = false;

  private:
    PureFunctions &functions_;
    const Bindings &bindings_;
    const ScalarContext *context_;
    size_t visits_ = 0;
};

Term substitute_parameters(const Term &term, const std::vector<Term> &arguments, size_t &remaining)
{
    if (remaining == 0)
    {
        return {};
    }
    --remaining;
    if (term->op == Op::Variable)
    {
        return term->value < arguments.size() ? arguments[term->value] : Term{};
    }
    if (term->op == Op::Constant)
    {
        return term;
    }
    const Term left = substitute_parameters(term->left, arguments, remaining);
    const Term right =
        term->right ? substitute_parameters(term->right, arguments, remaining) : Term{};
    return left && (!term->right || right) ? expression(term->op, left, right, term->bits) : Term{};
}

// Each summary accounts for the complete callee body. This cache is local to
// one pass, so no proof can outlive the ctree or inferred ABI it was built from.
class PureFunctions
{
  public:
    PureFunctions(ea_t caller, CallBudget &budget) : budget_(budget) { active_.insert(caller); }

    bool available() const { return budget_.available(); }

    bool needs_refresh() const { return needs_refresh_; }

    Term instantiate(const cexpr_t *call, CtreeTerms &terms)
    {
        if (!call->x || call->x->op != cot_obj || !call->a || !available())
        {
            return {};
        }
        const Summary *summary = find(call->x->obj_ea);
        if (!summary || call->a->size() != summary->parameters.size())
        {
            if (summary)
            {
                needs_refresh_ = true;
                deobf::log_verbose("[mba_smt_calls] Argument count at %a: call=%zu callee=%zu\n",
                                   call->ea, call->a->size(), summary->parameters.size());
            }
            return {};
        }

        std::vector<Term> arguments;
        for (size_t index = 0; index < call->a->size(); ++index)
        {
            const carg_t &argument = (*call->a)[index];
            if (!argument.formal_type.empty() &&
                integer_bits(argument.formal_type) != integer_bits(summary->parameters[index]))
            {
                needs_refresh_ = true;
                deobf::log_verbose("[mba_smt_calls] Argument width at %a: call=%u callee=%u\n",
                                   call->ea, integer_bits(argument.formal_type),
                                   integer_bits(summary->parameters[index]));
                return {};
            }
            Term value = convert_integer(terms.translate(&argument), argument.type,
                                         summary->parameters[index]);
            if (!value)
            {
                return {};
            }
            arguments.push_back(std::move(value));
        }

        // A narrower caller result observes only low return bits. Widening an
        // inferred return type would assume an ABI extension that is not proved.
        if (integer_bits(call->type) > integer_bits(summary->return_type))
        {
            needs_refresh_ = true;
            deobf::log_verbose("[mba_smt_calls] Rejected return widening at %a: %u -> %u bits\n",
                               call->ea, integer_bits(summary->return_type),
                               integer_bits(call->type));
            return {};
        }
        size_t remaining = limits::expression_visits;
        Term result = substitute_parameters(summary->result, arguments, remaining);
        return convert_integer(result, summary->return_type, call->type);
    }

  private:
    const Summary *find(ea_t address)
    {
        const auto cached = summaries_.find(address);
        if (cached != summaries_.end())
        {
            return cached->second ? &*cached->second : nullptr;
        }
        if (!available() || active_.count(address) != 0 || active_.size() > max_call_depth ||
            summaries_.size() >= max_callees)
        {
            return nullptr;
        }

        func_t *native = get_func(address);
        if (!native || native->start_ea != address ||
            (native->flags & (FUNC_LIB | FUNC_THUNK)) != 0 ||
            calc_func_size(native) > max_callee_bytes)
        {
            summaries_.emplace(address, std::nullopt);
            return nullptr;
        }

        active_.insert(address);
        hexrays_failure_t failure;
        const auto started = Clock::now();
        cfuncptr_t function = decompile(native, &failure);
        budget_.exclude_decompiler_time(Clock::now() - started);
        std::optional<Summary> summary = function ? build(*function) : std::nullopt;
        deobf::log_verbose("[mba_smt_calls] Callee %a: decompiled=%d admitted=%d\n", address,
                           bool(function), bool(summary));
        active_.erase(address);
        const auto inserted = summaries_.emplace(address, std::move(summary));
        return inserted.first->second ? &*inserted.first->second : nullptr;
    }

    std::optional<Summary> build(cfunc_t &function)
    {
        tinfo_t type;
        func_type_data_t details;
        if (!function.get_func_type(&type) || !type.get_func_details(&details) ||
            details.is_vararg_cc() || is_user_cc(details.get_cc()) ||
            !integer_bits(details.rettype) || function.argidx.size() != details.size() ||
            function.body.op != cit_block || !function.body.cblock ||
            function.body.cblock->size() > limits::statements)
        {
            return {};
        }

        lvars_t *locals = function.get_lvars();
        if (!locals)
        {
            return {};
        }
        Summary summary;
        summary.return_type = details.rettype;
        Bindings bindings;
        for (size_t index = 0; index < details.size(); ++index)
        {
            const int local = function.argidx[index];
            if (local < 0 || size_t(local) >= locals->size() ||
                !integer_bits(details[index].type) || (*locals)[local].is_used_byref() ||
                (*locals)[local].is_overlapped_var())
            {
                return {};
            }
            summary.parameters.push_back(details[index].type);
            bindings[local] = variable(index, integer_bits(details[index].type));
        }

        for (const cinsn_t &statement : *function.body.cblock)
        {
            if (!available() || statement.label_num >= 0 || summary.result)
            {
                return {};
            }
            CtreeTerms terms(*this, bindings);
            if (statement.op == cit_return && statement.creturn)
            {
                const cexpr_t &value = statement.creturn->expr;
                summary.result =
                    convert_integer(terms.translate(&value), value.type, details.rettype);
                if (!summary.result)
                {
                    return {};
                }
            }
            else if (statement.op == cit_expr && statement.cexpr &&
                     statement.cexpr->op == cot_asg && statement.cexpr->x &&
                     statement.cexpr->x->op == cot_var && statement.cexpr->y)
            {
                const cexpr_t &assignment = *statement.cexpr;
                const int local = assignment.x->v.idx;
                if (local < 0 || size_t(local) >= locals->size() ||
                    (*locals)[local].is_used_byref() || (*locals)[local].is_overlapped_var())
                {
                    return {};
                }
                Term value = convert_integer(terms.translate(assignment.y), assignment.y->type,
                                             assignment.x->type);
                if (!value)
                {
                    return {};
                }
                bindings[local] = std::move(value);
            }
            else if (statement.op != cit_empty)
            {
                // Every statement must be accounted for. Stores, assembly,
                // branches, loops, and standalone calls make a helper ineligible.
                return {};
            }
        }
        return summary.result ? std::optional<Summary>(std::move(summary)) : std::nullopt;
    }

    CallBudget &budget_;
    std::set<ea_t> active_;
    std::map<ea_t, std::optional<Summary>> summaries_;
    bool needs_refresh_ = false;
};

Term CtreeTerms::translate(const cexpr_t *node, unsigned depth)
{
    if (!node || !functions_.available() || depth > limits::expression_depth ||
        ++visits_ > limits::expression_visits || !integer_bits(node->type))
    {
        return {};
    }
    const unsigned bits = integer_bits(node->type);
    if (node->op == cot_num)
    {
        return constant(node->numval(), bits);
    }
    if (node->op == cot_var)
    {
        const auto bound = bindings_.find(node->v.idx);
        if (bound != bindings_.end())
        {
            used_context |= !context_ || context_->derived(node->v.idx);
            return bound->second->bits == bits ? bound->second : Term{};
        }
        return {};
    }
    if (node->op == cot_call)
    {
        Term value = functions_.instantiate(node, *this);
        used_context |= bool(value);
        return value;
    }
    if (node->op == cot_cast)
    {
        return node->x ? convert_integer(translate(node->x, depth + 1), node->x->type, node->type)
                       : Term{};
    }
    if (node->op == cot_land || node->op == cot_lor)
    {
        Term left = translate(node->x, depth + 1);
        Term right = translate(node->y, depth + 1);
        if (!left || !right)
        {
            return {};
        }
        left = expression(Op::NotEqual, left, constant(0, left->bits), 8);
        right = expression(Op::NotEqual, right, constant(0, right->bits), 8);
        return resize_integer(expression(node->op == cot_land ? Op::And : Op::Or, left, right),
                              bits, false);
    }

    if (!is_binary(node->op) && node->op != cot_lnot && node->op != cot_bnot && node->op != cot_neg)
    {
        return {};
    }

    Term left = translate(node->x, depth + 1);
    if (!left)
    {
        return {};
    }
    if (node->op == cot_lnot)
    {
        return expression(Op::Equal, left, constant(0, left->bits), bits);
    }
    if (node->op == cot_bnot || node->op == cot_neg)
    {
        left = convert_integer(left, node->x->type, node->type);
        return left ? expression(node->op == cot_bnot ? Op::Not : Op::Neg, left) : Term{};
    }

    Op operation;
    bool comparison = false;
    bool reverse = false;
    bool invert = false;
    switch (node->op)
    {
    case cot_add:
        operation = Op::Add;
        break;
    case cot_sub:
        operation = Op::Sub;
        break;
    case cot_mul:
        operation = Op::Mul;
        break;
    case cot_udiv:
        operation = Op::UnsignedDivide;
        break;
    case cot_band:
        operation = Op::And;
        break;
    case cot_bor:
        operation = Op::Or;
        break;
    case cot_xor:
        operation = Op::Xor;
        break;
    case cot_shl:
        operation = Op::Shl;
        break;
    case cot_ushr:
        operation = Op::Shr;
        break;
    case cot_sshr:
        operation = Op::Sar;
        break;
    case cot_eq:
        operation = Op::Equal;
        comparison = true;
        break;
    case cot_ne:
        operation = Op::NotEqual;
        comparison = true;
        break;
    case cot_slt:
        operation = Op::SignedLess;
        comparison = true;
        break;
    case cot_ult:
        operation = Op::UnsignedLess;
        comparison = true;
        break;
    case cot_sgt:
        operation = Op::SignedLess;
        comparison = true;
        reverse = true;
        break;
    case cot_ugt:
        operation = Op::UnsignedLess;
        comparison = true;
        reverse = true;
        break;
    case cot_sge:
        operation = Op::SignedLess;
        comparison = true;
        invert = true;
        break;
    case cot_uge:
        operation = Op::UnsignedLess;
        comparison = true;
        invert = true;
        break;
    case cot_sle:
        operation = Op::SignedLess;
        comparison = true;
        reverse = true;
        invert = true;
        break;
    case cot_ule:
        operation = Op::UnsignedLess;
        comparison = true;
        reverse = true;
        invert = true;
        break;
    default:
        return {};
    }
    Term right = translate(node->y, depth + 1);
    if (!right)
    {
        return {};
    }

    // C integer promotions happen before the operation; a narrow result is
    // truncated afterwards. In particular, truncating before division or a
    // right shift would change the result.
    const bool shift = operation == Op::Shl || operation == Op::Shr || operation == Op::Sar;
    const unsigned operand_bits =
        std::max({32u, left->bits, shift ? 0u : right->bits, comparison ? 0u : bits});
    left = resize_integer(left, operand_bits, node->x->type.is_signed());

    if (shift)
    {
        if (right->op != Op::Constant || right->value >= operand_bits)
        {
            return {};
        }
        right = constant(right->value, 8);
    }
    else
    {
        right = resize_integer(right, operand_bits, node->y->type.is_signed());
    }
    if (operation == Op::UnsignedDivide && (right->op != Op::Constant || right->value == 0))
    {
        return {};
    }
    Term result = expression(operation, reverse ? right : left, reverse ? left : right,
                             comparison ? bits : operand_bits);
    if (!comparison && operand_bits != bits)
    {
        result = expression(Op::Low, result, {}, bits);
    }
    return invert ? expression(Op::Equal, result, constant(0, bits), bits) : result;
}

struct LocalSafety final : ctree_visitor_t
{
    explicit LocalSafety(cfunc_t &function) : ctree_visitor_t(CV_FAST)
    {
        for (const lvar_t &local : *function.get_lvars())
        {
            // A mapping destination is a canonical ctree local: the SDK has
            // replaced its mapped references, and assignments here version that
            // canonical index. Shared chains and overlapping storage still fail.
            safe.push_back(integer_bits(local.tif) && !local.is_used_byref() &&
                           !local.is_overlapped_var() && !local.is_shared() &&
                           !local.is_fake_var() && !local.is_noprop() && !local.in_asm());
        }
        apply_to(&function.body, nullptr);
    }

    int idaapi visit_expr(cexpr_t *node) override
    {
        if (node->op == cot_ref && node->x)
        {
            struct AddressVariables final : ctree_visitor_t
            {
                explicit AddressVariables(std::vector<bool> &entries)
                    : ctree_visitor_t(CV_FAST), entries(entries)
                {
                }

                int idaapi visit_expr(cexpr_t *operand) override
                {
                    if (operand->op == cot_var && operand->v.idx >= 0 &&
                        size_t(operand->v.idx) < entries.size())
                    {
                        entries[operand->v.idx] = false;
                    }
                    return 0;
                }

                std::vector<bool> &entries;
            } addresses(safe);

            addresses.apply_to(node->x, nullptr);
        }
        return 0;
    }

    std::vector<bool> safe;
};

struct ControlHazards final : ctree_visitor_t
{
    ControlHazards() : ctree_visitor_t(CV_FAST) {}

    int idaapi visit_insn(cinsn_t *node) override
    {
        if (++visited > limits::expression_visits)
        {
            labeled = writes = true;
            return 1;
        }
        labeled |= node->label_num >= 0;
        return 0;
    }

    int idaapi visit_expr(cexpr_t *node) override
    {
        if (++visited > limits::expression_visits)
        {
            labeled = writes = true;
            return 1;
        }
        writes |= (node->op >= cot_asg && node->op <= cot_asgumod) || node->op == cot_preinc ||
                  node->op == cot_predec || node->op == cot_postinc || node->op == cot_postdec;
        return 0;
    }

    bool labeled = false;
    bool writes = false;
    size_t visited = 0;
};

// Contexts are snapshots of scalar value versions, not substitutions into live
// lvalues. Every emitted replacement is retranslated in the same snapshot.
class CallerSimplifier
{
  public:
    CallerSimplifier(cfunc_t &function, CallBudget &budget)
        : function_(function), budget_(budget), functions_(function.entry_ea, budget),
          safety_(function)
    {
        const lvars_t &locals = *function_.get_lvars();
        for (size_t index = 0; index < locals.size(); ++index)
        {
            widths_.push_back(safety_.safe[index] ? integer_bits(locals[index].tif) : 0);
        }
    }

    CallSimplification run()
    {
        for (size_t round = 0; round < max_propagation_rounds && budget_.available(); ++round)
        {
            const int previous_changes = changes_;
            ScalarContext context(widths_);
            statement(function_.body, context);
            if (changes_ == previous_changes)
            {
                break;
            }
        }
        return {changes_, functions_.needs_refresh()};
    }

  private:
    Term translate(const cexpr_t &node, const ScalarContext &context)
    {
        CtreeTerms terms(functions_, context.bindings(), &context);
        return terms.translate(&node);
    }

    std::unique_ptr<cexpr_t> prepare_replacement(const cexpr_t &node, const ScalarContext &context,
                                                 const ContextQuery &query, Analysis &analysis,
                                                 const Term &candidate)
    {
        const Term value = query.restore(candidate);
        if (!value)
        {
            return {};
        }

        auto emitted = std::make_unique<cexpr_t>();
        if (!emit_scalar_expression(function_, context, value, node.type, *emitted))
        {
            return {};
        }
        const bool constant_result = emitted->op == cot_num && node.op != cot_num;
        if (!constant_result && scalar_expression_cost(*emitted) >= scalar_expression_cost(node))
        {
            return {};
        }

        const Term translated = query.lower(translate(*emitted, context));
        if (!translated || analysis.verify(query.block(), 0, translated) != Verdict::Verified)
        {
            return {};
        }
        emitted->ea = node.ea;
        return emitted;
    }

    bool fold(cexpr_t &node, const ScalarContext &context)
    {
        if (node.op == cot_num || !budget_.available() || attempts_ >= max_expression_attempts)
        {
            return false;
        }
        CtreeTerms terms(functions_, context.bindings(), &context);
        const Term value = terms.translate(&node);
        if (!value || (!terms.used_context && context.conditions().empty()))
        {
            return false;
        }
        ContextQuery query(context, value);
        if (!query.valid())
        {
            return false;
        }
        ++attempts_;

        Options options;
        const bool deep = budget_.owner().limit_ms > limits::normal_budget_ms;
        options.budget_ms = std::min(budget_.remaining_ms(), deep ? deep_expression_budget_ms
                                                                  : normal_expression_budget_ms);
        // Bindings already contain their complete scalar expressions. Only the
        // entry edge's guard and its negation are needed at this query block.
        options.max_invariants = 2;
        options.cancelled = [] { return user_cancelled(); };
        Analysis analysis(query.program(), options);
        std::unique_ptr<cexpr_t> replacement;
        if (const Term candidate = analysis.constant_value(query.block(), 0))
        {
            replacement = prepare_replacement(node, context, query, analysis, candidate);
        }
        // A path condition can make an ordinary expression constant. General
        // synthesis is reserved for expanded calls and derived local values,
        // so an unrelated guard cannot spend the function's budget enumerating
        // replacements for an already simple assignment.
        if (!replacement && node.op != cot_var && terms.used_context && budget_.available())
        {
            // Verify a cheaper expansion before spending the search budget.
            // This proof remains valid if a later search runs out of time:
            // neither the context nor the original expression has changed.
            replacement = prepare_replacement(node, context, query, analysis, query.lower(value));
            if (!replacement || scalar_expression_cost(*replacement) != 0)
            {
                for (const Proposal &proposal : analysis.run())
                {
                    auto improved =
                        prepare_replacement(node, context, query, analysis, proposal.replacement);
                    if (improved && (!replacement || scalar_expression_cost(*improved) <=
                                                         scalar_expression_cost(*replacement)))
                    {
                        replacement = std::move(improved);
                    }
                }
            }
        }

        const auto &statistics = analysis.statistics();
        auto &totals = budget_.owner().totals;
        totals.candidates += statistics.candidates;
        totals.verified += statistics.verified;
        totals.disproved += statistics.disproved;
        totals.unknown += statistics.unknown;
        totals.exhausted += statistics.exhausted;
        if (!replacement || user_cancelled())
        {
            return false;
        }
        node.swap(*replacement);
        ++changes_;
        ++totals.applied;
        return true;
    }

    void expression_tree(cexpr_t *node, const ScalarContext &context)
    {
        if (!node || !budget_.available())
        {
            return;
        }
        ControlHazards hazards;
        hazards.apply_to(node, nullptr);
        std::optional<ScalarContext> isolated;
        if (hazards.writes)
        {
            // The relative order of sibling writes and reads is not established
            // here. Only identities independent of the incoming state may fold.
            isolated.emplace(context);
            isolated->reset();
        }
        const ScalarContext &facts = isolated ? *isolated : context;
        if (fold(*node, facts))
        {
            return;
        }
        if (node->op == cot_call && node->a)
        {
            for (carg_t &argument : *node->a)
            {
                expression_tree(&argument, facts);
            }
        }
        else if (node->op == cot_asg)
        {
            expression_tree(node->y, facts);
        }
        else if (node->op == cot_cast || node->op == cot_neg || node->op == cot_bnot ||
                 node->op == cot_lnot)
        {
            expression_tree(node->x, facts);
        }
        else if (node->op >= cot_tern && node->op <= cot_fdiv)
        {
            expression_tree(node->x, facts);
            expression_tree(node->y, facts);
            if (node->op == cot_tern)
            {
                expression_tree(node->z, facts);
            }
        }
    }

    void assignment(cexpr_t &node, ScalarContext &context)
    {
        ControlHazards rhs;
        rhs.apply_to(node.y, nullptr);
        expression_tree(node.y, context);
        if (rhs.writes)
        {
            context.reset();
            return;
        }

        Term value;
        if (node.op == cot_asg)
        {
            value = translate(*node.y, context);
        }
        else
        {
            cexpr_t calculation(node);
            switch (node.op)
            {
            case cot_asgadd:
                calculation.op = cot_add;
                break;
            case cot_asgsub:
                calculation.op = cot_sub;
                break;
            case cot_asgmul:
                calculation.op = cot_mul;
                break;
            case cot_asgband:
                calculation.op = cot_band;
                break;
            case cot_asgbor:
                calculation.op = cot_bor;
                break;
            case cot_asgxor:
                calculation.op = cot_xor;
                break;
            default:
                context.forget(node.x->v.idx);
                return;
            }
            value = translate(calculation, context);
        }
        const tinfo_t &source_type = node.op == cot_asg ? node.y->type : node.type;
        context.assign(node.x->v.idx, convert_integer(value, source_type, node.x->type));
    }

    bool conditional(cinsn_t &node, ScalarContext &context)
    {
        expression_tree(&node.cif->expr, context);
        ControlHazards condition;
        condition.apply_to(&node.cif->expr, nullptr);
        if (condition.writes)
        {
            context.reset();
        }
        ControlHazards hazards;
        hazards.apply_to(&node, nullptr);
        if (node.cif->expr.op == cot_num && !hazards.labeled)
        {
            const cinsn_t *selected = node.cif->expr.numval() ? node.cif->ithen : node.cif->ielse;
            auto replacement = selected ? new cinsn_t(*selected) : new cinsn_t;
            if (!selected)
            {
                replacement->op = cit_block;
                replacement->cblock = new cblock_t;
            }
            node.cleanup();
            node.replace_by(replacement);
            ++changes_;
            return statement(node, context);
        }

        // A jump into a labeled branch does not pass through this condition.
        const Term predicate =
            !condition.writes && !hazards.labeled ? translate(node.cif->expr, context) : Term{};
        ScalarContext then_context = context;
        ScalarContext else_context = context;
        if (predicate)
        {
            then_context.assume(predicate, true);
            else_context.assume(predicate, false);
        }
        const bool then_continues = statement(*node.cif->ithen, then_context);
        const bool else_continues = !node.cif->ielse || statement(*node.cif->ielse, else_context);
        if (hazards.labeled)
        {
            context.reset();
            return true;
        }
        if (then_continues && else_continues)
        {
            then_context.merge_from(else_context);
            context = std::move(then_context);
        }
        else if (then_continues || else_continues)
        {
            context = then_continues ? std::move(then_context) : std::move(else_context);
        }
        else
        {
            context.reset();
        }
        return then_continues || else_continues;
    }

    bool statement(cinsn_t &node, ScalarContext &context)
    {
        if (!budget_.available())
        {
            context.reset();
            return true;
        }
        if (node.label_num >= 0)
        {
            context.reset();
        }
        switch (node.op)
        {
        case cit_block:
        {
            bool continues = true;
            for (auto iterator = node.cblock->begin(); iterator != node.cblock->end();)
            {
                cinsn_t &child = *iterator;
                if (!continues)
                {
                    context.reset();
                    ControlHazards hazards;
                    hazards.apply_to(&child, nullptr);
                    continues = hazards.labeled;
                }
                const bool child_continues = statement(child, context);
                continues = continues && child_continues;
                const bool empty =
                    child.op == cit_empty || (child.op == cit_block && child.cblock->empty());
                if (empty && child.label_num < 0)
                {
                    iterator = node.cblock->erase(iterator);
                }
                else
                {
                    ++iterator;
                }
            }
            // SDK address recalculation expects a first item even in an empty
            // branch body. Keep its canonical empty-statement placeholder.
            if (node.cblock->empty())
            {
                node.new_insn(node.ea);
            }
            return continues;
        }
        case cit_expr:
        {
            cexpr_t &value = *node.cexpr;
            if (value.op >= cot_asg && value.op <= cot_asgumod && value.x &&
                value.x->op == cot_var && value.y)
            {
                assignment(value, context);
            }
            else if ((value.op == cot_preinc || value.op == cot_postinc || value.op == cot_predec ||
                      value.op == cot_postdec) &&
                     value.x && value.x->op == cot_var)
            {
                const Term previous = context.value(value.x->v.idx);
                if (previous)
                {
                    const bool increment = value.op == cot_preinc || value.op == cot_postinc;
                    context.assign(value.x->v.idx,
                                   expression(increment ? Op::Add : Op::Sub, previous,
                                              constant(1, previous->bits)));
                }
            }
            else
            {
                ControlHazards hazards;
                hazards.apply_to(&value, nullptr);
                expression_tree(&value, context);
                if (hazards.writes)
                {
                    context.reset();
                }
            }
            return true;
        }
        case cit_if:
            return conditional(node, context);
        case cit_return:
            expression_tree(&node.creturn->expr, context);
            return false;
        case cit_while:
        case cit_do:
        case cit_for:
            // Iteration-specific values and assumptions never cross a backedge.
            context.reset();
            if (node.op == cit_while)
            {
                expression_tree(&node.cwhile->expr, context);
                statement(*node.cwhile->body, context);
            }
            else if (node.op == cit_do)
            {
                statement(*node.cdo->body, context);
                context.reset();
                expression_tree(&node.cdo->expr, context);
            }
            else
            {
                expression_tree(&node.cfor->init, context);
                context.reset();
                expression_tree(&node.cfor->expr, context);
                statement(*node.cfor->body, context);
                context.reset();
                expression_tree(&node.cfor->step, context);
            }
            context.reset();
            return true;
        case cit_empty:
            return true;
        case cit_goto:
        case cit_break:
        case cit_continue:
            context.reset();
            return false;
        default:
            context.reset();
            return true;
        }
    }

    cfunc_t &function_;
    CallBudget &budget_;
    PureFunctions functions_;
    LocalSafety safety_;
    std::vector<unsigned> widths_;
    size_t attempts_ = 0;
    int changes_ = 0;
};
} // namespace

CallSimplification simplify_calls(cfunc_t *function, FunctionBudget &budget)
{
    qstring enabled;
    qstring disabled;
    if (!function || !function->get_lvars() || building_call_summaries ||
        (qgetenv("CHERNOBOG_MBA_SMT", &enabled) && enabled == "0") ||
        (qgetenv("CHERNOBOG_DISABLE", &disabled) && !disabled.empty() && disabled[0] != '0'))
    {
        return {};
    }

    struct SummaryGuard
    {
        SummaryGuard() { building_call_summaries = true; }

        ~SummaryGuard() { building_call_summaries = false; }
    } guard;

    CallBudget allowance(budget);
    deobf::log_verbose("[mba_smt_calls] Starting %a with %u ms remaining\n", function->entry_ea,
                       allowance.remaining_ms());
    CallerSimplifier simplifier(*function, allowance);
    const auto result = simplifier.run();
    if (result.changes)
    {
        function->recalc_item_addresses();
        function->verify(ALLOW_UNUSED_LABELS, true);
        deobf::log("[mba_smt] Applied %d caller-context simplifications at %a\n", result.changes,
                   function->entry_ea);
    }
    return result;
}
} // namespace chernobog::mba_smt
