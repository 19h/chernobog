#include "mba_smt_calls.h"

#include <algorithm>
#include <chrono>
#include <map>
#include <optional>
#include <set>

namespace chernobog::mba_smt
{
namespace
{
using Bindings = std::map<int, Term>;
using Clock = std::chrono::steady_clock;

constexpr size_t max_callees = 16;
constexpr size_t max_call_depth = 3;
constexpr size_t max_callee_bytes = 4096;
constexpr size_t max_expression_attempts = 128;

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
    explicit CallBudget(FunctionBudget &budget) : budget_(budget), started_(Clock::now())
    {
    }

    ~CallBudget()
    {
        budget_.spent_ns += elapsed_ns();
    }

    unsigned remaining_ms() const
    {
        const uint64_t spent = (budget_.spent_ns + elapsed_ns()) / 1000000;
        return spent < budget_.limit_ms ? unsigned(budget_.limit_ms - spent) : 0;
    }

    bool available() const
    {
        return remaining_ms() != 0 && !user_cancelled();
    }

    FunctionBudget &owner()
    {
        return budget_;
    }

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

// Translate only effect-free scalar expressions. Caller symbols have a single
// candidate lifetime; bindings supplied by the statement walk are closed values.
class CtreeTerms
{
  public:
    CtreeTerms(PureFunctions &functions, const Bindings &bindings,
               std::vector<unsigned> *widths = nullptr, const std::vector<bool> *safe = nullptr)
        : functions_(functions), bindings_(bindings), widths_(widths), safe_(safe)
    {
    }

    Term translate(const cexpr_t *node, unsigned depth = 0);
    bool used_context = false;

  private:
    PureFunctions &functions_;
    const Bindings &bindings_;
    std::vector<unsigned> *widths_;
    const std::vector<bool> *safe_;
    std::map<int, size_t> symbols_;
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
    PureFunctions(ea_t caller, CallBudget &budget) : budget_(budget)
    {
        active_.insert(caller);
    }

    bool available() const
    {
        return budget_.available();
    }

    bool needs_refresh() const
    {
        return needs_refresh_;
    }

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
            used_context = true;
            return bound->second->bits == bits ? bound->second : Term{};
        }
        if (!widths_ || !safe_ || node->v.idx < 0 || size_t(node->v.idx) >= safe_->size() ||
            !(*safe_)[node->v.idx])
        {
            return {};
        }
        const auto inserted = symbols_.emplace(node->v.idx, widths_->size());
        if (inserted.second)
        {
            widths_->push_back(bits);
        }
        return variable(inserted.first->second, bits);
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
            safe.push_back(integer_bits(local.tif) && !local.is_used_byref() &&
                           !local.is_overlapped_var() && !local.is_shared() &&
                           !local.is_fake_var() && !local.is_mapdst_var() && !local.is_noprop() &&
                           !local.in_asm());
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
    ControlHazards() : ctree_visitor_t(CV_FAST)
    {
    }

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

// Specialize calls virtually for proof, then materialize only a proven literal.
// This avoids duplicating callee expressions or moving their evaluation order.
class CallerSimplifier
{
  public:
    CallerSimplifier(cfunc_t &function, CallBudget &budget)
        : function_(function), budget_(budget), functions_(function.entry_ea, budget),
          safety_(function)
    {
    }

    CallSimplification run()
    {
        Bindings bindings;
        statement(function_.body, bindings);
        return {changes_, functions_.needs_refresh()};
    }

  private:
    bool fold(cexpr_t &node, const Bindings &bindings)
    {
        if (!budget_.available() || attempts_ >= max_expression_attempts)
        {
            return false;
        }
        std::vector<unsigned> widths;
        CtreeTerms terms(functions_, bindings, &widths, &safety_.safe);
        const Term value = terms.translate(&node);
        if (!value || !terms.used_context)
        {
            return false;
        }
        ++attempts_;

        Program program;
        program.widths = std::move(widths);
        const size_t result_index = program.widths.size();
        program.widths.push_back(value->bits);
        program.blocks.resize(1);
        program.blocks[0].statements = {Statement::assign(result_index, value)};
        Options options;
        options.budget_ms = budget_.remaining_ms();
        options.cancelled = [] { return user_cancelled(); };
        Analysis analysis(std::move(program), options);
        const Term replacement = analysis.constant_value(0, 0);
        const tinfo_t original_type = node.type;
        bool verified = false;
        if (replacement)
        {
            cexpr_t emitted;
            emitted.put_number(&function_, replacement->value, value->bits / 8, no_sign);
            emitted.type = original_type;
            CtreeTerms emitted_terms(functions_, bindings);
            const Term translated = emitted_terms.translate(&emitted);
            verified = translated && analysis.verify(0, 0, translated) == Verdict::Verified;
        }
        const auto &statistics = analysis.statistics();
        auto &totals = budget_.owner().totals;
        totals.candidates += statistics.candidates;
        totals.verified += statistics.verified;
        totals.disproved += statistics.disproved;
        totals.unknown += statistics.unknown;
        totals.exhausted += statistics.exhausted;

        if (!verified)
        {
            return false;
        }

        node.put_number(&function_, replacement->value, value->bits / 8, no_sign);
        node.type = original_type;
        ++changes_;
        ++totals.applied;
        return true;
    }

    void expression_tree(cexpr_t *node, const Bindings &bindings)
    {
        if (!node || !budget_.available())
        {
            return;
        }
        ControlHazards hazards;
        hazards.apply_to(node, nullptr);
        const Bindings empty;
        const Bindings &context = hazards.writes ? empty : bindings;
        if (fold(*node, context))
        {
            return;
        }
        if (node->op == cot_call && node->a)
        {
            for (carg_t &argument : *node->a)
            {
                expression_tree(&argument, context);
            }
        }
        else if (node->op == cot_asg)
        {
            expression_tree(node->y, context);
        }
        else if (node->op == cot_cast || node->op == cot_neg || node->op == cot_bnot ||
                 node->op == cot_lnot)
        {
            expression_tree(node->x, context);
        }
        else if (node->op >= cot_tern && node->op <= cot_fdiv)
        {
            expression_tree(node->x, context);
            expression_tree(node->y, context);
            if (node->op == cot_tern)
            {
                expression_tree(node->z, context);
            }
        }
    }

    void statement(cinsn_t &node, Bindings &bindings)
    {
        if (!budget_.available())
        {
            return;
        }
        if (node.label_num >= 0)
        {
            bindings.clear();
        }
        switch (node.op)
        {
        case cit_block:
            for (cinsn_t &child : *node.cblock)
            {
                statement(child, bindings);
            }
            break;
        case cit_expr:
        {
            cexpr_t *value = node.cexpr;
            ControlHazards hazards;
            hazards.apply_to(value, nullptr);
            expression_tree(value->op == cot_asg ? value->y : value, bindings);
            if (value->op == cot_asg && value->x && value->x->op == cot_var && value->y)
            {
                const int local = value->x->v.idx;
                ControlHazards rhs;
                rhs.apply_to(value->y, nullptr);
                if (rhs.writes)
                {
                    bindings.clear();
                }
                bindings.erase(local);
                if (local >= 0 && size_t(local) < safety_.safe.size() && safety_.safe[local] &&
                    value->y->op == cot_num && integer_bits(value->y->type) != 0)
                {
                    bindings[local] =
                        convert_integer(constant(value->y->numval(), integer_bits(value->y->type)),
                                        value->y->type, value->x->type);
                    if (!bindings[local])
                    {
                        bindings.erase(local);
                    }
                }
            }
            else if (hazards.writes)
            {
                bindings.clear();
            }
            break;
        }
        case cit_if:
        {
            expression_tree(&node.cif->expr, bindings);
            ControlHazards condition;
            condition.apply_to(&node.cif->expr, nullptr);
            if (condition.writes)
            {
                bindings.clear();
            }
            ControlHazards hazards;
            hazards.apply_to(&node, nullptr);
            if (node.cif->expr.op == cot_num && !hazards.labeled)
            {
                cinsn_t *selected = node.cif->expr.numval() ? node.cif->ithen : node.cif->ielse;
                cinsn_t *replacement = selected ? new cinsn_t(*selected) : new cinsn_t;
                node.cleanup();
                node.replace_by(replacement);
                ++changes_;
                statement(node, bindings);
                break;
            }
            Bindings branch = bindings;
            statement(*node.cif->ithen, branch);
            if (node.cif->ielse)
            {
                branch = bindings;
                statement(*node.cif->ielse, branch);
            }
            bindings.clear();
            break;
        }
        case cit_return:
            expression_tree(&node.creturn->expr, bindings);
            bindings.clear();
            break;
        case cit_while:
        case cit_do:
        case cit_for:
            // A binding at loop entry need not hold at the next iteration.
            bindings.clear();
            if (node.op == cit_while)
            {
                expression_tree(&node.cwhile->expr, bindings);
                statement(*node.cwhile->body, bindings);
            }
            else if (node.op == cit_do)
            {
                expression_tree(&node.cdo->expr, bindings);
                statement(*node.cdo->body, bindings);
            }
            else
            {
                expression_tree(&node.cfor->init, bindings);
                expression_tree(&node.cfor->expr, bindings);
                expression_tree(&node.cfor->step, bindings);
                statement(*node.cfor->body, bindings);
            }
            bindings.clear();
            break;
        default:
            bindings.clear();
            break;
        }
    }

    cfunc_t &function_;
    CallBudget &budget_;
    PureFunctions functions_;
    LocalSafety safety_;
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
        SummaryGuard()
        {
            building_call_summaries = true;
        }

        ~SummaryGuard()
        {
            building_call_summaries = false;
        }
    } guard;

    CallBudget allowance(budget);
    deobf::log_verbose("[mba_smt_calls] Starting %a with %u ms remaining\n", function->entry_ea,
                       allowance.remaining_ms());
    CallerSimplifier simplifier(*function, allowance);
    const auto result = simplifier.run();
    if (result.changes)
    {
        function->verify(ALLOW_UNUSED_LABELS, false);
        deobf::log("[mba_smt] Applied %d caller-context simplifications at %a\n", result.changes,
                   function->entry_ea);
    }
    return result;
}
} // namespace chernobog::mba_smt
