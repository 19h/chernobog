#include "mba_smt_control.h"
#include "mba_smt_ctree.h"
#include "mba_smt_emission.hpp"

#include <algorithm>
#include <chrono>
#include <optional>
#include <set>

namespace chernobog::mba_smt
{
namespace
{
using Clock = std::chrono::steady_clock;
constexpr size_t max_nodes = 4096, max_steps = 256, max_forks = 16, max_proofs = 128;

struct Inventory : ctree_visitor_t
{
    size_t nodes = 0, controls = 0;
    bool invalid = false;
    Inventory() : ctree_visitor_t(CV_PARENTS) {}
    int idaapi visit_expr(cexpr_t *node) override
    {
        return ++nodes > max_nodes || parents.size() > 64 || node->label_num >= 0;
    }
    int idaapi visit_insn(cinsn_t *node) override
    {
        controls += node->op == cit_for || node->op == cit_while || node->op == cit_do ||
                    node->op == cit_switch;
        invalid |= node->label_num >= 0 || node->op == cit_goto || node->op == cit_asm ||
                   node->op == cit_try || node->op == cit_throw;
        if (node->op == cit_switch)
        {
            if (!node->cswitch)
                return 1;
            const unsigned bits = scalar_integer_bits(node->cswitch->expr.type);
            // Narrow switches also require an explicit model of promoted case
            // values. Keep them outside this closed-state adapter.
            if (bits < 32)
                return 1;
            const uint64_t mask = bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1;
            std::set<uint64_t> values;
            bool fallback = false;
            size_t labels = 0;
            for (const auto &branch : node->cswitch->cases)
            {
                if (branch.values.empty())
                {
                    if (fallback)
                        return 1;
                    fallback = true;
                }
                for (const uint64 value : branch.values)
                    if (++labels > 256 || !values.insert(value & mask).second)
                        return 1;
            }
        }
        return ++nodes > max_nodes || parents.size() > 64 || invalid;
    }
};

bool scalar_local(const lvar_t &local)
{
    return scalar_integer_bits(local.tif) && !local.is_used_byref() && !local.is_overlapped_var() &&
           !local.is_shared() && !local.is_fake_var() && !local.is_noprop() && !local.in_asm();
}
struct AddressSafety : ctree_visitor_t
{
    std::vector<bool> &safe;
    AddressSafety(std::vector<bool> &safe) : ctree_visitor_t(CV_FAST), safe(safe) {}
    int idaapi visit_expr(cexpr_t *node) override
    {
        if (node->op == cot_ref && node->x)
        {
            struct Mark : ctree_visitor_t
            {
                std::vector<bool> &safe;
                Mark(std::vector<bool> &s) : ctree_visitor_t(CV_FAST), safe(s) {}
                int idaapi visit_expr(cexpr_t *value) override
                {
                    if (value->op == cot_var && value->v.idx >= 0 &&
                        size_t(value->v.idx) < safe.size())
                        safe[value->v.idx] = false;
                    return 0;
                }
            } mark(safe);
            mark.apply_to(node->x, nullptr);
        }
        return 0;
    }
};
struct Writes : ctree_visitor_t
{
    bool writes = false;
    Writes() : ctree_visitor_t(CV_FAST) {}
    int idaapi visit_expr(cexpr_t *node) override
    {
        writes |= (node->op >= cot_asg && node->op <= cot_asgumod) || node->op == cot_preinc ||
                  node->op == cot_postinc || node->op == cot_predec || node->op == cot_postdec ||
                  node->op == cot_call;
        return 0;
    }
};

struct Scope;
struct Step
{
    enum Kind
    {
        Statement,
        Test,
        Repeat
    } kind = Statement;
    const cinsn_t *node;
    std::shared_ptr<const Scope> scope;
};
using Work = std::vector<Step>;
struct Scope
{
    const cinsn_t *loop = nullptr;
    std::shared_ptr<const Scope> parent;
    Work after;
};
struct Certificate
{
    cexpr_t source;
    Program query;
    Term value;
    std::shared_ptr<const CtreeEmissionProof> proof;
    Certificate(const cexpr_t &source, Program query, Term value,
                std::shared_ptr<const CtreeEmissionProof> proof)
        : source(source), query(std::move(query)), value(std::move(value)), proof(std::move(proof))
    {
    }
};

class Control
{
  public:
    Control(cfunc_t &function, FunctionBudget &budget, const ControlFlowTestHooks *tests,
            Clock::time_point started, Clock::time_point deadline, size_t original_nodes)
        : function_(function), budget_(budget), tests_(tests), owner_(function.mba),
          source_(function.body), source_locals_(*function.get_lvars()), snapshot_(budget.snapshot),
          deadline_(deadline), original_nodes_(original_nodes)
    {
        (void)started;
        for (const auto &local : source_locals_)
            safe_.push_back(scalar_local(local));
        AddressSafety(safe_).apply_to(&source_, nullptr);
        for (size_t i = 0; i < safe_.size(); ++i)
            widths_.push_back(safe_[i] ? scalar_integer_bits(source_locals_[i].tif) : 0);
    }
    ~Control()
    {
        if (last_analysis_)
            accumulate_statistics(budget_.totals, last_analysis_->statistics());
    }
    Clock::time_point now() const { return tests_ && tests_->now ? tests_->now() : Clock::now(); }
    bool cancelled() const
    {
        return user_cancelled() || (tests_ && tests_->cancelled && tests_->cancelled());
    }
    bool available() const { return !cancelled() && now() < deadline_; }
    int run()
    {
        if (!capture_native() || !available())
            return 0;
        cinsn_t staged;
        lvars_t locals(source_locals_);
        if (!generate(staged, locals, false) || certificates_.empty() || !last_analysis_ ||
            !last_proof_)
            return 0;
        if (tests_ && tests_->before_commit)
            tests_->before_commit(staged, locals);
        const auto unchanged = [&]
        {
            if (!available() || !source_matches())
                return false;
            cinsn_t expected;
            lvars_t expected_locals(source_locals_);
            return generate(expected, expected_locals, true) && same_ctree_body(expected, staged) &&
                   same_ctree_locals(expected_locals, locals);
        };
        if (!last_analysis_->eligible_for_commit(last_proof_->core(), false, unchanged))
            return 0;
        if (budget_.snapshot != snapshot_ || function_.mba != owner_)
        {
            last_analysis_->reject_mutation(RejectReason::StaleSnapshot);
            return 0;
        }
        function_.body.swap(staged);
        function_.get_lvars()->swap(locals);
        ++budget_.snapshot.mutation_epoch;
        ++budget_.totals.applied;
        Options diagnostics;
        diagnostics.snapshot = snapshot_;
        diagnostics.diagnostic = {DiagnosticPhase::Control, uint64_t(function_.entry_ea),
                                  int(function_.maturity), true};
        record_diagnostic(budget_.totals, diagnostics, DiagnosticStage::Commit,
                          DiagnosticOutcome::Applied);
        return 1;
    }

  private:
    bool capture_native()
    {
        const func_t *function = get_func(function_.entry_ea);
        if (!function || function->start_ea != function_.entry_ea ||
            get_func_tail_qty(function_.entry_ea) || function->end_ea <= function->start_ea ||
            function->end_ea - function->start_ea > 16384)
            return false;
        native_start_ = function->start_ea;
        native_bytes_.resize(size_t(function->end_ea - function->start_ea));
        return get_bytes(native_bytes_.data(), native_bytes_.size(), native_start_) ==
               ssize_t(native_bytes_.size());
    }
    bool source_matches() const
    {
        if (function_.mba != owner_ || budget_.snapshot != snapshot_ ||
            !same_ctree_body(source_, function_.body) ||
            !same_ctree_locals(source_locals_, *function_.get_lvars()))
            return false;
        std::vector<unsigned char> bytes(native_bytes_.size());
        return get_bytes(bytes.data(), bytes.size(), native_start_) == ssize_t(bytes.size()) &&
               bytes == native_bytes_;
    }
    Term lift(const cexpr_t &node, const ScalarContext &context) const
    {
        return lift_scalar_expression(node, context.bindings(), owner_,
                                      [&] { return available(); });
    }
    std::optional<uint64_t> constant(const cexpr_t &node, const ScalarContext &context)
    {
        const Term source = lift(node, context);
        if (!source || !available())
            return {};
        ContextQuery query(context, source);
        if (!query.valid())
            return {};
        if (replay_)
        {
            if (cursor_ >= certificates_.size())
                return {};
            const auto &certificate = certificates_[cursor_];
            if (!same_ctree_expression(certificate.source, node) ||
                !same_program(certificate.query, query.program()) || !certificate.proof ||
                certificate.proof->core().source_bits() != source->bits)
                return {};
            const Term actual =
                lift_scalar_expression(certificate.proof->emitted_snapshot(), {}, owner_);
            if (!actual || key(actual) != key(certificate.value))
                return {};
            ++cursor_;
            return certificate.value->value;
        }
        if (certificates_.size() >= max_proofs)
            return {};
        Options options;
        options.backend = budget_.backend;
        options.profile = budget_.profile;
        options.snapshot = snapshot_;
        options.absolute_deadline = deadline_;
        options.budget_ms = unsigned(std::max<int64_t>(
            0,
            std::min<int64_t>(
                budget_.profile == Profile::Deep ? 100 : 50,
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline_ - now()).count())));
        options.max_invariants = 2;
        options.cancelled = [&] { return cancelled(); };
        options.diagnostic = {DiagnosticPhase::Control, uint64_t(node.ea), int(function_.maturity),
                              true};
        auto analysis = std::make_unique<Analysis>(query.program(), options);
        const Term value = analysis->constant_value(query.block(), 0);
        std::shared_ptr<const CtreeEmissionProof> proof;
        if (value)
        {
            const auto candidate = analysis->prove_candidate(query.block(), 0, value);
            if (candidate)
            {
                cexpr_t emitted;
                emitted.put_number(&function_, value->value, int(node.type.get_size()),
                                   type_unsigned);
                emitted.type = node.type;
                emitted.ea = node.ea;
                emitted.exflags = node.exflags;
                emitted.label_num = node.label_num;
                proof = CtreeEmissionProof::prove(
                    *analysis, *candidate, emitted, [&](const cexpr_t &actual)
                    { return lift_scalar_expression(actual, {}, owner_); });
            }
        }
        if (!value || !proof || !analysis->eligible_for_commit(proof->core(), false, {}))
        {
            accumulate_statistics(budget_.totals, analysis->statistics());
            return {};
        }
        certificates_.emplace_back(node, query.program(), value, proof);
        if (last_analysis_)
            accumulate_statistics(budget_.totals, last_analysis_->statistics());
        last_analysis_ = std::move(analysis);
        last_proof_ = proof;
        return value->value;
    }
    void update(const cexpr_t &node, ScalarContext &context)
    {
        const bool writes_local = (node.op >= cot_asg && node.op <= cot_asgumod) ||
                                  node.op == cot_preinc || node.op == cot_postinc ||
                                  node.op == cot_predec || node.op == cot_postdec;
        if (writes_local && node.x && node.x->op == cot_var && node.x->v.mba == owner_ &&
            node.x->v.idx >= 0 && size_t(node.x->v.idx) < safe_.size() && safe_[node.x->v.idx])
        {
            const int local = node.x->v.idx;
            if (node.op == cot_asg && node.y)
            {
                Writes effects;
                effects.apply_to(node.y, nullptr);
                if (effects.writes)
                    context.reset();
                const Term value = lift(*node.y, context);
                context.assign(local, convert_scalar_integer(value, node.y->type, node.x->type));
                return;
            }
            if (node.op == cot_preinc || node.op == cot_postinc || node.op == cot_predec ||
                node.op == cot_postdec)
            {
                const Term previous = context.value(local);
                if (previous)
                    context.assign(
                        local,
                        expression(node.op == cot_preinc || node.op == cot_postinc ? Op::Add
                                                                                   : Op::Sub,
                                   previous, chernobog::mba_smt::constant(1, previous->bits)));
                return;
            }
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
                context.reset();
                return;
            }
            const Term value = lift(calculation, context);
            context.assign(local, convert_scalar_integer(value, node.type, node.x->type));
            return;
        }
        Writes effects;
        effects.apply_to(const_cast<cexpr_t *>(&node), nullptr);
        if (effects.writes)
            context.reset();
    }
    static void block(cinsn_t &output, ea_t ea)
    {
        output.op = cit_block;
        output.ea = ea;
        output.cblock = new cblock_t;
    }
    void emit_expression(cinsn_t &output, const cexpr_t &expression, ScalarContext &context)
    {
        if (expression.op == cot_empty)
            return;
        cinsn_t statement;
        statement.op = cit_expr;
        statement.ea = expression.ea;
        statement.cexpr = new cexpr_t(expression);
        output.cblock->push_back(statement);
        update(expression, context);
    }
    const cloop_t *loop(const cinsn_t &node) const
    {
        if (node.op == cit_for)
            return node.cfor;
        if (node.op == cit_while)
            return node.cwhile;
        return node.op == cit_do ? node.cdo : nullptr;
    }
    bool execute(Work work, ScalarContext context, cinsn_t &output, unsigned depth = 0)
    {
        if (depth > 32)
            return false;
        while (!work.empty())
        {
            if (!available() || ++steps_ > max_steps)
                return false;
            const Step step = work.back();
            work.pop_back();
            const cinsn_t &node = *step.node;
            if (step.kind == Step::Repeat)
            {
                if (node.op == cit_for)
                    emit_expression(output, node.cfor->step, context);
                work = {{Step::Test, &node, step.scope}};
                continue;
            }
            if (step.kind == Step::Test)
            {
                const cloop_t *details = loop(node);
                if (!details || !details->body)
                    return false;
                cexpr_t unconditional;
                const cexpr_t *condition = &details->expr;
                if (condition->op == cot_empty)
                {
                    unconditional.put_number(&function_, 1, 1, type_unsigned);
                    unconditional.type = tinfo_t(BTF_UINT8);
                    unconditional.ea = node.ea;
                    condition = &unconditional;
                }
                const auto value = constant(*condition, context);
                if (!value)
                    return false;
                if (*value == 0)
                    work = step.scope->after;
                else
                    work = {{Step::Repeat, &node, step.scope},
                            {Step::Statement, details->body, step.scope}};
                continue;
            }
            switch (node.op)
            {
            case cit_block:
                if (!node.cblock)
                    return false;
                for (auto i = node.cblock->rbegin(); i != node.cblock->rend(); ++i)
                    work.push_back({Step::Statement, &*i, step.scope});
                break;
            case cit_empty:
                break;
            case cit_expr:
                if (!node.cexpr)
                    return false;
                if (auto conditional = conditional_assignment(node))
                {
                    const cinsn_t *lowered = conditional.get();
                    conditional_assignments_.push_back(std::move(conditional));
                    work.push_back({Step::Statement, lowered, step.scope});
                    break;
                }
                output.cblock->push_back(node);
                update(*node.cexpr, context);
                break;
            case cit_return:
                output.cblock->push_back(node);
                return true;
            case cit_for:
            case cit_while:
            case cit_do:
            {
                if (!loop(node) || !loop(node)->body)
                    return false;
                if (node.op == cit_for)
                    emit_expression(output, node.cfor->init, context);
                auto scope = std::make_shared<Scope>();
                scope->loop = &node;
                scope->parent = step.scope;
                scope->after = work;
                work = {{Step::Test, &node, scope}};
                if (node.op == cit_do)
                    work.push_back({Step::Statement, node.cdo->body, scope});
                break;
            }
            case cit_break:
                if (!step.scope)
                    return false;
                work = step.scope->after;
                break;
            case cit_continue:
            {
                auto scope = step.scope;
                while (scope && !scope->loop)
                    scope = scope->parent;
                if (!scope)
                    return false;
                work = {{Step::Repeat, scope->loop, scope}};
                break;
            }
            case cit_switch:
            {
                if (!node.cswitch)
                    return false;
                const auto value = constant(node.cswitch->expr, context);
                if (!value)
                    return false;
                const unsigned bits = scalar_integer_bits(node.cswitch->expr.type);
                const uint64_t mask = bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1;
                const auto &cases = node.cswitch->cases;
                size_t selected = cases.size(), fallback = cases.size();
                for (size_t i = 0; i < cases.size(); ++i)
                {
                    if (cases[i].values.empty())
                        fallback = i;
                    for (const uint64 case_value : cases[i].values)
                        if ((case_value & mask) == (*value & mask))
                        {
                            if (selected != cases.size())
                                return false;
                            selected = i;
                        }
                }
                if (selected == cases.size())
                    selected = fallback;
                if (selected == cases.size())
                    break;
                auto scope = std::make_shared<Scope>();
                scope->parent = step.scope;
                scope->after = work;
                for (size_t i = cases.size(); i-- > selected;)
                    work.push_back({Step::Statement, &cases[i], scope});
                break;
            }
            case cit_if:
            {
                if (!node.cif || !node.cif->ithen)
                    return false;
                const auto value = constant(node.cif->expr, context);
                if (value)
                {
                    const cinsn_t *selected = *value ? node.cif->ithen : node.cif->ielse;
                    if (selected)
                        work.push_back({Step::Statement, selected, step.scope});
                    break;
                }
                if (!available() || ++forks_ > max_forks)
                    return false;
                Writes effects;
                effects.apply_to(const_cast<cexpr_t *>(&node.cif->expr), nullptr);
                if (effects.writes)
                    return false;
                const Term condition = lift(node.cif->expr, context);
                ScalarContext then_context(context), else_context(context);
                if (condition)
                {
                    then_context.assume(condition, true);
                    else_context.assume(condition, false);
                }
                cinsn_t then_body, else_body;
                block(then_body, node.cif->ithen->ea);
                block(else_body, node.cif->ielse ? node.cif->ielse->ea : node.ea);
                Work then_work(work), else_work(work);
                then_work.push_back({Step::Statement, node.cif->ithen, step.scope});
                if (node.cif->ielse)
                    else_work.push_back({Step::Statement, node.cif->ielse, step.scope});
                if (!execute(std::move(then_work), std::move(then_context), then_body, depth + 1) ||
                    !execute(std::move(else_work), std::move(else_context), else_body, depth + 1))
                    return false;
                if (then_body.cblock->empty())
                    then_body.new_insn(then_body.ea);
                if (else_body.cblock->empty())
                    else_body.new_insn(else_body.ea);
                cinsn_t branch(node);
                delete branch.cif->ithen;
                delete branch.cif->ielse;
                branch.cif->ithen = new cinsn_t(then_body);
                branch.cif->ielse = new cinsn_t(else_body);
                output.cblock->push_back(branch);
                return true;
            }
            default:
                return false;
            }
            Inventory inventory;
            if (inventory.apply_to(&output, nullptr) ||
                inventory.nodes > std::min(max_nodes, 2 * original_nodes_ + 64))
                return false;
        }
        return true;
    }
    std::unique_ptr<cinsn_t> conditional_assignment(const cinsn_t &node)
    {
        const cexpr_t &assignment = *node.cexpr;
        if (conditional_assignments_.size() >= 2 * max_steps || assignment.op != cot_asg ||
            !assignment.x || assignment.x->op != cot_var || assignment.x->v.mba != owner_ ||
            assignment.x->v.idx < 0 || size_t(assignment.x->v.idx) >= safe_.size() ||
            !safe_[assignment.x->v.idx] || !assignment.y || assignment.y->op != cot_tern ||
            !assignment.y->x || !assignment.y->y || !assignment.y->z ||
            !scalar_integer_bits(assignment.y->type))
            return {};
        const cexpr_t &value = *assignment.y;
        auto branch = std::make_unique<cinsn_t>();
        branch->op = cit_if;
        branch->ea = node.ea;
        branch->cif = new cif_t;
        branch->cif->expr = *value.x;
        const auto arm = [&](const cexpr_t &selected)
        {
            auto output = std::make_unique<cinsn_t>(node);
            cexpr_t converted(selected);
            // Preserve the ternary's common type before the assignment's own
            // conversion; directly assigning the narrow arm could sign-extend
            // a value that the original conditional expression zero-extended.
            if (selected.type != value.type)
            {
                cexpr_t cast(cot_cast, new cexpr_t(selected));
                cast.type = value.type;
                cast.ea = value.ea;
                converted.swap(cast);
            }
            output->cexpr->y->swap(converted);
            return output;
        };
        branch->cif->ithen = arm(*value.y).release();
        branch->cif->ielse = arm(*value.z).release();
        return branch;
    }
    void eliminate_dead(cinsn_t &body, lvars_t &locals)
    {
        // Read dependencies of pure private definitions are followed only when
        // their target is live. Observable reads/calls and unsafe writes remain.
        ScalarContext::Bindings inputs;
        for (size_t i = 0; i < widths_.size(); ++i)
            if (widths_[i])
                inputs[int(i)] = variable(i, widths_[i]);
        std::map<int, std::set<int>> dependencies;
        std::set<int> live;
        std::vector<std::pair<cinsn_t *, int>> definitions;
        const auto variables_in = [&](const cexpr_t &expression)
        {
            struct Variables : ctree_visitor_t
            {
                std::set<int> indices;
                Variables() : ctree_visitor_t(CV_FAST) {}
                int idaapi visit_expr(cexpr_t *node) override
                {
                    if (node->op == cot_var)
                        indices.insert(node->v.idx);
                    return 0;
                }
            } variables;
            variables.apply_to(const_cast<cexpr_t *>(&expression), nullptr);
            return variables.indices;
        };
        const auto inspect = [&](const auto &self, cinsn_t &node) -> void
        {
            if (node.op == cit_block)
            {
                for (auto &child : *node.cblock)
                    self(self, child);
                return;
            }
            if (node.op == cit_if)
            {
                const auto used = variables_in(node.cif->expr);
                live.insert(used.begin(), used.end());
                self(self, *node.cif->ithen);
                if (node.cif->ielse)
                    self(self, *node.cif->ielse);
                return;
            }
            cexpr_t *expression = node.op == cit_expr     ? node.cexpr
                                  : node.op == cit_return ? &node.creturn->expr
                                                          : nullptr;
            if (!expression)
                return;
            const bool definition = (expression->op >= cot_asg && expression->op <= cot_asgumod) ||
                                    expression->op == cot_preinc || expression->op == cot_postinc ||
                                    expression->op == cot_predec || expression->op == cot_postdec;
            if (node.op == cit_expr && definition && expression->x &&
                expression->x->op == cot_var && expression->x->v.mba == owner_ &&
                expression->x->v.idx >= 0 && size_t(expression->x->v.idx) < safe_.size() &&
                safe_[expression->x->v.idx])
            {
                const int target = expression->x->v.idx;
                cexpr_t calculation(*expression);
                const cexpr_t *rhs = &calculation;
                if (expression->op == cot_asg)
                    rhs = expression->y;
                else if (expression->op == cot_asgadd)
                    calculation.op = cot_add;
                else if (expression->op == cot_asgsub)
                    calculation.op = cot_sub;
                else if (expression->op == cot_asgmul)
                    calculation.op = cot_mul;
                else if (expression->op == cot_asgband)
                    calculation.op = cot_band;
                else if (expression->op == cot_asgbor)
                    calculation.op = cot_bor;
                else if (expression->op == cot_asgxor)
                    calculation.op = cot_xor;
                else if (expression->op == cot_preinc || expression->op == cot_postinc ||
                         expression->op == cot_predec || expression->op == cot_postdec)
                    rhs = expression->x;
                else
                    rhs = nullptr;
                if (rhs && lift_scalar_expression(*rhs, inputs, owner_))
                {
                    const auto used = variables_in(*rhs);
                    dependencies[target].insert(used.begin(), used.end());
                    definitions.emplace_back(&node, target);
                    return;
                }
            }
            const auto used = variables_in(*expression);
            live.insert(used.begin(), used.end());
        };
        inspect(inspect, body);
        for (size_t round = 0; round < safe_.size(); ++round)
        {
            const size_t before = live.size();
            for (const auto &entry : dependencies)
                if (live.count(entry.first))
                    live.insert(entry.second.begin(), entry.second.end());
            if (before == live.size())
                break;
        }
        for (const auto &definition : definitions)
            if (!live.count(definition.second))
            {
                definition.first->cleanup();
                definition.first->op = cit_empty;
                if (!locals[definition.second].is_arg_var())
                    locals[definition.second].clear_used();
            }
    }
    bool generate(cinsn_t &output, lvars_t &locals, bool replay)
    {
        replay_ = replay;
        cursor_ = steps_ = forks_ = 0;
        block(output, source_.ea);
        output.label_num = source_.label_num;
        ScalarContext context(widths_);
        if (!execute({{Step::Statement, &source_, {}}}, std::move(context), output))
            return false;
        if (replay && cursor_ != certificates_.size())
            return false;
        eliminate_dead(output, locals);
        if (output.cblock->empty())
            output.new_insn(output.ea);
        Inventory inventory;
        return !inventory.apply_to(&output, nullptr) && inventory.controls == 0 &&
               inventory.nodes <= std::min(max_nodes, 2 * original_nodes_ + 64) && available();
    }
    cfunc_t &function_;
    FunctionBudget &budget_;
    const ControlFlowTestHooks *tests_;
    mba_t *owner_;
    cinsn_t source_;
    lvars_t source_locals_;
    SnapshotToken snapshot_;
    Clock::time_point deadline_;
    size_t original_nodes_;
    std::vector<bool> safe_;
    std::vector<unsigned> widths_;
    ea_t native_start_ = BADADDR;
    std::vector<unsigned char> native_bytes_;
    std::vector<Certificate> certificates_;
    std::vector<std::unique_ptr<cinsn_t>> conditional_assignments_;
    std::unique_ptr<Analysis> last_analysis_;
    std::shared_ptr<const CtreeEmissionProof> last_proof_;
    size_t cursor_ = 0, steps_ = 0, forks_ = 0;
    bool replay_ = false;
};
}
int simplify_bounded_control_flow(cfunc_t &function, FunctionBudget &budget,
                                  const ControlFlowTestHooks *tests)
{
    const auto now = [&] { return tests && tests->now ? tests->now() : Clock::now(); };
    const auto started = now();
    struct Charge
    {
        FunctionBudget &budget;
        const std::function<Clock::time_point()> now;
        Clock::time_point started;
        ~Charge()
        {
            budget.spent_ns += uint64_t(std::max<int64_t>(
                0, std::chrono::duration_cast<std::chrono::nanoseconds>(now() - started).count()));
        }
    } charge{budget, now, started};
    try
    {
        if (!function.mba || !function.get_lvars() ||
            function.get_lvars()->size() > limits::storage_regions)
            return 0;
        Inventory inventory;
        if (inventory.apply_to(&function.body, nullptr) || !inventory.controls)
            return 0;
        const uint64_t allowance = uint64_t(budget.limit_ms) * 1000000;
        const uint64_t remaining = allowance > budget.spent_ns ? allowance - budget.spent_ns : 0;
        const uint64_t pass_limit = budget.profile == Profile::Deep ? 1000000000 : 250000000;
        const auto deadline = started + std::chrono::nanoseconds(std::min(remaining, pass_limit));
        return Control(function, budget, tests, started, deadline, inventory.nodes).run();
    }
    catch (...)
    {
        return 0;
    }
}
}
