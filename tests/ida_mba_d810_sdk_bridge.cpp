#include "common/hexrays_handshake.hpp"
#include "chernobog/build_provenance.hpp"
#include "deobf/handlers/mba_smt_memory.h"
#include "deobf/handlers/mba_smt_control.h"
#include "deobf/handlers/mba_smt_ctree.h"
#include "deobf/handlers/mba_smt_emission.hpp"
#include "deobf/analysis/mba_smt_internal.hpp"
#include <cstring>

using namespace chernobog::mba_smt;
namespace
{
struct Reads : ctree_visitor_t
{
    std::vector<cexpr_t *> values;
    Reads() : ctree_visitor_t(CV_FAST) {}
    int idaapi visit_expr(cexpr_t *node) override
    {
        if (node->op == cot_ptr || node->op == cot_idx)
            values.push_back(node);
        return 0;
    }
};

}
#ifdef _WIN32
#define D810_EXPORT __declspec(dllexport)
#else
#define D810_EXPORT __attribute__((visibility("default")))
#endif
extern "C" D810_EXPORT int chernobog_mba_d810_memory_probe(uint64_t ea, int fault, char *buffer,
                                                           size_t capacity)
{
    try
    {
        if (!chernobog::hexrays::handshake() || fault < 0 || fault > 22)
            return -1;
        hexrays_failure_t failure;
        auto function = decompile(ea, &failure, DECOMP_NO_CACHE);
        if (!function)
            return -2;
        if (fault >= 16 && fault <= 19)
        {
            Reads source_reads;
            source_reads.apply_to(&function->body, nullptr);
            if (source_reads.values.size() < 2)
                return -4;
            if (fault == 16)
                source_reads.values[0]->type.set_volatile();
            if (fault == 17)
                source_reads.values[0]->ea = source_reads.values[1]->ea;
            if (fault == 18)
                source_reads.values[0]->type = tinfo_t(BTF_UINT16);
            if (fault == 19)
            {
                cinsn_t call;
                call.op = cit_expr;
                call.ea = function->entry_ea;
                call.cexpr = new cexpr_t;
                call.cexpr->op = cot_call;
                call.cexpr->type = tinfo_t(BTF_UINT32);
                call.cexpr->x = new cexpr_t;
                call.cexpr->x->op = cot_helper;
                call.cexpr->x->helper = qstrdup("unknown_memory_effect");
                call.cexpr->a = new carglist_t;
                function->body.cblock->push_front(call);
            }
        }
        cinsn_t original(function->body);
        const lvars_t original_locals(*function->get_lvars());
        FunctionBudget budget;
        budget.backend = Backend::Cobra;
        budget.limit_ms = 100;
        budget.snapshot = {53, 0};
        auto time = std::chrono::steady_clock::now();
        bool cancelled = false, visited = false, post_poll = false;
        size_t emitted_queries = 0;
        static std::map<uint64_t, size_t> expected_queries;
        detail::SessionTestHooks session;
        session.now = [&] { return time; };
        session.after_query = [&](const char *purpose, const z3::check_result &result)
        {
            if (result != z3::unsat || !std::strstr(purpose, "emitted replacement"))
                return;
            ++emitted_queries;
            if ((fault == 14 || fault == 15) && emitted_queries == expected_queries[ea])
            {
                post_poll = true;
                if (fault == 14)
                    cancelled = true;
                else
                    time += std::chrono::milliseconds(150);
            }
        };
        struct Restore
        {
            detail::SessionTestHooks *old;
            ~Restore() { detail::session_test_hooks = old; }
        } restore{detail::session_test_hooks};
        detail::session_test_hooks = &session;
        MemorySliceTestHooks hooks;
        hooks.now = [&] { return time; };
        hooks.cancelled = [&] { return cancelled; };
        hooks.before_snapshot = [&]
        {
            if (fault == 22)
                time += std::chrono::milliseconds(150);
        };
        hooks.before_commit = [&](cinsn_t &staged, lvars_t &locals)
        {
            visited = true;
            if (fault == 0)
                return;
            auto first = staged.cblock->begin();
            auto second = first;
            ++second;
            if (fault == 1)
                first->cexpr->x->v.idx++;
            if (fault == 2)
                first->cexpr->y->ea++;
            if (fault == 3)
                first->cexpr->y->type = tinfo_t(BTF_UINT16);
            if (fault == 4)
                first->cexpr->y->x->v.idx++;
            if (fault == 5)
                first->swap(*second);
            if (fault == 6)
                staged.cblock->erase(first);
            if (fault == 7)
                staged.cblock->push_front(*first);
            if (fault == 8)
                locals.back().tif = tinfo_t(BTF_UINT16);
            if (fault == 9)
                locals.back().location.set_reg1(mr_first + 1);
            if (fault == 10)
                staged.label_num = 0;
            if (fault == 11)
                ++budget.snapshot.generation;
            if (fault == 12)
                cancelled = true;
            if (fault == 13)
                time += std::chrono::milliseconds(150);
            if (fault == 20)
                first->cexpr->exflags ^= 1;
            if (fault == 21)
                locals.back().set_used_byref();
        };
        const int changes = simplify_memory_values(*function, budget, &hooks);
        if (fault == 0)
            expected_queries[ea] = emitted_queries;
        const bool unchanged = same_ctree_body(original, function->body) &&
                               same_ctree_locals(original_locals, *function->get_lvars());
        const bool expected_apply = fault == 0;
        bool passed = expected_apply
                          ? changes > 0 && visited && !unchanged
                          : changes == 0 && unchanged &&
                                (fault == 14 || fault == 15                    ? post_poll
                                 : (fault >= 16 && fault <= 19) || fault == 22 ? !visited
                                                                               : visited);
        if (expected_apply)
            function->verify(ALLOW_UNUSED_LABELS, true);
        qsnprintf(
            buffer, capacity,
            "{\"fault\":%d,\"passed\":%s,\"changes\":%d,\"unchanged\":%s,\"visited\":%s,\"post_poll\":%s}",
            fault, passed ? "true" : "false", changes, unchanged ? "true" : "false",
            visited ? "true" : "false", post_poll ? "true" : "false");
        return passed ? 0 : 1;
    }
    catch (...)
    {
        qsnprintf(buffer, capacity, "{\"passed\":false,\"exception\":true}");
        return -3;
    }
}

extern "C" D810_EXPORT int chernobog_mba_d810_control_probe(uint64_t ea, int fault, char *buffer,
                                                            size_t capacity)
{
    try
    {
        if (!chernobog::hexrays::handshake() || fault < -1 || fault > 17)
            return -1;
        hexrays_failure_t failure;
        auto function = decompile(ea, &failure, DECOMP_NO_CACHE);
        if (!function)
            return -2;
        if (fault == 16 || fault == 17)
            for (auto &local : *function->get_lvars())
                if (!local.is_arg_var())
                {
                    if (fault == 16)
                        local.tif.set_volatile();
                    else
                        local.set_used_byref();
                }
        const cinsn_t original(function->body);
        const lvars_t original_locals(*function->get_lvars());
        FunctionBudget budget;
        budget.backend = Backend::Cobra;
        budget.limit_ms = 100;
        budget.snapshot = {71, 0};
        auto time = std::chrono::steady_clock::now();
        bool cancelled = false, visited = false, post_poll = false;
        size_t emitted_queries = 0;
        static std::map<uint64_t, size_t> expected_queries;
        detail::SessionTestHooks session;
        session.now = [&] { return time; };
        session.after_query = [&](const char *purpose, const z3::check_result &result)
        {
            if (result != z3::unsat || !std::strstr(purpose, "emitted replacement"))
                return;
            ++emitted_queries;
            if ((fault == 14 || fault == 15) && emitted_queries == expected_queries[ea])
            {
                post_poll = true;
                if (fault == 14)
                    cancelled = true;
                else
                    time += std::chrono::milliseconds(150);
            }
        };
        struct Restore
        {
            detail::SessionTestHooks *old;
            ~Restore() { detail::session_test_hooks = old; }
        } restore{detail::session_test_hooks};
        detail::session_test_hooks = &session;
        ControlFlowTestHooks hooks;
        hooks.now = [&] { return time; };
        hooks.cancelled = [&] { return cancelled; };
        hooks.before_commit = [&](cinsn_t &staged, lvars_t &locals)
        {
            visited = true;
            auto first = staged.cblock->begin();
            if (fault == 1)
                staged.ea++;
            if (fault == 2 || fault == 9)
                staged.cblock->push_back(*first);
            if (fault == 3)
                first->ea++;
            if (fault == 4)
                staged.cblock->erase(first);
            if (fault == 5)
            {
                struct Variable : ctree_visitor_t
                {
                    Variable() : ctree_visitor_t(CV_FAST) {}
                    int idaapi visit_expr(cexpr_t *node) override
                    {
                        if (node->op != cot_var)
                            return 0;
                        node->v.idx++;
                        return 1;
                    }
                } variable;
                variable.apply_to(&staged, nullptr);
            }
            if (fault == 6)
                locals.back().tif = tinfo_t(BTF_UINT16);
            if (fault == 7)
                locals.back().set_used_byref();
            if (fault == 8)
                locals.back().location.set_reg1(mr_first + 1);
            if (fault == 10)
                staged.label_num = 4;
            if (fault == 11)
                ++budget.snapshot.generation;
            if (fault == 12)
                cancelled = true;
            if (fault == 13)
                time += std::chrono::milliseconds(150);
        };
        const int changes = simplify_bounded_control_flow(*function, budget, &hooks);
        const bool unchanged = same_ctree_body(original, function->body) &&
                               same_ctree_locals(original_locals, *function->get_lvars());
        if (fault == 0)
            expected_queries[ea] = emitted_queries;
        const bool expected_apply = fault == 0;
        const bool passed = expected_apply ? changes == 1 && visited && !unchanged
                                           : changes == 0 && unchanged &&
                                                 (fault == 14 || fault == 15   ? post_poll
                                                  : fault >= 16 || fault == -1 ? !visited
                                                                               : visited);
        if (expected_apply)
            function->verify(ALLOW_UNUSED_LABELS, true);
        qsnprintf(
            buffer, capacity,
            "{\"fault\":%d,\"passed\":%s,\"changes\":%d,\"unchanged\":%s,\"queries\":%zu,\"post_poll\":%s}",
            fault, passed ? "true" : "false", changes, unchanged ? "true" : "false",
            emitted_queries, post_poll ? "true" : "false");
        return passed ? 0 : 1;
    }
    catch (...)
    {
        qsnprintf(buffer, capacity, "{\"passed\":false,\"exception\":true}");
        return -3;
    }
}

extern "C" D810_EXPORT int chernobog_mba_d810_literal_probe(uint64_t ea, uint32_t literal,
                                                            char *buffer, size_t capacity)
{
    try
    {
        if (!chernobog::hexrays::handshake())
            return -1;
        hexrays_failure_t failure;
        auto function = decompile(ea, &failure, DECOMP_NO_CACHE);
        if (!function)
            return -2;
        const Term value = expression(Op::SignExtend, constant(literal, 32), {}, 64);
        Program program;
        program.widths = {64};
        program.blocks.resize(1);
        program.blocks[0].statements.push_back(Statement::assign(0, value));
        Analysis analysis(program, Options::deep());
        const auto candidate = analysis.prove_candidate(0, 0, value);
        ScalarContext context({});
        cexpr_t emitted;
        if (!candidate ||
            !emit_scalar_expression(*function, context, value,
                                    get_int_type_by_width_and_sign(8, type_unsigned), emitted))
            return -3;
        const auto proof = CtreeEmissionProof::prove(
            analysis, *candidate, emitted, [&](const cexpr_t &actual)
            { return lift_scalar_expression(actual, {}, function->mba); });
        if (!proof)
            return -4;
        qstring text;
        emitted.print1(&text, function);
        qstrncpy(buffer, text.c_str(), capacity);
        return 0;
    }
    catch (...)
    {
        return -5;
    }
}

extern "C" D810_EXPORT const char *chernobog_mba_d810_revision()
{
    return chernobog::build_provenance::revision;
}
extern "C" D810_EXPORT const char *chernobog_mba_d810_source_fingerprint()
{
    return chernobog::build_provenance::source_fingerprint;
}
