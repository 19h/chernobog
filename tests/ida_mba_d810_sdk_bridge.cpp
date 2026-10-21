#include "common/hexrays_handshake.hpp"
#include "deobf/handlers/mba_smt_memory.h"
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
        if (!chernobog::hexrays::handshake() || fault < 0 || fault > 21)
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
        detail::SessionTestHooks session;
        session.now = [&] { return time; };
        session.after_query = [&](const char *purpose, const z3::check_result &result)
        {
            if ((fault == 14 || fault == 15) && result == z3::unsat &&
                std::strstr(purpose, "emitted replacement"))
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
        const bool unchanged = same_ctree_body(original, function->body) &&
                               same_ctree_locals(original_locals, *function->get_lvars());
        const bool expected_apply = fault == 0;
        bool passed = expected_apply ? changes > 0 && visited && !unchanged
                                     : changes == 0 && unchanged &&
                                           (fault == 14 || fault == 15   ? post_poll
                                            : fault >= 16 && fault <= 19 ? !visited
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
