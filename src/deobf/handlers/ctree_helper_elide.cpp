#include "ctree_helper_elide.h"

#include "../../common/arm64e.h"

namespace
{

bool is_constant_argument(const cexpr_t *expression)
{
    while (expression != nullptr && expression->op == cot_cast)
        expression = expression->x;
    if (expression == nullptr)
        return false;
    return expression->op == cot_num || expression->op == cot_obj || expression->op == cot_str;
}

struct helper_statement_visitor_t final : public ctree_visitor_t
{
    int changes = 0;

    helper_statement_visitor_t() : ctree_visitor_t(CV_INSNS) {}

    int idaapi visit_insn(cinsn_t *instruction) override
    {
        if (instruction == nullptr || instruction->op != cit_expr || instruction->label_num >= 0 ||
            instruction->cexpr == nullptr)
        {
            return 0;
        }
        const cexpr_t *call = instruction->cexpr;
        while (call->op == cot_cast)
            call = call->x;
        if (call == nullptr || call->op != cot_call || call->x == nullptr ||
            call->x->op != cot_helper)
        {
            return 0;
        }
        if (!chernobog::arm64e::helper_instruction(call->x->helper))
            return 0;
        if (call->a == nullptr)
            return 0;
        for (const carg_t &argument : *call->a)
            if (!is_constant_argument(&argument))
                return 0;
        instruction->cleanup();
        ++changes;
        return 0;
    }
};

struct empty_statement_visitor_t final : public ctree_visitor_t
{
    empty_statement_visitor_t() : ctree_visitor_t(CV_POST) {}

    int idaapi leave_insn(cinsn_t *instruction) override
    {
        if (instruction == nullptr || instruction->op != cit_block ||
            instruction->cblock == nullptr)
        {
            return 0;
        }
        for (auto iterator = instruction->cblock->begin(); iterator != instruction->cblock->end();)
        {
            if (iterator->op == cit_empty && iterator->label_num == -1)
                iterator = instruction->cblock->erase(iterator);
            else
                ++iterator;
        }
        if (instruction->cblock->empty())
            instruction->new_insn(instruction->ea);
        return 0;
    }
};

} // namespace

//--------------------------------------------------------------------------
// Main entry point
//--------------------------------------------------------------------------
int ctree_helper_elide_handler_t::run(cfunc_t *cfunc)
{
    if (cfunc == nullptr)
        return 0;

    deobf::log_verbose("[ctree_helper_elide] Running on %a\n", cfunc->entry_ea);

    helper_statement_visitor_t visitor;
    visitor.apply_to(&cfunc->body, nullptr);
    if (visitor.changes == 0)
        return 0;

    empty_statement_visitor_t empty_remover;
    empty_remover.apply_to(&cfunc->body, nullptr);

    deobf::log("[ctree_helper_elide] Removed %d constant ARM64e helper statements\n",
               visitor.changes);
    cfunc->verify(ALLOW_UNUSED_LABELS, false);
    return visitor.changes;
}
