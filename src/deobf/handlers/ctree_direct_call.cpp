#include "ctree_direct_call.h"

namespace
{

// A statically known callable address is either a function or an imported
// symbol. Everything else is data that merely holds an address, and calling
// through it stays an indirect call.
bool is_callable_object(ea_t address)
{
    const segment_t *segment = getseg(address);
    if (segment == nullptr)
        return false;
    if (segment->type == SEG_XTRN)
        return true;
    return is_func(get_flags(address));
}

struct direct_call_visitor_t final : public ctree_visitor_t
{
    int changes = 0;

    direct_call_visitor_t() : ctree_visitor_t(CV_FAST) {}

    int idaapi visit_expr(cexpr_t *expression) override
    {
        if (expression == nullptr || expression->op != cot_call)
            return 0;
        cexpr_t *callee = expression->x;
        if (callee == nullptr || callee->op != cot_cast)
            return 0;
        cexpr_t *object = callee->x;
        if (object == nullptr || object->op != cot_obj)
            return 0;
        if (!callee->type.is_funcptr())
            return 0;
        if (!is_callable_object(object->obj_ea))
            return 0;

        const ea_t target = object->obj_ea;
        const ea_t ea = callee->ea;
        const tinfo_t prototype = callee->type;

        cexpr_t *replacement = new cexpr_t;
        replacement->op = cot_obj;
        replacement->obj_ea = target;
        replacement->type = prototype;
        replacement->ea = ea;

        // replace_by() abandons children and consumes the replacement, so
        // release the cast first and keep the target in plain locals.
        callee->cleanup();
        callee->replace_by(replacement);
        ++changes;
        deobf::log_verbose("[ctree_direct_call] direct call to %a at %a\n", target, ea);
        return 0;
    }
};

} // namespace

//--------------------------------------------------------------------------
// Main entry point
//--------------------------------------------------------------------------
int ctree_direct_call_handler_t::run(cfunc_t *cfunc)
{
    if (cfunc == nullptr)
        return 0;

    deobf::log_verbose("[ctree_direct_call] Running on %a\n", cfunc->entry_ea);

    direct_call_visitor_t visitor;
    visitor.apply_to(&cfunc->body, nullptr);
    if (visitor.changes == 0)
        return 0;

    deobf::log("[ctree_direct_call] Rendered %d casted calls as direct calls\n", visitor.changes);
    cfunc->verify(ALLOW_UNUSED_LABELS, false);
    return visitor.changes;
}
