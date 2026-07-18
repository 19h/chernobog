#include "ctree_const_fold.h"
#include "../../common/ida_memory.h"

#include <vector>

namespace {

struct lvar_usage_t
{
    int reads = 0;
    int writes = 0;
    bool address_taken = false;
};

struct lvar_usage_visitor_t final : public ctree_visitor_t
{
    std::vector<lvar_usage_t> usage;

    explicit lvar_usage_visitor_t(size_t count)
        : ctree_visitor_t(CV_PARENTS), usage(count)
    {
    }

    int idaapi visit_expr(cexpr_t *expression) override
    {
        if ( expression == nullptr || expression->op != cot_var
          || expression->v.idx >= usage.size() )
        {
            return 0;
        }

        lvar_usage_t &entry = usage[expression->v.idx];
        cexpr_t *parent = parent_expr();
        if ( parent != nullptr && parent->op == cot_asg
          && parent->x == expression )
        {
            ++entry.writes;
        }
        else
        {
            ++entry.reads;
        }
        if ( parent != nullptr && parent->op == cot_ref )
            entry.address_taken = true;
        return 0;
    }
};

bool is_discardable_rhs(const cexpr_t *expression)
{
    if ( expression == nullptr || expression->type.is_volatile()
      || expression->has_side_effects() )
    {
        return false;
    }

    switch ( expression->op )
    {
        case cot_num:
        case cot_fnum:
        case cot_str:
        case cot_obj:
        case cot_var:
        case cot_helper:
            return true;

        case cot_cast:
        case cot_ref:
        case cot_neg:
        case cot_bnot:
        case cot_lnot:
            return is_discardable_rhs(expression->x);

        case cot_add:
        case cot_sub:
        case cot_mul:
        case cot_fadd:
        case cot_fsub:
        case cot_fmul:
        case cot_bor:
        case cot_xor:
        case cot_band:
        case cot_shl:
        case cot_sshr:
        case cot_ushr:
        case cot_eq:
        case cot_ne:
        case cot_sge:
        case cot_uge:
        case cot_sle:
        case cot_ule:
        case cot_sgt:
        case cot_ugt:
        case cot_slt:
        case cot_ult:
        case cot_land:
        case cot_lor:
            return is_discardable_rhs(expression->x)
                && is_discardable_rhs(expression->y);

        default:
            // Calls, pointer/member loads, comma/ternary expressions,
            // assignments, increments, and potentially trapping div/mod
            // expressions are deliberately retained.
            return false;
    }
}

struct dead_assignment_visitor_t final : public ctree_visitor_t
{
    cfunc_t *function;
    const std::vector<lvar_usage_t> &usage;
    std::vector<int> removed_by_variable;
    int changes = 0;

    dead_assignment_visitor_t(cfunc_t *function,
        const std::vector<lvar_usage_t> &usage)
        : ctree_visitor_t(CV_PARENTS), function(function), usage(usage),
          removed_by_variable(usage.size(), 0)
    {
    }

    int idaapi visit_insn(cinsn_t *instruction) override
    {
        if ( instruction == nullptr || instruction->op != cit_expr
          || instruction->label_num != -1
          || instruction->cexpr == nullptr
          || instruction->cexpr->op != cot_asg
          || instruction->cexpr->x == nullptr
          || instruction->cexpr->x->op != cot_var
          || instruction->cexpr->y == nullptr )
        {
            return 0;
        }

        const int index = instruction->cexpr->x->v.idx;
        lvars_t *variables = function->get_lvars();
        if ( index < 0 || variables == nullptr
          || static_cast<size_t>(index) >= variables->size()
          || static_cast<size_t>(index) >= usage.size() )
        {
            return 0;
        }

        const lvar_usage_t &entry = usage[index];
        const lvar_t &variable = (*variables)[index];
        if ( entry.reads != 0 || entry.address_taken
          || variable.is_arg_var() || variable.is_result_var()
          || variable.is_fake_var() || variable.is_used_byref()
          || variable.is_overlapped_var() || variable.is_mapdst_var()
          || variable.is_shared() || variable.is_noprop()
          || variable.in_asm() || variable.has_user_info()
          || !variable.tif.is_scalar() || variable.tif.is_volatile()
          || !is_discardable_rhs(instruction->cexpr->y) )
        {
            return 0;
        }

        instruction->cleanup();
        ++removed_by_variable[index];
        ++changes;
        return 0;
    }
};

struct empty_statement_visitor_t final : public ctree_visitor_t
{
    empty_statement_visitor_t() : ctree_visitor_t(CV_POST) {}

    int idaapi leave_insn(cinsn_t *instruction) override
    {
        if ( instruction == nullptr || instruction->op != cit_block
          || instruction->cblock == nullptr )
        {
            return 0;
        }
        for ( auto iterator = instruction->cblock->begin();
              iterator != instruction->cblock->end(); )
        {
            if ( iterator->op == cit_empty && iterator->label_num == -1 )
                iterator = instruction->cblock->erase(iterator);
            else
                ++iterator;
        }
        return 0;
    }
};

int remove_write_only_local_assignments(cfunc_t *function)
{
    lvars_t *variables = function != nullptr ? function->get_lvars() : nullptr;
    if ( function == nullptr || variables == nullptr || variables->empty() )
        return 0;

    lvar_usage_visitor_t usage(variables->size());
    usage.apply_to(&function->body, nullptr);

    dead_assignment_visitor_t remover(function, usage.usage);
    remover.apply_to(&function->body, nullptr);

    empty_statement_visitor_t empty_remover;
    empty_remover.apply_to(&function->body, nullptr);

    for ( size_t index = 0; index < variables->size(); ++index )
    {
        if ( usage.usage[index].reads == 0
          && remover.removed_by_variable[index] == usage.usage[index].writes )
        {
            (*variables)[index].clear_used();
        }
    }
    return remover.changes;
}

} // namespace

//--------------------------------------------------------------------------
// Ctree visitor that folds XOR with global constants
//--------------------------------------------------------------------------
struct const_fold_visitor_t : public ctree_visitor_t {
    int changes = 0;
    cfunc_t *func = nullptr;

    const_fold_visitor_t(cfunc_t *f) : ctree_visitor_t(CV_PARENTS), func(f) {}

    int idaapi visit_expr(cexpr_t *e) override {
        // Look for XOR expressions
        if ( e->op != cot_xor ) 
            return 0;

        // Need both operands
        if ( !e->x || !e->y ) 
            return 0;

        // One operand must be a number constant
        if ( e->x->op != cot_num && e->y->op != cot_num ) 
            return 0;

        cexpr_t *val_expr = (e->y->op == cot_num) ? e->x : e->y;
        cexpr_t *num_expr = (e->y->op == cot_num) ? e->y : e->x;

        // Try to get a global address from the value expression
        ea_t obj_addr = BADADDR;

        // Case 1: Direct object reference (cot_obj)
        if ( val_expr->op == cot_obj ) {
            obj_addr = val_expr->obj_ea;
        }
        // Case 2: Pointer dereference (cot_ptr) - check if dereferencing a constant
        else if ( val_expr->op == cot_ptr && val_expr->x ) {
            if ( val_expr->x->op == cot_num ) {
                obj_addr = (ea_t)val_expr->x->numval();
            } else if ( val_expr->x->op == cot_cast && val_expr->x->x ) {
                // A casted numeric address is direct. A cot_obj here holds a
                // pointer value and would require an additional load.
                if ( val_expr->x->x->op == cot_num ) {
                    obj_addr = (ea_t)val_expr->x->x->numval();
                }
            }
        }

        if ( obj_addr == BADADDR ) 
            return 0;

        // Check if the address is in a valid segment
        segment_t *seg = getseg(obj_addr);
        if ( !seg || (seg->perm & SEGPERM_WRITE) != 0 )
            return 0;

        if ( !is_loaded(obj_addr) ) 
            return 0;

        // Read the value based on size
        int size = val_expr->type.get_size();
        if ( size <= 0 || size > 8 ) 
            return 0;

        auto object_value = chernobog::ida_memory::read_integer(obj_addr, size);
        if ( !object_value )
            return 0;
        const uint64_t obj_val = *object_value;

        // Get the constant
        uint64_t const_val = num_expr->numval();

        // Compute the XOR
        uint64_t result = obj_val ^ const_val;
        if ( size < 8 )
            result &= (uint64_t{1} << static_cast<unsigned>(size * 8)) - 1;

        deobf::log("[ctree_const_fold] Folding %a ^ 0x%llx = 0x%llx\n",
                   obj_addr, (unsigned long long)const_val,
                   (unsigned long long)result);

        e->put_number(func, result, size, no_sign);

        changes++;
        return 0;
    }
};

//--------------------------------------------------------------------------
// Main entry point
//--------------------------------------------------------------------------
int ctree_const_fold_handler_t::run(cfunc_t *cfunc)
{
    if ( !cfunc ) 
        return 0;

    deobf::log_verbose("[ctree_const_fold] Running on %a\n", cfunc->entry_ea);

    const_fold_visitor_t visitor(cfunc);
    visitor.apply_to(&cfunc->body, nullptr);

    const int dead_assignments = remove_write_only_local_assignments(cfunc);
    const int total_changes = visitor.changes + dead_assignments;

    if ( total_changes > 0 ) {
        deobf::log(
            "[ctree_const_fold] Folded %d constants and removed %d "
            "write-only local assignments\n",
            visitor.changes, dead_assignments);
        cfunc->verify(ALLOW_UNUSED_LABELS, false);
    }

    return total_changes;
}
