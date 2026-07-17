#include "ctree_const_fold.h"
#include "../../common/ida_memory.h"

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

    if ( visitor.changes > 0 ) {
        deobf::log("[ctree_const_fold] Folded %d constants\n", visitor.changes);
        cfunc->verify(ALLOW_UNUSED_LABELS, false);
    }

    return visitor.changes;
}
