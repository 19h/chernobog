#include "ctree_const_fold.h"

//--------------------------------------------------------------------------
// Ctree visitor that folds XOR with global constants
//--------------------------------------------------------------------------
struct const_fold_visitor_t : public ctree_visitor_t {
    int changes = 0;

    const_fold_visitor_t() : ctree_visitor_t(CV_PARENTS) {}

    int idaapi visit_expr(cexpr_t *e) override {
        // Look for XOR expressions
        if (e->op != cot_xor)
            return 0;

        // One operand must be a number constant
        if (e->x->op != cot_num && e->y->op != cot_num)
            return 0;

        cexpr_t *val_expr = (e->y->op == cot_num) ? e->x : e->y;
        cexpr_t *num_expr = (e->y->op == cot_num) ? e->y : e->x;

        // Debug: show what we're dealing with
        static int xor_count = 0;
        if (xor_count < 20) {
            xor_count++;
            deobf::log_verbose("[ctree_const_fold] XOR: val.op=%d num=0x%llx\n",
                              val_expr->op, (unsigned long long)num_expr->numval());
        }

        // Try to get a global address from the value expression
        ea_t obj_addr = BADADDR;

        // Case 1: Direct object reference (cot_obj)
        if (val_expr->op == cot_obj) {
            obj_addr = val_expr->obj_ea;
        }
        // Case 2: Pointer dereference (cot_ptr) - check if dereferencing a constant
        else if (val_expr->op == cot_ptr && val_expr->x) {
            if (val_expr->x->op == cot_obj) {
                obj_addr = val_expr->x->obj_ea;
            } else if (val_expr->x->op == cot_num) {
                obj_addr = (ea_t)val_expr->x->numval();
            } else if (val_expr->x->op == cot_cast && val_expr->x->x) {
                // Cast of number or obj
                if (val_expr->x->x->op == cot_num) {
                    obj_addr = (ea_t)val_expr->x->x->numval();
                } else if (val_expr->x->x->op == cot_obj) {
                    obj_addr = val_expr->x->x->obj_ea;
                }
            }
        }

        if (obj_addr == BADADDR)
            return 0;

        // Check if it's a byte/word/dword in a data section
        flags64_t flags = get_flags(obj_addr);
        if (!is_data(flags))
            return 0;

        // Read the value based on size
        uint64_t obj_val = 0;
        int size = val_expr->type.get_size();
        if (size <= 0 || size > 8)
            return 0;

        switch (size) {
            case 1: obj_val = get_byte(obj_addr); break;
            case 2: obj_val = get_word(obj_addr); break;
            case 4: obj_val = get_dword(obj_addr); break;
            case 8: obj_val = get_qword(obj_addr); break;
            default: return 0;
        }

        // Get the constant
        uint64_t const_val = num_expr->numval();

        // Compute the XOR
        uint64_t result = obj_val ^ const_val;

        deobf::log_verbose("[ctree_const_fold] Folding %a ^ 0x%llx = 0x%llx\n",
                          obj_addr, (unsigned long long)const_val,
                          (unsigned long long)result);

        // Replace the expression with the constant result
        e->op = cot_num;
        e->n = new cnumber_t();
        e->n->_value = result;
        e->x = nullptr;
        e->y = nullptr;

        changes++;
        return 0;
    }
};

//--------------------------------------------------------------------------
// Main entry point
//--------------------------------------------------------------------------
int ctree_const_fold_handler_t::run(cfunc_t *cfunc) {
    if (!cfunc)
        return 0;

    deobf::log_verbose("[ctree_const_fold] Running on %a\n", cfunc->entry_ea);

    const_fold_visitor_t visitor;
    visitor.apply_to(&cfunc->body, nullptr);

    if (visitor.changes > 0) {
        deobf::log("[ctree_const_fold] Folded %d constants\n", visitor.changes);
    }

    return visitor.changes;
}
