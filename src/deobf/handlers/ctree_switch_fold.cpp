#include "ctree_switch_fold.h"

//--------------------------------------------------------------------------
// Helper: Find a case value in ccases_t (since SDK function may not be exported)
//--------------------------------------------------------------------------
static int find_case_value(const ccases_t &cases, uint64_t v)
{
    for ( size_t i = 0; i < cases.size(); ++i ) {
        const ccase_t &c = cases[i];
        for ( size_t j = 0; j < c.values.size(); ++j ) {
            if ( c.values[j] == v ) 
                return (int)i;
        }
    }
    return -1;
}

//--------------------------------------------------------------------------
// Helper: Try to evaluate a switch expression to a constant
//--------------------------------------------------------------------------
static bool try_eval_switch_expr(const cexpr_t *e, uint64_t *out_val) {
    if ( !e || !out_val ) 
        return false;

    // Direct constant
    if ( e->op == cot_num ) {
        *out_val = e->numval();
        return true;
    }

    // Cast of constant
    if ( e->op == cot_cast && e->x && e->x->op == cot_num ) {
        *out_val = e->x->numval();
        int size = e->type.get_size();
        if ( size > 0 && size < 8 ) {
            uint64_t mask = (1ULL << (size * 8)) - 1;
            *out_val &= mask;
        }
        return true;
    }

    return false;
}

static bool remove_trailing_break(cinsn_t *ins)
{
    if ( ins == nullptr )
        return false;
    if ( ins->op == cit_break ) {
        ins->cleanup();
        return true;
    }
    if ( ins->op != cit_block || ins->cblock == nullptr || ins->cblock->empty() )
        return false;

    cinsn_t *last = &ins->cblock->back();
    if ( last->op != cit_break )
        return false;
    last->cleanup();
    return true;
}

//--------------------------------------------------------------------------
// Second pass: Fold switches with constant conditions
//--------------------------------------------------------------------------
struct switch_fold_visitor_t : public ctree_visitor_t {
    cfunc_t *func;
    int changes = 0;

    explicit switch_fold_visitor_t(cfunc_t *f)
        : ctree_visitor_t(CV_PARENTS), func(f) {}

    int idaapi visit_insn(cinsn_t *ins) override {
        if ( !ins || ins->op != cit_switch || !ins->cswitch ) 
            return 0;

        cswitch_t *sw = ins->cswitch;
        cexpr_t *switch_expr = &sw->expr;

        deobf::log("[ctree_switch_fold] Found switch at %a with %zu cases\n",
                  ins->ea, sw->cases.size());

        // Debug: log switch expression type
        deobf::log_verbose("[ctree_switch_fold] Switch expr op=%d\n", switch_expr->op);

        uint64_t const_val = 0;
        bool is_constant = false;

        // Check if switch expression is a direct constant
        if ( try_eval_switch_expr(switch_expr, &const_val) ) {
            is_constant = true;
            deobf::log("[ctree_switch_fold] Switch expression is constant: 0x%llx\n",
                      (unsigned long long)const_val);
        }

        // Check for ( cast )&object pattern - this is a constant address
        // Pattern: cot_cast(cot_ref(cot_obj))
        if ( !is_constant && switch_expr->op == cot_cast && switch_expr->x ) {
            cexpr_t *inner = switch_expr->x;
            if ( inner->op == cot_ref && inner->x && inner->x->op == cot_obj ) {
                // This is &object - get the object address
                ea_t obj_addr = inner->x->obj_ea;
                if ( obj_addr != BADADDR ) {
                    const_val = (uint64_t)obj_addr;
                    is_constant = true;
                    deobf::log("[ctree_switch_fold] Switch on &object: addr 0x%llx\n",
                              (unsigned long long)const_val);
                }
            }
        }

        if ( !is_constant ) 
            return 0;

        // Find the matching case
        int matching_idx = find_case_value(sw->cases, const_val);
        if ( matching_idx < 0 ) {
            // Check for default case
            for ( size_t i = 0; i < sw->cases.size(); ++i ) {
                if ( sw->cases[i].values.empty() ) {
                    matching_idx = (int)i;
                    break;
                }
            }
        }

        if ( matching_idx < 0 ) {
            deobf::log("[ctree_switch_fold] No matching case for value 0x%llx\n",
                      (unsigned long long)const_val);
            return 0;
        }

        deobf::log("[ctree_switch_fold] Replacing switch with case %d body\n", matching_idx);

        // Deep-copy the selected body before cleaning the switch. A case that
        // is not last must end in an unconditional top-level break; otherwise
        // C fall-through semantics require subsequent case bodies as well.
        ccase_t &matching_case = sw->cases[matching_idx];
        cinsn_t *replacement = new cinsn_t(matching_case);
        const bool had_trailing_break = remove_trailing_break(replacement);
        if ( static_cast<size_t>(matching_idx + 1) < sw->cases.size()
          && !had_trailing_break ) {
            delete replacement;
            deobf::log_verbose("[ctree_switch_fold] Case %d may fall through; not folding\n",
                              matching_idx);
            return 0;
        }

        ins->cleanup();
        ins->replace_by(replacement);

        changes++;
        return 0;
    }
};

//--------------------------------------------------------------------------
// Main entry point
//--------------------------------------------------------------------------
int ctree_switch_fold_handler_t::run(cfunc_t *cfunc) {
    if ( !cfunc ) 
        return 0;

    deobf::log_verbose("[ctree_switch_fold] Running on %a\n", cfunc->entry_ea);

    switch_fold_visitor_t folder(cfunc);
    folder.apply_to(&cfunc->body, nullptr);

    if ( folder.changes > 0 ) {
        deobf::log("[ctree_switch_fold] Folded %d switches\n", folder.changes);
        // Verify the ctree after modification
        cfunc->verify(ALLOW_UNUSED_LABELS, false);
    }

    return folder.changes;
}
