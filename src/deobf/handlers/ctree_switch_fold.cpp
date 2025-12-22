#include "ctree_switch_fold.h"
#include <set>
#include <map>

//--------------------------------------------------------------------------
// Helper: Find a case value in ccases_t (since SDK function may not be exported)
//--------------------------------------------------------------------------
static int find_case_value(const ccases_t &cases, uint64_t v) {
    for (size_t i = 0; i < cases.size(); i++) {
        const ccase_t &c = cases[i];
        for (size_t j = 0; j < c.values.size(); j++) {
            if (c.values[j] == v)
                return (int)i;
        }
    }
    return -1;
}

//--------------------------------------------------------------------------
// Helper: Check if an expression is a high-bits extraction (HIDWORD pattern)
// Returns true if expr is (x >> 32) or similar high-bits extraction
//--------------------------------------------------------------------------
static bool is_hidword_expr(const cexpr_t *e, int *base_var_idx = nullptr) {
    if (!e)
        return false;

    // Pattern: (x >> 32) - unsigned or signed shift by 32
    if ((e->op == cot_ushr || e->op == cot_sshr) && e->y && e->y->op == cot_num) {
        uint64_t shift = e->y->numval();
        if (shift == 32 && e->x) {
            if (base_var_idx && e->x->op == cot_var)
                *base_var_idx = e->x->v.idx;
            return true;
        }
    }

    // Pattern: cast((x >> 32))
    if (e->op == cot_cast && e->x) {
        return is_hidword_expr(e->x, base_var_idx);
    }

    // Pattern: (x >> 32) & 0xFFFFFFFF
    if (e->op == cot_band && e->y && e->y->op == cot_num) {
        uint64_t mask = e->y->numval();
        if (mask == 0xFFFFFFFF && e->x) {
            return is_hidword_expr(e->x, base_var_idx);
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Helper: Try to evaluate a switch expression to a constant
//--------------------------------------------------------------------------
static bool try_eval_switch_expr(const cexpr_t *e, uint64_t *out_val) {
    if (!e || !out_val)
        return false;

    // Direct constant
    if (e->op == cot_num) {
        *out_val = e->numval();
        return true;
    }

    // Cast of constant
    if (e->op == cot_cast && e->x && e->x->op == cot_num) {
        *out_val = e->x->numval();
        int size = e->type.get_size();
        if (size > 0 && size < 8) {
            uint64_t mask = (1ULL << (size * 8)) - 1;
            *out_val &= mask;
        }
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Visitor that removes break statements from a block
// This is needed when extracting a case body from a switch
//--------------------------------------------------------------------------
struct break_remover_t : public ctree_visitor_t {
    int removed = 0;

    break_remover_t() : ctree_visitor_t(CV_PARENTS) {}

    int idaapi visit_insn(cinsn_t *ins) override {
        if (!ins)
            return 0;

        // Remove break statements by converting to empty block
        if (ins->op == cit_break) {
            ins->op = cit_empty;
            removed++;
        }

        return 0;
    }
};

//--------------------------------------------------------------------------
// First pass: Track variable assignments to find constant patterns
//--------------------------------------------------------------------------
struct var_tracker_visitor_t : public ctree_visitor_t {
    cfunc_t *func;

    // Track assignments to each variable: var_idx -> set of assigned values
    std::map<int, std::set<uint64_t>> var_full_values;

    // Track HIDWORD values: var_idx -> set of high 32-bit values seen
    std::map<int, std::set<uint64_t>> var_hidword_values;

    var_tracker_visitor_t(cfunc_t *f) : ctree_visitor_t(CV_FAST), func(f) {}

    int idaapi visit_expr(cexpr_t *e) override {
        if (!e)
            return 0;

        // Look for assignments: var = value
        if (e->op == cot_asg && e->x && e->y && e->x->op == cot_var) {
            int var_idx = e->x->v.idx;

            // Direct constant assignment
            if (e->y->op == cot_num) {
                uint64_t val = e->y->numval();
                var_full_values[var_idx].insert(val);

                // Track high 32 bits for 64-bit values
                if (e->x->type.get_size() == 8) {
                    uint64_t hidword = val >> 32;
                    var_hidword_values[var_idx].insert(hidword);
                }
            }

            // OR assignment: var |= (const << 32) - sets HIDWORD
            if (e->op == cot_asgbor && e->y->op == cot_shl) {
                cexpr_t *shl = e->y;
                if (shl->x && shl->x->op == cot_num &&
                    shl->y && shl->y->op == cot_num &&
                    shl->y->numval() == 32) {
                    var_hidword_values[var_idx].insert(shl->x->numval());
                }
            }
        }

        return 0;
    }

    // Check if a variable's HIDWORD is always the same constant
    bool get_constant_hidword(int var_idx, uint64_t *out_val) const {
        auto it = var_hidword_values.find(var_idx);
        if (it != var_hidword_values.end() && it->second.size() == 1) {
            if (out_val)
                *out_val = *it->second.begin();
            return true;
        }
        return false;
    }
};

//--------------------------------------------------------------------------
// Second pass: Fold switches with constant conditions
//--------------------------------------------------------------------------
struct switch_fold_visitor_t : public ctree_visitor_t {
    cfunc_t *func;
    const var_tracker_visitor_t &tracker;
    int changes = 0;

    switch_fold_visitor_t(cfunc_t *f, const var_tracker_visitor_t &t)
        : ctree_visitor_t(CV_PARENTS), func(f), tracker(t) {}

    int idaapi visit_insn(cinsn_t *ins) override {
        if (!ins || ins->op != cit_switch || !ins->cswitch)
            return 0;

        cswitch_t *sw = ins->cswitch;
        cexpr_t *switch_expr = &sw->expr;

        deobf::log_verbose("[ctree_switch_fold] Found switch at %a with %zu cases\n",
                  ins->ea, sw->cases.size());

        uint64_t const_val = 0;
        bool is_constant = false;

        // Check if switch expression is a direct constant
        if (try_eval_switch_expr(switch_expr, &const_val)) {
            is_constant = true;
            deobf::log("[ctree_switch_fold] Switch expression is constant: 0x%llx\n",
                      (unsigned long long)const_val);
        }

        // Check for HIDWORD pattern with constant
        int hidword_var = -1;
        if (!is_constant && is_hidword_expr(switch_expr, &hidword_var)) {
            if (hidword_var >= 0 && tracker.get_constant_hidword(hidword_var, &const_val)) {
                is_constant = true;
                deobf::log("[ctree_switch_fold] HIDWORD(var%d) is always 0x%llx\n",
                          hidword_var, (unsigned long long)const_val);
            }
        }

        if (!is_constant)
            return 0;

        // Find the matching case
        int matching_idx = find_case_value(sw->cases, const_val);
        if (matching_idx < 0) {
            // Check for default case
            for (size_t i = 0; i < sw->cases.size(); i++) {
                if (sw->cases[i].values.empty()) {
                    matching_idx = (int)i;
                    break;
                }
            }
        }

        if (matching_idx < 0) {
            deobf::log("[ctree_switch_fold] No matching case for value 0x%llx\n",
                      (unsigned long long)const_val);
            return 0;
        }

        deobf::log("[ctree_switch_fold] Replacing switch with case %d body\n", matching_idx);

        // Get the matching case body
        ccase_t &matching_case = sw->cases[matching_idx];

        // The case body IS a cinsn_t (ccase_t extends cinsn_t)
        // We need to copy its contents to replace the switch

        // Remove break statements from the case body
        break_remover_t remover;
        remover.apply_to(&matching_case, nullptr);
        if (remover.removed > 0) {
            deobf::log_verbose("[ctree_switch_fold] Removed %d break statements\n", remover.removed);
        }

        // Replace the switch instruction with the case body
        // We copy the op and relevant fields from the case to the switch insn
        cinsn_t *case_body = &matching_case;

        // Copy the case instruction type and data
        ins->op = case_body->op;
        ins->label_num = case_body->label_num;

        // Copy the appropriate union member based on op type
        switch (case_body->op) {
            case cit_block:
                ins->cblock = case_body->cblock;
                case_body->cblock = nullptr;  // Transfer ownership
                break;
            case cit_expr:
                ins->cexpr = case_body->cexpr;
                case_body->cexpr = nullptr;
                break;
            case cit_if:
                ins->cif = case_body->cif;
                case_body->cif = nullptr;
                break;
            case cit_for:
                ins->cfor = case_body->cfor;
                case_body->cfor = nullptr;
                break;
            case cit_while:
                ins->cwhile = case_body->cwhile;
                case_body->cwhile = nullptr;
                break;
            case cit_do:
                ins->cdo = case_body->cdo;
                case_body->cdo = nullptr;
                break;
            case cit_switch:
                ins->cswitch = case_body->cswitch;
                case_body->cswitch = nullptr;
                break;
            case cit_return:
                ins->creturn = case_body->creturn;
                case_body->creturn = nullptr;
                break;
            case cit_goto:
                ins->cgoto = case_body->cgoto;
                case_body->cgoto = nullptr;
                break;
            default:
                // For simple ops like cit_empty, cit_break, cit_continue
                break;
        }

        // The old switch data will be cleaned up when sw goes out of scope
        // But we set cswitch to nullptr so it's not double-freed
        // Actually, we already transferred ownership above

        changes++;
        return 0;
    }
};

//--------------------------------------------------------------------------
// Main entry point
//--------------------------------------------------------------------------
int ctree_switch_fold_handler_t::run(cfunc_t *cfunc) {
    if (!cfunc)
        return 0;

    deobf::log_verbose("[ctree_switch_fold] Running on %a\n", cfunc->entry_ea);

    // First pass: track variable assignments
    var_tracker_visitor_t tracker(cfunc);
    tracker.apply_to(&cfunc->body, nullptr);

    // Log any variables with constant HIDWORD values
    for (const auto &kv : tracker.var_hidword_values) {
        if (kv.second.size() == 1) {
            deobf::log_verbose("[ctree_switch_fold] var%d has constant HIDWORD: 0x%llx\n",
                      kv.first, (unsigned long long)*kv.second.begin());
        }
    }

    // Second pass: fold switches
    switch_fold_visitor_t folder(cfunc, tracker);
    folder.apply_to(&cfunc->body, nullptr);

    if (folder.changes > 0) {
        deobf::log("[ctree_switch_fold] Folded %d switches\n", folder.changes);
        // Verify the ctree after modification
        cfunc->verify(ALLOW_UNUSED_LABELS, false);
    }

    return folder.changes;
}
