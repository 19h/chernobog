#include "ctree_switch_fold.h"
#include <set>
#include <map>

//--------------------------------------------------------------------------
// Helper: Check if an expression is a high-bits extraction (HIDWORD pattern)
// Returns true if expr is (x >> 32) or similar high-bits extraction
//--------------------------------------------------------------------------
static bool is_hidword_expr(const cexpr_t *e, cexpr_t **base_out = nullptr) {
    if (!e)
        return false;

    // Pattern: (x >> 32) - unsigned or signed shift by 32
    if ((e->op == cot_ushr || e->op == cot_sshr) && e->y && e->y->op == cot_num) {
        uint64_t shift = e->y->numval();
        if (shift == 32) {
            if (base_out && e->x)
                *base_out = e->x;
            return true;
        }
    }

    // Pattern: (x >> 32) & 0xFFFFFFFF (explicit mask)
    if (e->op == cot_band && e->y && e->y->op == cot_num) {
        uint64_t mask = e->y->numval();
        if (mask == 0xFFFFFFFF && e->x) {
            return is_hidword_expr(e->x, base_out);
        }
    }

    // Pattern: cast to 32-bit of (x >> 32)
    if (e->op == cot_cast && e->x) {
        tinfo_t t = e->type;
        if (t.get_size() == 4) {
            return is_hidword_expr(e->x, base_out);
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Helper: Try to evaluate a switch expression to a constant
// This handles cases where the expression involves constants that
// can be resolved at analysis time
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
        // Apply size mask
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
// Visitor that analyzes switch statements and their case blocks
//--------------------------------------------------------------------------
struct switch_fold_visitor_t : public ctree_visitor_t {
    cfunc_t *func;
    int changes = 0;

    // Track which variables are assigned constant values
    std::map<int, uint64_t> var_constants;  // lvars_t index -> constant value

    switch_fold_visitor_t(cfunc_t *f) : ctree_visitor_t(CV_PARENTS), func(f) {}

    // Check if a variable always has a specific constant value (for HIDWORD pattern)
    bool var_hidword_is_constant(cexpr_t *base_expr, uint64_t *out_val) {
        // For now, we check if the base is a variable and if its high 32 bits
        // are always the same value. This is a simplified check.
        //
        // A more complete implementation would:
        // 1. Track all assignments to the variable
        // 2. Check if the high 32 bits are always the same

        // Check if base is a local variable reference
        if (!base_expr || base_expr->op != cot_var)
            return false;

        // For now, just check if we've seen this variable with a constant HIDWORD
        // This can be enhanced with proper dataflow analysis
        return false;
    }

    int idaapi visit_insn(cinsn_t *ins) override {
        if (!ins)
            return 0;

        // Look for switch statements
        if (ins->op != cit_switch || !ins->cswitch)
            return 0;

        cswitch_t *sw = ins->cswitch;
        cexpr_t *switch_expr = &sw->expr;

        deobf::log_verbose("[ctree_switch_fold] Found switch at %a\n", ins->ea);

        // Check if switch expression is a constant
        uint64_t const_val = 0;
        if (try_eval_switch_expr(switch_expr, &const_val)) {
            deobf::log("[ctree_switch_fold] Switch expression is constant: 0x%llx\n",
                      (unsigned long long)const_val);

            // Find the matching case using the built-in helper
            int matching_case = sw->cases.find_value(const_val);

            if (matching_case >= 0) {
                deobf::log("[ctree_switch_fold] Matching case found: %d\n", matching_case);
                // TODO: Replace switch with the body of matching case
                // This is complex because we need to handle break statements,
                // fall-through, and update the parent correctly
                changes++;
            } else {
                // Check for default case (empty values vector)
                for (size_t i = 0; i < sw->cases.size(); i++) {
                    if (sw->cases[i].values.empty()) {
                        deobf::log("[ctree_switch_fold] No matching case, will use default: %zu\n", i);
                        matching_case = (int)i;
                        changes++;
                        break;
                    }
                }
            }
        }

        // Check for HIDWORD pattern: switch(HIDWORD(x)) where HIDWORD is always constant
        cexpr_t *base_expr = nullptr;
        if (is_hidword_expr(switch_expr, &base_expr)) {
            deobf::log("[ctree_switch_fold] Switch on HIDWORD expression\n");

            // Check if the high bits are always the same value
            uint64_t hidword_val;
            if (var_hidword_is_constant(base_expr, &hidword_val)) {
                deobf::log("[ctree_switch_fold] HIDWORD is always 0x%llx\n",
                          (unsigned long long)hidword_val);
                // TODO: Fold the switch
            }
        }

        return 0;
    }
};

//--------------------------------------------------------------------------
// Visitor that tracks variable assignments to detect constant patterns
//--------------------------------------------------------------------------
struct var_tracker_visitor_t : public ctree_visitor_t {
    cfunc_t *func;

    // Track assignments: var_idx -> set of assigned values
    std::map<int, std::set<uint64_t>> var_assignments;

    // Track which variables hold 64-bit values with constant high 32 bits
    std::map<int, std::set<uint64_t>> var_hidword_values;

    var_tracker_visitor_t(cfunc_t *f) : ctree_visitor_t(CV_FAST), func(f) {}

    int idaapi visit_expr(cexpr_t *e) override {
        if (!e)
            return 0;

        // Look for assignments: var = expr
        if (e->op == cot_asg && e->x && e->y) {
            if (e->x->op == cot_var) {
                int var_idx = e->x->v.idx;

                // Check if RHS is a constant
                if (e->y->op == cot_num) {
                    uint64_t val = e->y->numval();
                    var_assignments[var_idx].insert(val);

                    // Track high 32 bits for 64-bit values
                    if (e->y->type.get_size() == 8) {
                        uint64_t hidword = val >> 32;
                        var_hidword_values[var_idx].insert(hidword);
                    }
                }

                // Check for OR with shifted constant: var |= (const << 32)
                // This is how HIDWORD is often set
                if (e->op == cot_asgbor && e->y && e->y->op == cot_shl) {
                    cexpr_t *shl = e->y;
                    if (shl->x && shl->x->op == cot_num &&
                        shl->y && shl->y->op == cot_num) {
                        uint64_t val = shl->x->numval();
                        uint64_t shift = shl->y->numval();
                        if (shift == 32) {
                            var_hidword_values[var_idx].insert(val);
                        }
                    }
                }
            }
        }

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

    // First pass: track variable assignments to detect constant patterns
    var_tracker_visitor_t tracker(cfunc);
    tracker.apply_to(&cfunc->body, nullptr);

    // Log any variables with constant HIDWORD values
    for (const auto &kv : tracker.var_hidword_values) {
        if (kv.second.size() == 1) {
            uint64_t hidword = *kv.second.begin();
            deobf::log_verbose("[ctree_switch_fold] Variable %d has constant HIDWORD: 0x%llx\n",
                      kv.first, (unsigned long long)hidword);
        }
    }

    // Second pass: fold switches
    switch_fold_visitor_t folder(cfunc);
    folder.apply_to(&cfunc->body, nullptr);

    if (folder.changes > 0) {
        deobf::log("[ctree_switch_fold] Identified %d foldable switches\n", folder.changes);
        // Note: actual folding is not yet implemented - just detection
    }

    return folder.changes;
}
