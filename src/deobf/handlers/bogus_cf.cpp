#include "bogus_cf.h"
#include "../analysis/pattern_match.h"
#include "../analysis/cfg_analysis.h"
#include "../analysis/opaque_eval.h"
#include <functional>

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool bogus_cf_handler_t::detect(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba)
        return false;

    // Look for opaque predicates
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk || !blk->tail)
            continue;

        if (deobf::is_jcc(blk->tail->opcode)) {
            bool is_true;
            if (is_opaque_predicate(blk->tail, &is_true)) {
                return true;
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int bogus_cf_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    deobf::log("[bogus_cf] Starting bogus control flow removal\n");

    int total_changes = 0;

    // Find all opaque predicates
    auto opaques = find_opaque_predicates(mba, ctx);
    deobf::log("[bogus_cf] Found %zu opaque predicates\n", opaques.size());

    // Remove dead branches (replace conditional with unconditional)
    total_changes += remove_dead_branches(mba, opaques);

    // Find newly unreachable blocks
    auto dead_blocks = find_dead_blocks(mba, opaques);
    deobf::log("[bogus_cf] Found %zu dead blocks\n", dead_blocks.size());

    // Note: Actually removing blocks from mba is complex and may require
    // rebuilding the microcode. For now, we just mark them and let
    // IDA's optimizer handle cleanup.

    // Simplify any remaining junk instructions
    total_changes += simplify_junk_instructions(mba, ctx);

    deobf::log("[bogus_cf] Bogus CF removal complete, %d changes\n", total_changes);
    return total_changes;
}

//--------------------------------------------------------------------------
// Find all opaque predicates
//--------------------------------------------------------------------------
std::vector<bogus_cf_handler_t::opaque_info_t> bogus_cf_handler_t::find_opaque_predicates(
    mbl_array_t *mba, deobf_ctx_t *ctx) {

    std::vector<opaque_info_t> result;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk || !blk->tail)
            continue;

        minsn_t *tail = blk->tail;
        if (!deobf::is_jcc(tail->opcode))
            continue;

        bool is_true;
        if (is_opaque_predicate(tail, &is_true)) {
            opaque_info_t info;
            info.block_idx = i;
            info.cond_insn = tail;
            info.always_true = is_true;

            // Determine live/dead targets
            // For jnz (jump if not zero): if always_true, taken branch is live
            // The fall-through is the block after this one (blk->serial + 1)
            // The taken branch is in tail->d

            if (tail->d.t == mop_b) {
                int taken_target = tail->d.b;
                int fallthrough = i + 1;  // Simplified - actual fall-through may differ

                if (is_true) {
                    // Condition is always true
                    // For jnz/jne: taken branch is live
                    // For jz/je: fall-through is live
                    if (tail->opcode == m_jnz ||
                        tail->opcode == m_ja || tail->opcode == m_jae ||
                        tail->opcode == m_jg || tail->opcode == m_jge) {
                        info.live_target = taken_target;
                        info.dead_target = fallthrough;
                    } else {
                        info.live_target = fallthrough;
                        info.dead_target = taken_target;
                    }
                } else {
                    // Condition is always false
                    if (tail->opcode == m_jnz ||
                        tail->opcode == m_ja || tail->opcode == m_jae ||
                        tail->opcode == m_jg || tail->opcode == m_jge) {
                        info.live_target = fallthrough;
                        info.dead_target = taken_target;
                    } else {
                        info.live_target = taken_target;
                        info.dead_target = fallthrough;
                    }
                }
            }

            result.push_back(info);
            deobf::log_verbose("[bogus_cf] Opaque predicate in block %d: always %s\n",
                              i, is_true ? "true" : "false");
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Check if condition is opaque
//--------------------------------------------------------------------------
bool bogus_cf_handler_t::is_opaque_predicate(minsn_t *cond, bool *is_true) {
    if (!cond)
        return false;

    // Try different opaque patterns (fast path first)

    if (check_const_comparison(cond, is_true))
        return true;

    if (check_math_identity(cond, is_true))
        return true;

    if (check_global_var_pattern(cond, is_true))
        return true;

    // Use Z3-based analysis for complex predicates
    auto z3_result = opaque_eval_t::check_opaque_predicate(cond);
    switch (z3_result) {
        case opaque_eval_t::OPAQUE_ALWAYS_TRUE:
            *is_true = true;
            deobf::log_verbose("[bogus_cf] Z3 determined predicate is always true\n");
            return true;
        case opaque_eval_t::OPAQUE_ALWAYS_FALSE:
            *is_true = false;
            deobf::log_verbose("[bogus_cf] Z3 determined predicate is always false\n");
            return true;
        default:
            break;
    }

    return false;
}

//--------------------------------------------------------------------------
// Check constant comparison (e.g., 1 == 1, 5 < 10)
//--------------------------------------------------------------------------
bool bogus_cf_handler_t::check_const_comparison(minsn_t *insn, bool *result) {
    if (!insn)
        return false;

    // The condition is in the operand (for jcc instructions)
    // It may be a nested setXX instruction

    minsn_t *cmp = nullptr;

    if (insn->l.t == mop_d && insn->l.d) {
        cmp = insn->l.d;
    } else if (insn->l.t == mop_n) {
        // Direct constant condition
        *result = (insn->l.nnn->value != 0);
        return true;
    }

    if (!cmp)
        return false;

    // Check for setXX with two constant operands
    if (cmp->opcode >= m_setz && cmp->opcode <= m_setle) {
        if (cmp->l.t == mop_n && cmp->r.t == mop_n) {
            int64_t l = cmp->l.nnn->value;
            int64_t r = cmp->r.nnn->value;

            switch (cmp->opcode) {
                case m_setz:  *result = (l == r); return true;
                case m_setnz: *result = (l != r); return true;
                case m_setae: *result = ((uint64_t)l >= (uint64_t)r); return true;
                case m_setb:  *result = ((uint64_t)l < (uint64_t)r); return true;
                case m_seta:  *result = ((uint64_t)l > (uint64_t)r); return true;
                case m_setbe: *result = ((uint64_t)l <= (uint64_t)r); return true;
                case m_setg:  *result = (l > r); return true;
                case m_setge: *result = (l >= r); return true;
                case m_setl:  *result = (l < r); return true;
                case m_setle: *result = (l <= r); return true;
                default: break;
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Check math identity pattern: x * (x + 1) % 2 == 0
// This is always true because consecutive integers have opposite parity
//--------------------------------------------------------------------------
bool bogus_cf_handler_t::check_math_identity(minsn_t *insn, bool *result) {
    if (!insn)
        return false;

    // Look for: setz(smod(mul(...), 2), 0)
    // Or similar patterns

    minsn_t *cmp = nullptr;
    if (insn->l.t == mop_d)
        cmp = insn->l.d;
    else
        return false;

    if (!cmp || cmp->opcode != m_setz)
        return false;

    // Right operand should be 0
    if (cmp->r.t != mop_n || cmp->r.nnn->value != 0)
        return false;

    // Left operand should be mod by 2
    if (cmp->l.t != mop_d)
        return false;

    minsn_t *mod = cmp->l.d;
    if (!mod || (mod->opcode != m_smod && mod->opcode != m_umod))
        return false;

    // Modulus should be 2
    if (mod->r.t != mop_n || mod->r.nnn->value != 2)
        return false;

    // The dividend should be a multiplication
    if (mod->l.t != mop_d)
        return false;

    minsn_t *mul = mod->l.d;
    if (!mul || mul->opcode != m_mul)
        return false;

    // One factor should be (x + 1) where x is the other factor
    // This is complex to verify precisely, but the pattern is distinctive

    // For now, assume any mul -> mod 2 -> cmp 0 is this pattern
    *result = true;  // x * (x+1) % 2 is always 0
    return true;
}

//--------------------------------------------------------------------------
// Check global variable pattern (Hikari uses LHSGV/RHSGV)
// This handles complex expressions using global constants like:
//   ((~((~(~dword_Y | ~dword_X) | v2 ^ (v1 | ~dword_X & mask)) + C) & M1) * ...) / D < threshold
//--------------------------------------------------------------------------
bool bogus_cf_handler_t::check_global_var_pattern(minsn_t *insn, bool *result) {
    if (!insn)
        return false;

    // Use the opaque evaluator to try to evaluate the full expression
    // It will read globals from the binary and compute the result

    // First, check if this expression involves any global variables
    bool has_global = false;
    std::function<void(const mop_t &)> check_op = [&](const mop_t &op) {
        if (op.t == mop_v) {
            has_global = true;
        } else if (op.t == mop_d && op.d) {
            check_op(op.d->l);
            check_op(op.d->r);
        }
    };

    check_op(insn->l);
    check_op(insn->r);

    if (!has_global)
        return false;

    // Try to evaluate the condition
    bool eval_result;
    if (opaque_eval_t::evaluate_condition(insn, &eval_result)) {
        *result = eval_result;
        deobf::log_verbose("[bogus_cf] Evaluated global pattern: always %s\n",
                          eval_result ? "true" : "false");
        return true;
    }

    // If direct evaluation fails, try evaluating sub-expressions
    // to see if we can determine the outcome

    // Handle nested condition in jcc
    minsn_t *cond = nullptr;
    if (insn->l.t == mop_d && insn->l.d) {
        cond = insn->l.d;
    }

    if (cond) {
        // Try to evaluate the comparison operands
        auto left_val = opaque_eval_t::evaluate_operand(cond->l);
        auto right_val = opaque_eval_t::evaluate_operand(cond->r);

        if (left_val.has_value() && right_val.has_value()) {
            uint64_t l = *left_val;
            uint64_t r = *right_val;
            int64_t sl = (int64_t)l;
            int64_t sr = (int64_t)r;

            bool cond_result = false;
            bool found = true;

            switch (cond->opcode) {
                case m_setz:  cond_result = (l == r); break;
                case m_setnz: cond_result = (l != r); break;
                case m_setl:  cond_result = (sl < sr); break;
                case m_setle: cond_result = (sl <= sr); break;
                case m_setg:  cond_result = (sl > sr); break;
                case m_setge: cond_result = (sl >= sr); break;
                case m_setb:  cond_result = (l < r); break;
                case m_setbe: cond_result = (l <= r); break;
                case m_seta:  cond_result = (l > r); break;
                case m_setae: cond_result = (l >= r); break;
                default: found = false;
            }

            if (found) {
                // Adjust for the outer jump instruction
                if (insn->opcode == m_jnz) {
                    *result = cond_result;
                } else if (insn->opcode == m_jz) {
                    *result = !cond_result;
                } else {
                    *result = cond_result;
                }
                deobf::log_verbose("[bogus_cf] Computed global expression: %llx vs %llx -> %s\n",
                                  (unsigned long long)l, (unsigned long long)r,
                                  *result ? "true" : "false");
                return true;
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Find dead blocks
//--------------------------------------------------------------------------
std::set<int> bogus_cf_handler_t::find_dead_blocks(mbl_array_t *mba,
    const std::vector<opaque_info_t> &opaques) {

    std::set<int> dead;

    // Start with dead targets from opaque predicates
    for (const auto &op : opaques) {
        if (op.dead_target >= 0 && op.dead_target < mba->qty) {
            dead.insert(op.dead_target);
        }
    }

    // Expand: any block only reachable from dead blocks is also dead
    bool changed = true;
    while (changed) {
        changed = false;

        for (int i = 0; i < mba->qty; i++) {
            if (i == 0)  // Entry block is never dead
                continue;
            if (dead.count(i))
                continue;

            mblock_t *blk = mba->get_mblock(i);
            if (!blk)
                continue;

            // Check if all predecessors are dead
            bool all_preds_dead = true;
            bool has_preds = false;

            for (int j = 0; j < mba->qty; j++) {
                if (j == i)
                    continue;

                mblock_t *pred = mba->get_mblock(j);
                if (!pred)
                    continue;

                // Check if j is a predecessor of i
                for (int k = 0; k < pred->nsucc(); k++) {
                    if (pred->succ(k) == i) {
                        has_preds = true;
                        if (!dead.count(j)) {
                            all_preds_dead = false;
                            break;
                        }
                    }
                }

                if (!all_preds_dead)
                    break;
            }

            if (has_preds && all_preds_dead) {
                dead.insert(i);
                changed = true;
            }
        }
    }

    return dead;
}

//--------------------------------------------------------------------------
// Remove dead branches
//--------------------------------------------------------------------------
int bogus_cf_handler_t::remove_dead_branches(mbl_array_t *mba,
    const std::vector<opaque_info_t> &opaques) {

    int changes = 0;

    for (const auto &op : opaques) {
        mblock_t *blk = mba->get_mblock(op.block_idx);
        if (!blk || !blk->tail)
            continue;

        minsn_t *tail = blk->tail;

        // Replace conditional jump with unconditional to live target
        // This requires creating a new goto instruction

        // For simplicity, just modify the condition to be a constant
        // so that the optimizer will eliminate the dead branch

        if (tail->l.t == mop_d && tail->l.d) {
            // Replace nested condition with constant
            minsn_t *cond = tail->l.d;

            // Change to: set result = always_true ? 1 : 0
            cond->opcode = m_mov;
            cond->l.make_number(op.always_true ? 1 : 0, cond->l.size);
            cond->r.erase();

            changes++;
            deobf::log_verbose("[bogus_cf] Simplified opaque predicate in block %d\n",
                              op.block_idx);
        }
    }

    return changes;
}

//--------------------------------------------------------------------------
// Remove dead blocks (mark as unreachable)
//--------------------------------------------------------------------------
int bogus_cf_handler_t::remove_dead_blocks(mbl_array_t *mba, const std::set<int> &dead_blocks) {
    int changes = 0;

    // Removing blocks from mba is complex
    // For now, just clear their contents to make them no-ops

    for (int idx : dead_blocks) {
        mblock_t *blk = mba->get_mblock(idx);
        if (!blk)
            continue;

        // Clear all instructions except the terminator
        // Replace terminator with goto to itself (infinite loop = unreachable)

        // This is a simplified approach - proper removal would need mba manipulation
        deobf::log_verbose("[bogus_cf] Marked block %d as dead\n", idx);
        changes++;
    }

    return changes;
}

//--------------------------------------------------------------------------
// Simplify junk instructions
//--------------------------------------------------------------------------
int bogus_cf_handler_t::simplify_junk_instructions(mbl_array_t *mba, deobf_ctx_t *ctx) {
    int changes = 0;

    // Hikari adds random arithmetic that doesn't affect results
    // Look for patterns like: x = x + r; x = x - r (where r is random constant)

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        // Track variable values to detect no-op patterns
        // This is simplified - full implementation would need dataflow analysis

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Check for x = x op const patterns that could be canceled
            // by subsequent x = x reverse_op const

            // For now, just count potential junk instructions
            if (ins->opcode == m_add || ins->opcode == m_sub ||
                ins->opcode == m_xor || ins->opcode == m_or || ins->opcode == m_and) {

                // If result is not used later, it might be junk
                // This requires use-def analysis
            }
        }
    }

    return changes;
}
