#include "mba_simplify.h"
#include "../analysis/ast.h"
#include "../analysis/ast_builder.h"

// Include all rule headers to trigger registration
#include "../rules/rules_add.h"
#include "../rules/rules_sub.h"
#include "../rules/rules_xor.h"
#include "../rules/rules_and.h"
#include "../rules/rules_or.h"
#include "../rules/rules_misc.h"

using namespace chernobog::ast;
using namespace chernobog::rules;

// Static member initialization
bool mba_simplify_handler_t::initialized_ = false;
size_t mba_simplify_handler_t::total_simplified_ = 0;

//--------------------------------------------------------------------------
// Initialization
//--------------------------------------------------------------------------
void mba_simplify_handler_t::initialize() {
    if (initialized_) {
        return;
    }

    // Initialize the rule registry (builds pattern index)
    RuleRegistry::instance().initialize();
    initialized_ = true;

    msg("[chernobog] MBA simplify handler initialized\n");
}

bool mba_simplify_handler_t::is_initialized() {
    return initialized_;
}

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool mba_simplify_handler_t::detect(mbl_array_t *mba) {
    if (!mba) {
        return false;
    }

    // Ensure initialized
    if (!initialized_) {
        initialize();
    }

    // Look for complex arithmetic/logic patterns
    int complex_count = 0;
    const int THRESHOLD = 3;  // Need at least 3 complex patterns

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk) continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Look for nested operations (sign of obfuscation)
            if (!is_mba_opcode(ins->opcode)) {
                continue;
            }

            // Check if operands contain nested operations
            bool has_nested = false;

            if (ins->l.t == mop_d && ins->l.d) {
                if (is_mba_opcode(ins->l.d->opcode)) {
                    has_nested = true;
                }
            }

            if (ins->r.t == mop_d && ins->r.d) {
                if (is_mba_opcode(ins->r.d->opcode)) {
                    has_nested = true;
                }
            }

            if (has_nested) {
                complex_count++;
                if (complex_count >= THRESHOLD) {
                    return true;
                }
            }
        }
    }

    return complex_count > 0;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int mba_simplify_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx) {
        return 0;
    }

    if (!initialized_) {
        initialize();
    }

    int total_changes = 0;
    int pass = 0;
    const int MAX_PASSES = 10;

    // Multi-pass simplification (simplifications may enable more simplifications)
    do {
        int pass_changes = 0;
        pass++;

        for (int i = 0; i < mba->qty; i++) {
            mblock_t *blk = mba->get_mblock(i);
            if (!blk) continue;

            for (minsn_t *ins = blk->head; ins; ins = ins->next) {
                int changes = try_simplify_instruction(blk, ins);
                pass_changes += changes;
            }
        }

        total_changes += pass_changes;

        if (pass_changes > 0) {
            // Verify after changes
            mba->verify(false);
        }

    } while (pass < MAX_PASSES && total_changes > 0 && pass == 1);
    // Note: For now, only do one pass to avoid potential infinite loops
    // TODO: Improve change detection to safely do multiple passes

    if (total_changes > 0) {
        ctx->expressions_simplified += total_changes;
        deobf::log_verbose("[MBA] Simplified %d expressions\n", total_changes);
    }

    return total_changes;
}

//--------------------------------------------------------------------------
// Instruction-level simplification
//--------------------------------------------------------------------------
int mba_simplify_handler_t::simplify_insn(mblock_t *blk, minsn_t *ins, deobf_ctx_t *ctx) {
    if (!blk || !ins) {
        return 0;
    }

    if (!initialized_) {
        initialize();
    }

    int changes = try_simplify_instruction(blk, ins);

    if (changes > 0 && ctx) {
        ctx->expressions_simplified += changes;
    }

    return changes;
}

//--------------------------------------------------------------------------
// Internal simplification
//--------------------------------------------------------------------------
int mba_simplify_handler_t::try_simplify_instruction(mblock_t *blk, minsn_t *ins) {
    if (!ins || !is_mba_opcode(ins->opcode)) {
        return 0;
    }

    // Try to find a matching rule
    auto match = RuleRegistry::instance().find_match(ins);

    if (!match.matched()) {
        return 0;
    }

    return apply_match(blk, ins, match);
}

int mba_simplify_handler_t::apply_match(mblock_t *blk, minsn_t *ins,
                                        const RuleRegistry::MatchResult &match) {
    if (!match.rule) {
        return 0;
    }

    // Apply the replacement
    minsn_t *replacement = match.rule->apply_replacement(match.bindings, blk, ins);

    if (!replacement) {
        return 0;
    }

    // Copy the replacement into the original instruction
    ea_t orig_ea = ins->ea;
    int orig_dest_size = ins->d.size;
    mop_t orig_dest = ins->d;

    // Replace the instruction content
    ins->opcode = replacement->opcode;
    ins->l = replacement->l;
    ins->r = replacement->r;
    ins->ea = orig_ea;
    ins->d = orig_dest;
    ins->d.size = orig_dest_size;

    delete replacement;

    total_simplified_++;

    deobf::log_verbose("[MBA] Applied rule '%s' at %a\n", match.rule->name(), orig_ea);

    return 1;
}

//--------------------------------------------------------------------------
// Statistics
//--------------------------------------------------------------------------
size_t mba_simplify_handler_t::total_simplifications() {
    return total_simplified_;
}

void mba_simplify_handler_t::reset_statistics() {
    total_simplified_ = 0;
    RuleRegistry::instance().clear_statistics();
}

void mba_simplify_handler_t::dump_statistics() {
    msg("[chernobog] MBA Simplify Statistics:\n");
    msg("  Total simplifications: %zu\n", total_simplified_);

    RuleRegistry::instance().dump();
}
