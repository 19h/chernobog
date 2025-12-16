#include "jump_optimizer.h"

namespace chernobog {

// Static member initialization
size_t jump_optimizer_handler_t::jumps_simplified_ = 0;
size_t jump_optimizer_handler_t::jumps_converted_goto_ = 0;
size_t jump_optimizer_handler_t::jumps_removed_ = 0;

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------

bool jump_optimizer_handler_t::detect(mbl_array_t* mba) {
    if (!mba)
        return false;

    // Look for conditional jumps with complex conditions
    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk || !blk->tail)
            continue;

        minsn_t* tail = blk->tail;
        if (!is_mcode_jcond(tail->opcode))
            continue;

        // Check if condition is complex (involves nested operations)
        if (tail->l.t == mop_d && tail->l.d) {
            return true;  // Has nested instruction in condition
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Main pass
//--------------------------------------------------------------------------

int jump_optimizer_handler_t::run(mbl_array_t* mba, deobf_ctx_t* ctx) {
    if (!mba || !ctx)
        return 0;

    // Initialize rule registry
    rules::JumpRuleRegistry::instance().initialize();

    int total_changes = 0;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk || !blk->tail)
            continue;

        minsn_t* tail = blk->tail;
        if (!is_mcode_jcond(tail->opcode))
            continue;

        int changes = simplify_jcc(blk, tail, ctx);
        total_changes += changes;
    }

    if (total_changes > 0) {
        ctx->branches_simplified += total_changes;
        deobf::log_verbose("[JumpOpt] Simplified %d conditional jumps\n", total_changes);
    }

    return total_changes;
}

//--------------------------------------------------------------------------
// Instruction-level optimization
//--------------------------------------------------------------------------

int jump_optimizer_handler_t::simplify_jcc(mblock_t* blk, minsn_t* jcc, deobf_ctx_t* ctx) {
    if (!blk || !jcc || !is_mcode_jcond(jcc->opcode))
        return 0;

    int result = rules::JumpRuleRegistry::instance().try_apply(blk, jcc);
    if (result == -1)
        return 0;  // No rule matched

    return apply_optimization(blk, jcc, result);
}

//--------------------------------------------------------------------------
// Apply optimization
//--------------------------------------------------------------------------

int jump_optimizer_handler_t::apply_optimization(mblock_t* blk, minsn_t* jcc, int result) {
    if (result == 1) {
        // Jump is always taken - convert to unconditional goto
        ea_t orig_ea = jcc->ea;

        // Get the target block
        int target_block = jcc->d.b;

        // Convert to unconditional goto
        jcc->opcode = m_goto;
        jcc->l.erase();
        jcc->r.erase();
        jcc->d.t = mop_b;
        jcc->d.b = target_block;
        jcc->ea = orig_ea;

        jumps_simplified_++;
        jumps_converted_goto_++;

        deobf::log_verbose("[JumpOpt] Converted always-taken jcc at %a to goto\n", orig_ea);
        return 1;
    }
    else if (result == 0) {
        // Jump is never taken - remove it (becomes fall-through)
        ea_t orig_ea = jcc->ea;

        // Convert to nop
        jcc->opcode = m_nop;
        jcc->l.erase();
        jcc->r.erase();
        jcc->d.erase();
        jcc->ea = orig_ea;

        jumps_simplified_++;
        jumps_removed_++;

        deobf::log_verbose("[JumpOpt] Removed never-taken jcc at %a\n", orig_ea);
        return 1;
    }

    return 0;
}

//--------------------------------------------------------------------------
// Statistics
//--------------------------------------------------------------------------

void jump_optimizer_handler_t::dump_statistics() {
    msg("[chernobog] Jump Optimizer Statistics:\n");
    msg("  Total simplified: %zu\n", jumps_simplified_);
    msg("  Converted to goto: %zu\n", jumps_converted_goto_);
    msg("  Removed (nop): %zu\n", jumps_removed_);

    rules::JumpRuleRegistry::instance().dump_statistics();
}

void jump_optimizer_handler_t::reset_statistics() {
    jumps_simplified_ = 0;
    jumps_converted_goto_ = 0;
    jumps_removed_ = 0;

    rules::JumpRuleRegistry::instance().reset_statistics();
}

} // namespace chernobog
