#include "deobf_main.h"
#include "analysis/opaque_eval.h"
#include "handlers/deflatten.h"
#include "handlers/bogus_cf.h"
#include "handlers/string_decrypt.h"
#include "handlers/const_decrypt.h"
#include "handlers/indirect_branch.h"
#include "handlers/block_merge.h"
#include "handlers/select_chain.h"
#include "handlers/mba_simplify.h"
#include "handlers/vm_mba.h"
#include "handlers/identity_call.h"
#include "handlers/stack_string.h"
#include "handlers/hikari_wrapper.h"
#include "handlers/savedregs.h"
#include "handlers/objc_resolve.h"
#include "handlers/global_const.h"
#include "handlers/ptr_resolve.h"
#include "handlers/indirect_call.h"
#include "handlers/ctree_string_decrypt.h"
#include "rules/rule_registry.h"
#include "../hybrid/session.hpp"
#include "../hybrid/z3_bridge.hpp"

// Forward declaration
static int run_deobfuscation_passes(mbl_array_t *mba, deobf_ctx_t *ctx);

static void ensure_current_function_explored(ea_t function_ea)
{
    const chernobog::hybrid::EnsureExploredResult result =
        chernobog::hybrid::hybrid_ensure_current_function_explored(
            uint64_t(function_ea));
    if ( result == chernobog::hybrid::EnsureExploredResult::FAILED
      || result == chernobog::hybrid::EnsureExploredResult::CANCELLED )
    {
        deobf::log("[chernobog][rax] Pre-deobfuscation exploration for %a did not produce fresh evidence; continuing without rax evidence\n",
                   function_ea);
    }
}

struct deobf_module_state_t
{
    chernobog_t *deobf = nullptr;
    chernobog_optblock_t *optblock = nullptr;
    bool active = false;
    ea_t last_inactive_ea = BADADDR;
    std::set<std::pair<ea_t, int>> optblock_processed;
};

// IDA stores one pointer for this data ID in each database context.
static int s_deobf_data_id = 0;

static deobf_module_state_t *get_deobf_state()
{
    if ( s_deobf_data_id == 0 || get_dbctx_id() < 0 )
        return nullptr;
    return static_cast<deobf_module_state_t *>(get_module_data(s_deobf_data_id));
}

static void register_deobf_actions();
static void unregister_deobf_actions();

// Clear tracking for a function to allow re-deobfuscation
void chernobog_clear_function_tracking(ea_t func_ea)
{
    deobf_module_state_t *state = get_deobf_state();

    // Clear all maturity combinations for this function from optblock tracking
    if ( state != nullptr )
    {
        for ( int m = 0; m < 16; ++m )
            state->optblock_processed.erase({func_ea, m});
    }

    // Clear deferred analysis for all handlers
    deflatten_handler_t::clear_deferred(func_ea);
    identity_call_handler_t::clear_caches();
    vm_mba_handler_t::clear_function(func_ea);
}

bool chernobog_function_requires_deobfuscation(ea_t func_ea)
{
    const deobf_module_state_t *state = get_deobf_state();
    return state != nullptr && state->active
        && state->optblock_processed.count({func_ea, MMAT_LOCOPT}) == 0;
}

void chernobog_mark_function_deobfuscated(ea_t func_ea)
{
    deobf_module_state_t *state = get_deobf_state();
    if ( state != nullptr )
        state->optblock_processed.insert({func_ea, MMAT_LOCOPT});
    chernobog::hybrid::hybrid_seal_deobfuscation_projection(
        uint64_t(func_ea));
}

// Clear ALL tracking caches (called on database load if CHERNOBOG_RESET=1)
void chernobog_clear_all_tracking()
{
    deobf_module_state_t *state = get_deobf_state();
    if ( state != nullptr )
        state->optblock_processed.clear();
    deflatten_handler_t::s_deferred_analysis.clear();
    identity_call_handler_t::clear_caches();
    hikari_wrapper_handler_t::clear_cache();
    opaque_eval_t::clear_cache();
    vm_mba_handler_t::clear();
    global_const_handler_t::clear_cache();
    deobf::log_verbose("[chernobog] Cleared all deobfuscation caches\n");
}

//--------------------------------------------------------------------------
// File-based debug logging for optblock
//--------------------------------------------------------------------------
#include "../common/compat.h"

static void optblock_debug(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    deobf::debug_vlog("/tmp/optblock_debug.log", fmt, args);
    va_end(args);
}

//--------------------------------------------------------------------------
// Block-level optimizer callback - runs at various maturity levels
//--------------------------------------------------------------------------
int idaapi chernobog_optblock_t::func(mblock_t *blk)
{
    optblock_debug("[optblock] func() called\n");

    // Debug: log every call to see if we're being invoked
    if ( !blk || !blk->mba )
    {
        optblock_debug("[optblock] null blk or mba!\n");
        msg("[optblock] Called with null blk or mba\n");
        return 0;
    }

    int maturity = blk->mba->maturity;
    deobf_module_state_t *state = get_deobf_state();
    const bool active = state != nullptr && state->active;
    optblock_debug("[optblock] active=%d, entry_ea=%llx, maturity=%d, blk=%d\n",
                   active ? 1 : 0,
                   (unsigned long long)blk->mba->entry_ea,
                   maturity,
                   blk->serial);

    if ( !active )
    {
        // Only log once per function to avoid spam
        if ( state != nullptr && blk->mba->entry_ea != state->last_inactive_ea )
        {
            state->last_inactive_ea = blk->mba->entry_ea;
            msg("[optblock] inactive, skipping %a\n", blk->mba->entry_ea);
        }
        return 0;
    }

    mbl_array_t *mba = blk->mba;
    ea_t func_ea = mba->entry_ea;
    // maturity already declared above

    if ( maturity != MMAT_LOCOPT && maturity != MMAT_CALLS &&
         maturity != MMAT_GLBOPT1 && maturity != MMAT_GLBOPT2 )
        return 0;

    // Track which function+maturity combinations we've processed to avoid duplicate work
    const auto key = std::make_pair(func_ea, maturity);

    if ( state->optblock_processed.count(key) )
    {
        optblock_debug("[optblock] Already processed %llx/%d\n",
                       (unsigned long long)func_ea, maturity);
        return 0;
    }
    state->optblock_processed.insert(key);

    optblock_debug("[optblock] NEW processing: maturity=%d, func=%llx\n", maturity, (unsigned long long)func_ea);
    deobf::log_verbose("[optblock] Processing %a at maturity %d (blk %d)\n",
                       func_ea, maturity, blk->serial);

    // Run full deobfuscation at maturity 3 (MMAT_LOCOPT) - first opportunity for CFG mods
    if ( maturity == MMAT_LOCOPT )
    {
        optblock_debug("[optblock] Running FULL deobfuscation passes at maturity 3\n");
        deobf_ctx_t full_ctx;
        full_ctx.mba = mba;
        full_ctx.func_ea = func_ea;

        const int full_changes = run_deobfuscation_passes(mba, &full_ctx);
        // The prerequisite captured the pre-pass identity. Preserve only the
        // display-only runtime plaintext projection across the exact bytes
        // written by this trusted pass; proof consumers remain fail-closed.
        chernobog::hybrid::hybrid_seal_deobfuscation_projection(
            uint64_t(func_ea));
        optblock_debug("[optblock] Detected obfuscations: 0x%x\n", full_ctx.detected_obf);
        optblock_debug("[optblock] Full deobfuscation complete, changes: blocks=%d, branches=%d, indirect=%d\n",
                       full_ctx.blocks_merged, full_ctx.branches_simplified, full_ctx.indirect_resolved);
        // The complete pass already includes global-constant and deflattening
        // handlers. Report its mutations to Hex-Rays and do not run those
        // handlers a second time on the same microcode maturity.
        return full_changes;
    }

    // Two-phase deflattening approach:
    //
    // NOTE: optblock handlers are typically NOT called at maturity 0.
    // IDA only starts invoking optblock at MMAT_LOCOPT (3) and above.
    //
    // So we do both analysis and application at maturity 3 (MMAT_LOCOPT),
    // which is the earliest maturity where optblock is invoked and where
    // the CFG is stable enough for modification.
    //
    // At maturity 3, the state machine patterns are still visible (switch/case
    // with state constants), but the CFG has explicit gotos that can be modified.

    // At MMAT_CALLS, specifically try to resolve indirect calls
    // This is when mcallinfo is available, making it safe to modify calls
    if ( maturity == MMAT_CALLS )
    {
        deobf_ctx_t icall_ctx;
        icall_ctx.mba = mba;
        icall_ctx.func_ea = func_ea;

        int total_changes = 0;
        if ( vm_mba_handler_t::detect(mba) )
            total_changes += vm_mba_handler_t::run(mba, &icall_ctx);

        if ( indirect_call_handler_t::detect(mba) )
        {
            optblock_debug("[optblock] Running indirect call handler at MMAT_CALLS\n");
            deobf::log_verbose("[optblock] Running indirect call deobfuscation "
                               "at maturity %d (MMAT_CALLS)\n", maturity);
            int changes = indirect_call_handler_t::run(mba, &icall_ctx);
            if ( changes > 0 )
            {
                deobf::log_verbose("[optblock] Resolved %d indirect calls at MMAT_CALLS\n",
                                   icall_ctx.indirect_resolved);
                total_changes += changes;
            }
        }
        return total_changes;
    }

    if ( maturity == MMAT_GLBOPT2 )
    {
        deobf_ctx_t late_ctx;
        late_ctx.mba = mba;
        late_ctx.func_ea = func_ea;
        int late_changes = 0;
        if ( vm_mba_handler_t::detect(mba) )
        {
            late_changes += vm_mba_handler_t::run(mba, &late_ctx);
            vm_mba_handler_t::dump_summary(func_ea);
        }
        if ( mba_simplify_handler_t::detect(mba) )
            late_changes += mba_simplify_handler_t::run(mba, &late_ctx);
        return late_changes;
    }

    deobf_ctx_t ctx;
    ctx.mba = mba;
    ctx.func_ea = func_ea;

    int total_changes = 0;

    // Try global constant inlining - works better at later maturity when addresses resolved
    if ( maturity >= MMAT_LOCOPT && global_const_handler_t::detect(mba) )
    {
        deobf::log_verbose("[optblock] Detected global constants at maturity %d\n",
                           maturity);
        int changes = global_const_handler_t::run(mba, &ctx);
        if ( changes > 0 )
        {
            deobf::log_verbose("[optblock] Global const handler applied %d changes\n",
                               changes);
            total_changes += changes;
        }
    }

    // Check for pending identity call analysis from maturity 0
    if ( identity_call_handler_t::has_pending_analysis(func_ea) )
    {
        deobf::log_verbose("[optblock] Applying deferred identity call transformations for %a\n",
                           func_ea);
        int changes = identity_call_handler_t::apply_deferred(mba, &ctx);
        if ( changes > 0 )
        {
            deobf::log_verbose("[optblock] Identity call handler applied %d changes\n",
                               changes);
            total_changes += changes;
        }
    }

    // Check if we have pending deflattening analysis from maturity 0
    // The maturity 0 analysis uses block ADDRESSES which are stable across maturities
    if ( deflatten_handler_t::has_pending_analysis(func_ea) )
    {
        deobf::log_verbose("[optblock] Applying deferred analysis from maturity 0 for %a\n",
                           func_ea);
        int changes = deflatten_handler_t::apply_deferred(mba, &ctx);
        if ( changes > 0 )
        {
            deobf::log_verbose("[optblock] Deflattening applied %d changes from deferred analysis\n",
                               changes);
            total_changes += changes;
        }
        else
        {
            deobf::log_verbose("[optblock] Deferred analysis made no changes, "
                               "trying fresh analysis\n");
            // Fall through to fresh analysis
        }
        // apply_deferred clears the deferred analysis, so we won't try again
        if ( changes > 0 )
            return total_changes;
    }

    // No deferred analysis or it didn't help - try fresh analysis at maturity 3
    if ( !deflatten_handler_t::detect(mba, &ctx) )
    {
        deobf::log_verbose("[optblock] No flattening detected at %a\n", func_ea);
        return 0;
    }

    deobf::log_verbose("[optblock] Detected flattening at %a, running fresh analysis...\n",
                       func_ea);

    // Run the full deflattening pass
    int changes = deflatten_handler_t::run(mba, &ctx);
    if ( changes > 0 )
    {
        deobf::log_verbose("[optblock] Deflattening applied %d changes\n", changes);
    }
    else
    {
        deobf::log_verbose("[optblock] Deflattening found patterns but made no changes\n");
    }

    return changes;
}

//--------------------------------------------------------------------------
// Constructor/Destructor
//--------------------------------------------------------------------------
chernobog_t::chernobog_t()
{
}

chernobog_t::~chernobog_t()
{
}

//--------------------------------------------------------------------------
// optinsn_t callback - called during microcode optimization
// This is where we do instruction-level simplification
//--------------------------------------------------------------------------
int idaapi chernobog_t::func(mblock_t *blk, minsn_t *ins, int optflags)
{
    if ( !blk || !ins )
    {
        return 0;
    }

    // Debug: log ldx instructions (opcode 14)
    if ( ins->opcode == m_ldx )
    {
        static int ldx_count = 0;
        if ( ldx_count < 20 )
        {
            ++ldx_count;
            deobf::log_verbose("[optinsn] m_ldx: r.t=%d\n", ins->r.t);
        }
    }

    int changes = 0;

    // Try global constant inlining
    changes += global_const_handler_t::simplify_insn(blk, ins, nullptr);

    // VM rewrites are restricted to functions structurally admitted by the
    // opt-in detector at an earlier block maturity.
    changes += vm_mba_handler_t::simplify_insn(blk, ins, nullptr);

    // Try MBA simplification on this instruction
    changes += mba_simplify_handler_t::simplify_insn(blk, ins, nullptr);

    return changes;
}

//--------------------------------------------------------------------------
// Main deobfuscation entry point - from mba (used by auto mode)
//--------------------------------------------------------------------------
void chernobog_t::deobfuscate_mba(mbl_array_t *mba)
{
    if ( !mba )
        return;

    if ( !chernobog_function_requires_deobfuscation(mba->entry_ea) )
    {
        deobf::log("[chernobog] Function %a already has a completed deobfuscation pass; duplicate request skipped\n",
                   mba->entry_ea);
        return;
    }

    ensure_current_function_explored(mba->entry_ea);
    deobf::log("[chernobog] Deobfuscating %a (from mba)\n", mba->entry_ea);

    deobf_ctx_t ctx;
    ctx.mba = mba;
    ctx.func_ea = mba->entry_ea;

    // Run the core deobfuscation logic
    run_deobfuscation_passes(mba, &ctx);
    chernobog_mark_function_deobfuscated(mba->entry_ea);
}

//--------------------------------------------------------------------------
// Main deobfuscation entry point - from cfunc
//--------------------------------------------------------------------------
void chernobog_t::deobfuscate_function(cfunc_t *cfunc)
{
    if ( !cfunc || !cfunc->mba )
        return;

    if ( !chernobog_function_requires_deobfuscation(cfunc->entry_ea) )
    {
        deobf_ctx_t ctree_ctx;
        ctree_ctx.mba = cfunc->mba;
        ctree_ctx.cfunc = cfunc;
        ctree_ctx.func_ea = cfunc->entry_ea;
        const int ctree_changes = ctree_string_decrypt_handler_t::run(
            cfunc, &ctree_ctx);
        deobf::log("[chernobog] Function %a already has a completed MBA pass; skipped duplicate byte/CFG transformations and applied %d ctree string literals\n",
                   cfunc->entry_ea, ctree_changes);
        return;
    }

    ensure_current_function_explored(cfunc->entry_ea);
    deobf::log("[chernobog] Deobfuscating %a\n", cfunc->entry_ea);

    deobf_ctx_t ctx;
    ctx.mba = cfunc->mba;
    ctx.cfunc = cfunc;
    ctx.func_ea = cfunc->entry_ea;

    // Run the core deobfuscation logic
    run_deobfuscation_passes(cfunc->mba, &ctx);
    chernobog_mark_function_deobfuscated(cfunc->entry_ea);
}

//--------------------------------------------------------------------------
// Core deobfuscation passes (shared by all entry points)
//--------------------------------------------------------------------------
static int run_deobfuscation_passes(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx )
        return 0;

    // Database bytes can be patched by string/constant handlers. Restrict
    // global-value memoization to one coherent pass.
    opaque_eval_t::clear_cache();

    // Detect what obfuscations are present
    ctx->detected_obf = chernobog_t::detect_obfuscations(mba);

    deobf::log("[chernobog] Detected obfuscations: 0x%x\n", ctx->detected_obf);

    if ( ctx->detected_obf & OBF_STRING_ENC )
    {
        deobf::log("[chernobog] - String encryption detected\n");
    }
    if ( ctx->detected_obf & OBF_CONST_ENC )
    {
        deobf::log("[chernobog] - Constant encryption detected\n");
    }
    if ( ctx->detected_obf & OBF_FLATTENED )
    {
        deobf::log("[chernobog] - Control flow flattening detected\n");
    }
    if ( ctx->detected_obf & OBF_BOGUS_CF )
    {
        deobf::log("[chernobog] - Bogus control flow detected\n");
    }
    if ( ctx->detected_obf & OBF_INDIRECT_BR )
    {
        deobf::log("[chernobog] - Indirect branches detected\n");
    }
    if ( ctx->detected_obf & OBF_SUBSTITUTION )
    {
        deobf::log("[chernobog] - Instruction substitution detected\n");
    }
    if ( ctx->detected_obf & OBF_SAVEDREGS )
    {
        deobf::log("[chernobog] - Register demotion (savedregs) detected\n");
    }
    if ( ctx->detected_obf & OBF_OBJC_OBFUSC )
    {
        deobf::log("[chernobog] - Obfuscated ObjC calls detected\n");
    }
    if ( ctx->detected_obf & OBF_GLOBAL_CONST )
    {
        deobf::log("[chernobog] - Global constants detected\n");
    }
    if ( ctx->detected_obf & OBF_PTR_INDIRECT )
    {
        deobf::log("[chernobog] - Indirect pointer references detected\n");
    }
    if ( ctx->detected_obf & OBF_INDIRECT_CALL )
    {
        deobf::log("[chernobog] - Indirect call obfuscation detected\n");
    }
    if ( ctx->detected_obf & OBF_VM_MBA )
    {
        deobf::log("[chernobog] - VM-family MBA handler detected\n");
    }
    if ( ctx->detected_obf & OBF_SELECT_CHAIN )
    {
        deobf::log("[chernobog] - Long select chain detected\n");
    }

    // Apply deobfuscation passes in order
    int total_changes = 0;

    // Collapse compiler-lowered select cascades before general CFG passes.
    // This prevents thousands of two-way blocks from reaching ctree.
    if ( ctx->detected_obf & OBF_SELECT_CHAIN )
    {
        total_changes += select_chain_handler_t::run(mba, ctx);
    }

    if ( ctx->detected_obf & OBF_VM_MBA )
    {
        total_changes += vm_mba_handler_t::run(mba, ctx);
    }

    // 1. First merge split blocks (simplest transformation)
    if ( ctx->detected_obf & OBF_SPLIT_BLOCKS )
    {
        total_changes += chernobog_t::merge_blocks(mba, ctx);
    }

    // 2. Decrypt strings
    if ( ctx->detected_obf & OBF_STRING_ENC )
    {
        total_changes += chernobog_t::decrypt_strings(mba, ctx);
    }

    // 2.5. Reconstruct stack strings
    if ( ctx->detected_obf & OBF_STACK_STRING )
    {
        total_changes += stack_string_handler_t::run(mba, ctx);
    }

    // 3. Decrypt constants
    if ( ctx->detected_obf & OBF_CONST_ENC )
    {
        total_changes += chernobog_t::decrypt_consts(mba, ctx);
    }

    // 3.5. Inline global constants
    if ( ctx->detected_obf & OBF_GLOBAL_CONST )
    {
        total_changes += global_const_handler_t::run(mba, ctx);
    }
    total_changes += global_const_handler_t::remove_write_only_stores(mba);

    // 3.6. Resolve indirect pointer references
    if ( ctx->detected_obf & OBF_PTR_INDIRECT )
    {
        total_changes += ptr_resolve_handler_t::run(mba, ctx);
    }

    // 4. Simplify substituted expressions
    if ( ctx->detected_obf & OBF_SUBSTITUTION )
    {
        total_changes += chernobog_t::simplify_substitutions(mba, ctx);
    }

    // 5. Resolve indirect branches
    if ( ctx->detected_obf & OBF_INDIRECT_BR )
    {
        total_changes += chernobog_t::resolve_indirect_branches(mba, ctx);
    }

    // 5.1. Resolve indirect calls (Hikari IndirectCall obfuscation)
    if ( ctx->detected_obf & OBF_INDIRECT_CALL )
    {
        total_changes += indirect_call_handler_t::run(mba, ctx);
    }

    // 5.5. Resolve identity function calls
    if ( ctx->detected_obf & OBF_IDENTITY_CALL )
    {
        total_changes += identity_call_handler_t::run(mba, ctx);
    }

    // 5.6. Resolve Hikari function wrappers
    if ( ctx->detected_obf & OBF_FUNC_WRAPPER )
    {
        total_changes += hikari_wrapper_handler_t::run(mba, ctx);
    }

    // 5.7. Resolve savedregs (register demotion) patterns
    if ( ctx->detected_obf & OBF_SAVEDREGS )
    {
        total_changes += savedregs_handler_t::run(mba, ctx);
    }

    // 5.8. Resolve obfuscated ObjC method calls
    if ( ctx->detected_obf & OBF_OBJC_OBFUSC )
    {
        total_changes += objc_resolve_handler_t::run(mba, ctx);
    }

    // 6. Remove bogus control flow
    if ( ctx->detected_obf & OBF_BOGUS_CF )
    {
        total_changes += chernobog_t::remove_bogus_cf(mba, ctx);
    }

    // 7. Deflatten control flow (most complex, do last)
    if ( ctx->detected_obf & OBF_FLATTENED )
    {
        total_changes += chernobog_t::deflatten(mba, ctx);
    }

    // 8. Ctree-level string analysis (runs on cfunc if available)
    if ( ctx->cfunc )
    {
        // Manual deobfuscation operates on the cfunc that entered this pass.
        // Seal after all MBA/byte handlers, before its ctree phase, so runtime
        // literals are available in this first pass as well as in the refresh
        // requested by the action handler.
        chernobog::hybrid::hybrid_seal_deobfuscation_projection(
            uint64_t(ctx->func_ea));
        int str_changes = ctree_string_decrypt_handler_t::run(ctx->cfunc, ctx);
        if ( str_changes > 0 )
        {
            total_changes += str_changes;
            deobf::log("[chernobog] Ctree string analysis: %d strings found\n", str_changes);
        }
    }

    deobf::log("[chernobog] Deobfuscation complete. Total changes: %d\n", total_changes);
    deobf::log("[chernobog]   Blocks merged: %d\n", ctx->blocks_merged);
    deobf::log("[chernobog]   Branches simplified: %d\n", ctx->branches_simplified);
    deobf::log("[chernobog]   Strings decrypted: %d\n", ctx->strings_decrypted);
    deobf::log("[chernobog]   Constants decrypted: %d\n", ctx->consts_decrypted);
    deobf::log("[chernobog]   Expressions simplified: %d\n", ctx->expressions_simplified);
    deobf::log("[chernobog]   Indirect calls resolved: %d\n", ctx->indirect_resolved);
    return total_changes;
}

//--------------------------------------------------------------------------
// Deobfuscate by address
//--------------------------------------------------------------------------
void chernobog_t::deobfuscate_function(ea_t ea)
{
    func_t *func = get_func(ea);
    if ( !func )
    {
        deobf::log("[chernobog] No function at %a\n", ea);
        return;
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(func, &hf, DECOMP_NO_CACHE);
    if ( !cfunc )
    {
        deobf::log("[chernobog] Failed to decompile %a: %s\n", ea, hf.desc().c_str());
        return;
    }

    deobfuscate_function(cfunc);
}

//--------------------------------------------------------------------------
// Analyze function without modifying
//--------------------------------------------------------------------------
void chernobog_t::analyze_function(ea_t ea)
{
    func_t *func = get_func(ea);
    if ( !func )
    {
        deobf::log("[chernobog] No function at %a\n", ea);
        return;
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(func, &hf, DECOMP_NO_CACHE);
    if ( !cfunc )
    {
        deobf::log("[chernobog] Failed to decompile %a: %s\n", ea, hf.desc().c_str());
        return;
    }

    deobf_ctx_t ctx;
    ctx.mba = cfunc->mba;
    ctx.cfunc = cfunc;
    ctx.func_ea = ea;

    uint32_t obf = detect_obfuscations(cfunc->mba);

    msg("[chernobog] Analysis of %a:\n", ea);
    msg("  Detected obfuscations: 0x%x\n", obf);

    if ( obf & OBF_FLATTENED ) msg("  - Control flow flattening\n");
    if ( obf & OBF_BOGUS_CF ) msg("  - Bogus control flow\n");
    if ( obf & OBF_STRING_ENC ) msg("  - String encryption\n");
    if ( obf & OBF_CONST_ENC ) msg("  - Constant encryption\n");
    if ( obf & OBF_INDIRECT_BR ) msg("  - Indirect branches\n");
    if ( obf & OBF_SUBSTITUTION ) msg("  - Instruction substitution\n");
    if ( obf & OBF_SPLIT_BLOCKS ) msg("  - Split basic blocks\n");
    if ( obf & OBF_FUNC_WRAPPER ) msg("  - Hikari function wrappers\n");
    if ( obf & OBF_IDENTITY_CALL ) msg("  - Identity function call obfuscation\n");
    if ( obf & OBF_STACK_STRING ) msg("  - Stack string construction\n");
    if ( obf & OBF_SAVEDREGS ) msg("  - Register demotion (savedregs patterns)\n");
    if ( obf & OBF_OBJC_OBFUSC ) msg("  - Obfuscated ObjC method calls\n");
    if ( obf & OBF_GLOBAL_CONST ) msg("  - Inlinable global constants\n");
    if ( obf & OBF_PTR_INDIRECT ) msg("  - Indirect pointer references\n");
    if ( obf & OBF_INDIRECT_CALL ) msg("  - Indirect call obfuscation (Hikari)\n");
    if ( obf & OBF_VM_MBA ) msg("  - VM-family MBA handler\n");
    if ( obf & OBF_SELECT_CHAIN ) msg("  - Long select/cmov chain\n");
    if ( obf == OBF_NONE ) msg("  - No obfuscation detected\n");
}

//--------------------------------------------------------------------------
// Detection functions
//--------------------------------------------------------------------------
uint32_t chernobog_t::detect_obfuscations(mbl_array_t *mba)
{
    if ( !mba )
        return OBF_NONE;

    uint32_t detected = OBF_NONE;
    deobf_ctx_t ctx;
    ctx.mba = mba;

    // Check for control flow flattening
    if ( is_flattened(mba, &ctx) )
        detected |= OBF_FLATTENED;

    // Check for bogus control flow
    if ( has_bogus_cf(mba, &ctx) )
        detected |= OBF_BOGUS_CF;

    if ( has_encrypted_strings(mba) )
        detected |= OBF_STRING_ENC;

    // Check for encrypted constants (XOR patterns)
    if ( has_encrypted_consts(mba) )
        detected |= OBF_CONST_ENC;

    // Check for indirect branches
    if ( has_indirect_branches(mba) )
        detected |= OBF_INDIRECT_BR;

    // Check for instruction substitution / MBA obfuscation patterns
    if ( mba_simplify_handler_t::detect(mba) )
        detected |= OBF_SUBSTITUTION;

    // Check for split blocks (many small blocks with unconditional jumps)
    if ( block_merge_handler_t::detect_split_blocks(mba) )
        detected |= OBF_SPLIT_BLOCKS;

    // Check for identity function call obfuscation
    if ( identity_call_handler_t::detect(mba) )
        detected |= OBF_IDENTITY_CALL;

    // Check for stack string construction
    if ( stack_string_handler_t::detect(mba) )
        detected |= OBF_STACK_STRING;

    // Check for Hikari function wrappers
    if ( hikari_wrapper_handler_t::detect(mba) )
        detected |= OBF_FUNC_WRAPPER;

    // Check for savedregs (register demotion) patterns
    if ( savedregs_handler_t::detect(mba) )
        detected |= OBF_SAVEDREGS;

    // Check for obfuscated ObjC method calls
    if ( objc_resolve_handler_t::detect(mba) )
        detected |= OBF_OBJC_OBFUSC;

    // Check for inlinable global constants
    if ( global_const_handler_t::detect(mba) )
        detected |= OBF_GLOBAL_CONST;

    // Check for indirect pointer references
    if ( ptr_resolve_handler_t::detect(mba) )
        detected |= OBF_PTR_INDIRECT;

    // Check for indirect call obfuscation (Hikari IndirectCall)
    if ( indirect_call_handler_t::detect(mba) )
        detected |= OBF_INDIRECT_CALL;

    if ( vm_mba_handler_t::detect(mba) )
        detected |= OBF_VM_MBA;

    if ( select_chain_handler_t::detect(mba) )
        detected |= OBF_SELECT_CHAIN;

    return detected;
}

bool chernobog_t::is_flattened(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    return deflatten_handler_t::detect(mba, ctx);
}

bool chernobog_t::has_bogus_cf(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    return bogus_cf_handler_t::detect(mba, ctx);
}

bool chernobog_t::has_encrypted_strings(mbl_array_t *mba)
{
    return string_decrypt_handler_t::detect(mba);
}

bool chernobog_t::has_encrypted_consts(mbl_array_t *mba)
{
    return const_decrypt_handler_t::detect(mba);
}

bool chernobog_t::has_indirect_branches(mbl_array_t *mba)
{
    return indirect_branch_handler_t::detect(mba);
}

//--------------------------------------------------------------------------
// Deobfuscation pass wrappers
//--------------------------------------------------------------------------
int chernobog_t::deflatten(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    return deflatten_handler_t::run(mba, ctx);
}

int chernobog_t::remove_bogus_cf(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    return bogus_cf_handler_t::run(mba, ctx);
}

int chernobog_t::decrypt_strings(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    return string_decrypt_handler_t::run(mba, ctx);
}

int chernobog_t::decrypt_consts(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    return const_decrypt_handler_t::run(mba, ctx);
}

int chernobog_t::resolve_indirect_branches(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    return indirect_branch_handler_t::run(mba, ctx);
}

int chernobog_t::merge_blocks(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    return block_merge_handler_t::run(mba, ctx);
}

int chernobog_t::simplify_substitutions(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    return mba_simplify_handler_t::run(mba, ctx);
}

//--------------------------------------------------------------------------
// Component registration
//--------------------------------------------------------------------------
bool deobf_avail()
{
    // Available on all platforms with Hex-Rays
    return true;
}

bool deobf_active()
{
    deobf_module_state_t *state = get_deobf_state();
    return state != nullptr && state->active;
}

void deobf_init()
{
    if ( get_deobf_state() != nullptr )
        return;

    deobf_module_state_t *state = new deobf_module_state_t();
    set_module_data(&s_deobf_data_id, state);

    // Initialize MBA simplification (pattern matching rules)
    mba_simplify_handler_t::initialize();

    // Install instruction-level optimizer
    state->deobf = new chernobog_t();
    install_optinsn_handler(state->deobf);

    // Install block-level optimizer for CFG modifications (deflattening)
    state->optblock = new chernobog_optblock_t();
    install_optblock_handler(state->optblock);

    register_deobf_actions();

    state->active = true;
    msg("[chernobog] Deobfuscator initialized (optinsn + optblock handlers, active=true)\n");
}

void deobf_done()
{
    deobf_module_state_t *state = get_deobf_state();
    if ( state == nullptr )
        return;

    state->active = false;
    unregister_deobf_actions();

    // Remove instruction-level optimizer
    if ( state->deobf )
    {
        remove_optinsn_handler(state->deobf);
        delete state->deobf;
        state->deobf = nullptr;
    }

    // Remove block-level optimizer
    if ( state->optblock )
    {
        remove_optblock_handler(state->optblock);
        delete state->optblock;
        state->optblock = nullptr;
    }

    // Clear any pending analysis
    deflatten_handler_t::s_deferred_analysis.clear();
    identity_call_handler_t::clear_caches();
    vm_mba_handler_t::dump_statistics();
    vm_mba_handler_t::clear();
    global_const_handler_t::clear_cache();
    state->optblock_processed.clear();

    // NOTE: Do NOT call RuleRegistry::instance().clear() here!
    // The RuleRegistry singleton intentionally leaks to avoid crashes from
    // mop_t destructors calling IDA functions that are unavailable at shutdown.

    deobf::log("[chernobog] Deobfuscator terminated\n");

    deobf_module_state_t *removed = static_cast<deobf_module_state_t *>(
        clr_module_data(s_deobf_data_id));
    delete removed;
}

//--------------------------------------------------------------------------
// Action handlers for popup menu
//--------------------------------------------------------------------------
struct deobf_action_handler_t : public action_handler_t
{
    int (*action_func)(vdui_t *);

    deobf_action_handler_t(int (*f)(vdui_t *)) : action_func(f) {}

    virtual int idaapi activate(action_activation_ctx_t *ctx) override
    {
        // Check if hexrays is available before using its API
        if ( !get_hexdsp() )
            return 0;
        vdui_t *vu = get_widget_vdui(ctx->widget);
        if ( vu )
            return action_func(vu);
        return 0;
    }

    virtual action_state_t idaapi update(action_update_ctx_t *ctx) override
    {
        // Check if hexrays is available before using its API
        if ( !get_hexdsp() )
            return AST_DISABLE_FOR_WIDGET;
        if ( !ctx || !ctx->widget )
            return AST_DISABLE_FOR_WIDGET;
        vdui_t *vu = get_widget_vdui(ctx->widget);
        return vu ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
    }
};

static int do_deobfuscate(vdui_t *vu)
{
    if ( !vu || !vu->cfunc )
        return 0;

    const bool redo_mba = chernobog_function_requires_deobfuscation(
        vu->cfunc->entry_ea);
    chernobog_t::deobfuscate_function(vu->cfunc);
    if ( redo_mba )
        vu->refresh_view(true);
    else
        vu->refresh_ctext();
    return 1;
}

static int do_analyze(vdui_t *vu)
{
    if ( !vu || !vu->cfunc )
        return 0;

    chernobog_t::analyze_function(vu->cfunc->entry_ea);
    return 1;
}

static deobf_action_handler_t ah_deobf(do_deobfuscate);
static deobf_action_handler_t ah_analyze(do_analyze);

static const action_desc_t actions[] = {
    ACTION_DESC_LITERAL("chernobog:deobfuscate", "Deobfuscate (Chernobog)", &ah_deobf, "Ctrl+Shift+D", nullptr, -1),
    ACTION_DESC_LITERAL("chernobog:analyze", "Analyze obfuscation (Chernobog)", &ah_analyze, "Ctrl+Shift+A", nullptr, -1),
};

void deobf_attach_popup(TWidget *widget, TPopupMenu *popup, vdui_t *vu)
{
    if ( !vu )
        return;

    for ( const auto &act : actions )
    {
        attach_action_to_popup(widget, popup, act.name);
    }
}

static bool s_actions_registered = false;
static size_t s_action_users = 0;

static void register_deobf_actions()
{
    ++s_action_users;
    if ( s_action_users > 1 )
        return;
    bool registered_any = false;
    for ( const auto &act : actions )
    {
        registered_any |= register_action(act);
    }
    s_actions_registered = registered_any;
}

static void unregister_deobf_actions()
{
    if ( s_action_users == 0 )
        return;
    --s_action_users;
    if ( s_action_users != 0 || !s_actions_registered )
        return;
    for ( const auto &act : actions )
    {
        unregister_action(act.name);
    }
    s_actions_registered = false;
}

// Register component
REGISTER_COMPONENT(
    deobf_avail,
    deobf_active,
    deobf_init,
    deobf_done,
    deobf_attach_popup,
    "Chernobog",
    chernobog,
    chernobog
)
