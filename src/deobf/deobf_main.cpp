#include "deobf_main.h"
#include "analysis/pattern_match.h"
#include "analysis/expr_simplify.h"
#include "analysis/cfg_analysis.h"
#include "analysis/opaque_eval.h"
#include "analysis/stack_tracker.h"
#include "handlers/deflatten.h"
#include "handlers/bogus_cf.h"
#include "handlers/string_decrypt.h"
#include "handlers/const_decrypt.h"
#include "handlers/indirect_branch.h"
#include "handlers/block_merge.h"
#include "handlers/mba_simplify.h"
#include "handlers/identity_call.h"
#include "handlers/stack_string.h"
#include "handlers/hikari_wrapper.h"
#include "handlers/savedregs.h"
#include "handlers/objc_resolve.h"
#include "handlers/global_const.h"
#include "handlers/ptr_resolve.h"
#include "handlers/indirect_call.h"
#include "handlers/ctree_string_decrypt.h"
#include "analysis/ast_builder.h"
#include "rules/rule_registry.h"

bool chernobog_t::s_active = false;
deobf_ctx_t chernobog_t::s_ctx;

// Forward declaration
static void run_deobfuscation_passes(mbl_array_t *mba, deobf_ctx_t *ctx);

static chernobog_t *g_deobf = nullptr;
static chernobog_optblock_t *g_optblock = nullptr;

// Track functions we've already processed to avoid duplicate analysis
static std::set<ea_t> s_processed_functions;

// Track optblock processed combinations (cleared on refresh)
static std::set<uint64_t> s_optblock_processed;

// Clear tracking for a function to allow re-deobfuscation
void chernobog_clear_function_tracking(ea_t func_ea) {
    s_processed_functions.erase(func_ea);

    // Clear all maturity combinations for this function from optblock tracking
    for (int m = 0; m < 16; m++) {
        uint64_t key = ((uint64_t)func_ea << 4) | m;
        s_optblock_processed.erase(key);
    }

    // Clear deferred analysis for all handlers
    deflatten_handler_t::clear_deferred(func_ea);
    identity_call_handler_t::clear_deferred(func_ea);
}

// Clear ALL tracking caches (called on database load if CHERNOBOG_RESET=1)
void chernobog_clear_all_tracking() {
    s_processed_functions.clear();
    s_optblock_processed.clear();
    deflatten_handler_t::s_deferred_analysis.clear();
    identity_call_handler_t::s_deferred_analysis.clear();
    msg("[chernobog] Cleared all deobfuscation caches\n");
}

//--------------------------------------------------------------------------
// File-based debug logging for optblock
//--------------------------------------------------------------------------
#include "../common/compat.h"

static void optblock_debug(const char *fmt, ...) {
#ifndef _WIN32
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    int len = qvsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    int fd = open("/tmp/optblock_debug.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        write(fd, buf, len);
        close(fd);
    }
#else
    (void)fmt;
#endif
}

//--------------------------------------------------------------------------
// Block-level optimizer callback - runs at various maturity levels
//--------------------------------------------------------------------------
int idaapi chernobog_optblock_t::func(mblock_t *blk) {
    optblock_debug("[optblock] func() called\n");
    
    // Debug: log every call to see if we're being invoked
    if (!blk || !blk->mba) {
        optblock_debug("[optblock] null blk or mba!\n");
        msg("[optblock] Called with null blk or mba\n");
        return 0;
    }

    int maturity = blk->mba->maturity;
    optblock_debug("[optblock] s_active=%d, entry_ea=%llx, maturity=%d, blk=%d\n", 
                   chernobog_t::s_active ? 1 : 0, 
                   (unsigned long long)blk->mba->entry_ea,
                   maturity,
                   blk->serial);

    if (!chernobog_t::s_active) {
        // Only log once per function to avoid spam
        static ea_t last_inactive_ea = BADADDR;
        if (blk->mba->entry_ea != last_inactive_ea) {
            last_inactive_ea = blk->mba->entry_ea;
            msg("[optblock] s_active=false, skipping %a\n", blk->mba->entry_ea);
        }
        return 0;
    }

    mbl_array_t *mba = blk->mba;
    ea_t func_ea = mba->entry_ea;
    // maturity already declared above

    // Track which function+maturity combinations we've processed to avoid duplicate work
    // Key: (func_ea << 4) | maturity (assuming maturity < 16)
    // Uses global set that can be cleared to allow re-deobfuscation
    uint64_t key = ((uint64_t)func_ea << 4) | (maturity & 0xF);

    if (s_optblock_processed.count(key)) {
        optblock_debug("[optblock] Already processed key=%llx\n", (unsigned long long)key);
        return 0;
    }
    s_optblock_processed.insert(key);

    optblock_debug("[optblock] NEW processing: maturity=%d, func=%llx\n", maturity, (unsigned long long)func_ea);
    msg("[optblock] Processing %a at maturity %d (blk %d)\n", func_ea, maturity, blk->serial);

    // Run full deobfuscation at maturity 3 (MMAT_LOCOPT) - first opportunity for CFG mods
    if (maturity == MMAT_LOCOPT) {
        optblock_debug("[optblock] Running FULL deobfuscation passes at maturity 3\n");
        deobf_ctx_t full_ctx;
        full_ctx.mba = mba;
        full_ctx.func_ea = func_ea;
        
        // First detect what obfuscations are present
        full_ctx.detected_obf = chernobog_t::detect_obfuscations(mba);
        optblock_debug("[optblock] Detected obfuscations: 0x%x\n", full_ctx.detected_obf);
        
        run_deobfuscation_passes(mba, &full_ctx);
        optblock_debug("[optblock] Full deobfuscation complete, changes: blocks=%d, branches=%d, indirect=%d\n",
                       full_ctx.blocks_merged, full_ctx.branches_simplified, full_ctx.indirect_resolved);
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

    // Process at multiple maturity levels
    // MMAT_LOCOPT (3): CFG modifications (but calls are "unknown" - no mcallinfo)
    // MMAT_CALLS (4): Call info is available - can modify indirect calls
    // MMAT_GLBOPT1 (5): Global constant inlining (addresses resolved)
    if (maturity != MMAT_LOCOPT && maturity != MMAT_CALLS && maturity != MMAT_GLBOPT1)
        return 0;
    
    // At MMAT_CALLS, specifically try to resolve indirect calls
    // This is when mcallinfo is available, making it safe to modify calls
    if (maturity == MMAT_CALLS) {
        if (indirect_call_handler_t::detect(mba)) {
            optblock_debug("[optblock] Running indirect call handler at MMAT_CALLS\n");
            msg("[optblock] Running indirect call deobfuscation at maturity %d (MMAT_CALLS)\n", maturity);
            deobf_ctx_t icall_ctx;
            icall_ctx.mba = mba;
            icall_ctx.func_ea = func_ea;
            int changes = indirect_call_handler_t::run(mba, &icall_ctx);
            if (changes > 0) {
                msg("[optblock] Resolved %d indirect calls at MMAT_CALLS\n", icall_ctx.indirect_resolved);
                return 1;  // Signal that we made changes
            }
        }
        return 0;
    }

    deobf_ctx_t ctx;
    ctx.mba = mba;
    ctx.func_ea = func_ea;

    int total_changes = 0;

    // Try global constant inlining - works better at later maturity when addresses resolved
    if (maturity >= MMAT_LOCOPT && global_const_handler_t::detect(mba)) {
        msg("[optblock] Detected global constants at maturity %d\n", maturity);
        int changes = global_const_handler_t::run(mba, &ctx);
        if (changes > 0) {
            msg("[optblock] Global const handler applied %d changes\n", changes);
            total_changes += changes;
        }
    }

    // Check for pending identity call analysis from maturity 0
    if (identity_call_handler_t::has_pending_analysis(func_ea)) {
        msg("[optblock] Applying deferred identity call transformations for %a\n", func_ea);
        int changes = identity_call_handler_t::apply_deferred(mba, &ctx);
        if (changes > 0) {
            msg("[optblock] Identity call handler applied %d changes\n", changes);
            total_changes += changes;
        }
    }

    // Check if we have pending deflattening analysis from maturity 0
    // The maturity 0 analysis uses block ADDRESSES which are stable across maturities
    if (deflatten_handler_t::has_pending_analysis(func_ea)) {
        msg("[optblock] Applying deferred analysis from maturity 0 for %a\n", func_ea);
        int changes = deflatten_handler_t::apply_deferred(mba, &ctx);
        if (changes > 0) {
            msg("[optblock] Deflattening applied %d changes from deferred analysis\n", changes);
            total_changes += changes;
        } else {
            msg("[optblock] Deferred analysis made no changes, trying fresh analysis\n");
            // Fall through to fresh analysis
        }
        // apply_deferred clears the deferred analysis, so we won't try again
        if (changes > 0)
            return total_changes;
    }

    // No deferred analysis or it didn't help - try fresh analysis at maturity 3
    if (!deflatten_handler_t::detect(mba, &ctx)) {
        msg("[optblock] No flattening detected at %a\n", func_ea);
        return 0;
    }

    msg("[optblock] Detected flattening at %a, running fresh analysis...\n", func_ea);

    // Run the full deflattening pass
    int changes = deflatten_handler_t::run(mba, &ctx);
    if (changes > 0) {
        msg("[optblock] Deflattening applied %d changes\n", changes);
    } else {
        msg("[optblock] Deflattening found patterns but made no changes\n");
    }

    return changes;
}

//--------------------------------------------------------------------------
// Constructor/Destructor
//--------------------------------------------------------------------------
chernobog_t::chernobog_t() {
}

chernobog_t::~chernobog_t() {
}

//--------------------------------------------------------------------------
// optinsn_t callback - called during microcode optimization
// This is where we do instruction-level simplification
//--------------------------------------------------------------------------
int idaapi chernobog_t::func(mblock_t *blk, minsn_t *ins, int optflags) {
    if (!blk || !ins) {
        return 0;
    }

    // Debug: log ldx instructions (opcode 14)
    if (ins->opcode == m_ldx) {
        static int ldx_count = 0;
        if (ldx_count < 20) {
            ldx_count++;
            deobf::log_verbose("[optinsn] m_ldx: r.t=%d\n", ins->r.t);
        }
    }

    int changes = 0;

    // Try global constant inlining
    changes += global_const_handler_t::simplify_insn(blk, ins, nullptr);

    // Try MBA simplification on this instruction
    changes += mba_simplify_handler_t::simplify_insn(blk, ins, nullptr);

    return changes;
}

//--------------------------------------------------------------------------
// Main deobfuscation entry point - from mba (used by auto mode)
//--------------------------------------------------------------------------
void chernobog_t::deobfuscate_mba(mbl_array_t *mba) {
    if (!mba)
        return;

    deobf::log("[chernobog] Deobfuscating %a (from mba)\n", mba->entry_ea);

    s_ctx = deobf_ctx_t();
    s_ctx.mba = mba;
    s_ctx.func_ea = mba->entry_ea;

    // Run the core deobfuscation logic
    run_deobfuscation_passes(mba, &s_ctx);
}

//--------------------------------------------------------------------------
// Main deobfuscation entry point - from cfunc
//--------------------------------------------------------------------------
void chernobog_t::deobfuscate_function(cfunc_t *cfunc) {
    if (!cfunc || !cfunc->mba)
        return;

    deobf::log("[chernobog] Deobfuscating %a\n", cfunc->entry_ea);

    s_ctx = deobf_ctx_t();
    s_ctx.mba = cfunc->mba;
    s_ctx.cfunc = cfunc;
    s_ctx.func_ea = cfunc->entry_ea;

    // Run the core deobfuscation logic
    run_deobfuscation_passes(cfunc->mba, &s_ctx);
}

//--------------------------------------------------------------------------
// Core deobfuscation passes (shared by all entry points)
//--------------------------------------------------------------------------
static void run_deobfuscation_passes(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return;

    // Detect what obfuscations are present
    ctx->detected_obf = chernobog_t::detect_obfuscations(mba);

    deobf::log("[chernobog] Detected obfuscations: 0x%x\n", ctx->detected_obf);

    if (ctx->detected_obf & OBF_STRING_ENC) {
        deobf::log("[chernobog] - String encryption detected\n");
    }
    if (ctx->detected_obf & OBF_CONST_ENC) {
        deobf::log("[chernobog] - Constant encryption detected\n");
    }
    if (ctx->detected_obf & OBF_FLATTENED) {
        deobf::log("[chernobog] - Control flow flattening detected\n");
    }
    if (ctx->detected_obf & OBF_BOGUS_CF) {
        deobf::log("[chernobog] - Bogus control flow detected\n");
    }
    if (ctx->detected_obf & OBF_INDIRECT_BR) {
        deobf::log("[chernobog] - Indirect branches detected\n");
    }
    if (ctx->detected_obf & OBF_SUBSTITUTION) {
        deobf::log("[chernobog] - Instruction substitution detected\n");
    }
    if (ctx->detected_obf & OBF_SAVEDREGS) {
        deobf::log("[chernobog] - Register demotion (savedregs) detected\n");
    }
    if (ctx->detected_obf & OBF_OBJC_OBFUSC) {
        deobf::log("[chernobog] - Obfuscated ObjC calls detected\n");
    }
    if (ctx->detected_obf & OBF_GLOBAL_CONST) {
        deobf::log("[chernobog] - Global constants detected\n");
    }
    if (ctx->detected_obf & OBF_PTR_INDIRECT) {
        deobf::log("[chernobog] - Indirect pointer references detected\n");
    }
    if (ctx->detected_obf & OBF_INDIRECT_CALL) {
        deobf::log("[chernobog] - Indirect call obfuscation detected\n");
    }

    // Initialize stack tracker for virtual stack analysis
    stack_tracker_t::analyze_function(mba);

    // Apply deobfuscation passes in order
    int total_changes = 0;

    // 1. First merge split blocks (simplest transformation)
    if (ctx->detected_obf & OBF_SPLIT_BLOCKS) {
        total_changes += chernobog_t::merge_blocks(mba, ctx);
    }

    // 2. Decrypt strings
    if (ctx->detected_obf & OBF_STRING_ENC) {
        total_changes += chernobog_t::decrypt_strings(mba, ctx);
    }

    // 2.5. Reconstruct stack strings
    if (ctx->detected_obf & OBF_STACK_STRING) {
        total_changes += stack_string_handler_t::run(mba, ctx);
    }

    // 3. Decrypt constants
    if (ctx->detected_obf & OBF_CONST_ENC) {
        total_changes += chernobog_t::decrypt_consts(mba, ctx);
    }

    // 3.5. Inline global constants
    if (ctx->detected_obf & OBF_GLOBAL_CONST) {
        total_changes += global_const_handler_t::run(mba, ctx);
    }

    // 3.6. Resolve indirect pointer references
    if (ctx->detected_obf & OBF_PTR_INDIRECT) {
        total_changes += ptr_resolve_handler_t::run(mba, ctx);
    }

    // 4. Simplify substituted expressions
    if (ctx->detected_obf & OBF_SUBSTITUTION) {
        total_changes += chernobog_t::simplify_substitutions(mba, ctx);
    }

    // 5. Resolve indirect branches
    if (ctx->detected_obf & OBF_INDIRECT_BR) {
        total_changes += chernobog_t::resolve_indirect_branches(mba, ctx);
    }

    // 5.1. Resolve indirect calls (Hikari IndirectCall obfuscation)
    if (ctx->detected_obf & OBF_INDIRECT_CALL) {
        total_changes += indirect_call_handler_t::run(mba, ctx);
    }

    // 5.5. Resolve identity function calls
    if (ctx->detected_obf & OBF_IDENTITY_CALL) {
        total_changes += identity_call_handler_t::run(mba, ctx);
    }

    // 5.6. Resolve Hikari function wrappers
    if (ctx->detected_obf & OBF_FUNC_WRAPPER) {
        total_changes += hikari_wrapper_handler_t::run(mba, ctx);
    }

    // 5.7. Resolve savedregs (register demotion) patterns
    if (ctx->detected_obf & OBF_SAVEDREGS) {
        total_changes += savedregs_handler_t::run(mba, ctx);
    }

    // 5.8. Resolve obfuscated ObjC method calls
    if (ctx->detected_obf & OBF_OBJC_OBFUSC) {
        total_changes += objc_resolve_handler_t::run(mba, ctx);
    }

    // 6. Remove bogus control flow
    if (ctx->detected_obf & OBF_BOGUS_CF) {
        total_changes += chernobog_t::remove_bogus_cf(mba, ctx);
    }

    // 7. Deflatten control flow (most complex, do last)
    if (ctx->detected_obf & OBF_FLATTENED) {
        total_changes += chernobog_t::deflatten(mba, ctx);
    }

    // 8. Ctree-level string analysis (runs on cfunc if available)
    if (ctx->cfunc) {
        int str_changes = ctree_string_decrypt_handler_t::run(ctx->cfunc, ctx);
        if (str_changes > 0) {
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
}

//--------------------------------------------------------------------------
// Deobfuscate by address
//--------------------------------------------------------------------------
void chernobog_t::deobfuscate_function(ea_t ea) {
    func_t *func = get_func(ea);
    if (!func) {
        deobf::log("[chernobog] No function at %a\n", ea);
        return;
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(func, &hf, DECOMP_NO_CACHE);
    if (!cfunc) {
        deobf::log("[chernobog] Failed to decompile %a: %s\n", ea, hf.desc().c_str());
        return;
    }

    deobfuscate_function(cfunc);
}

//--------------------------------------------------------------------------
// Analyze function without modifying
//--------------------------------------------------------------------------
void chernobog_t::analyze_function(ea_t ea) {
    func_t *func = get_func(ea);
    if (!func) {
        deobf::log("[chernobog] No function at %a\n", ea);
        return;
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(func, &hf, DECOMP_NO_CACHE);
    if (!cfunc) {
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

    if (obf & OBF_FLATTENED) msg("  - Control flow flattening\n");
    if (obf & OBF_BOGUS_CF) msg("  - Bogus control flow\n");
    if (obf & OBF_STRING_ENC) msg("  - String encryption\n");
    if (obf & OBF_CONST_ENC) msg("  - Constant encryption\n");
    if (obf & OBF_INDIRECT_BR) msg("  - Indirect branches\n");
    if (obf & OBF_SUBSTITUTION) msg("  - Instruction substitution\n");
    if (obf & OBF_SPLIT_BLOCKS) msg("  - Split basic blocks\n");
    if (obf & OBF_FUNC_WRAPPER) msg("  - Hikari function wrappers\n");
    if (obf & OBF_IDENTITY_CALL) msg("  - Identity function call obfuscation\n");
    if (obf & OBF_STACK_STRING) msg("  - Stack string construction\n");
    if (obf & OBF_SAVEDREGS) msg("  - Register demotion (savedregs patterns)\n");
    if (obf & OBF_OBJC_OBFUSC) msg("  - Obfuscated ObjC method calls\n");
    if (obf & OBF_GLOBAL_CONST) msg("  - Inlinable global constants\n");
    if (obf & OBF_PTR_INDIRECT) msg("  - Indirect pointer references\n");
    if (obf & OBF_INDIRECT_CALL) msg("  - Indirect call obfuscation (Hikari)\n");
    if (obf == OBF_NONE) msg("  - No obfuscation detected\n");
}

//--------------------------------------------------------------------------
// Detection functions
//--------------------------------------------------------------------------
uint32_t chernobog_t::detect_obfuscations(mbl_array_t *mba) {
    if (!mba)
        return OBF_NONE;

    uint32_t detected = OBF_NONE;
    deobf_ctx_t ctx;
    ctx.mba = mba;

    // Check for control flow flattening
    if (is_flattened(mba, &ctx))
        detected |= OBF_FLATTENED;

    // Check for bogus control flow
    if (has_bogus_cf(mba, &ctx))
        detected |= OBF_BOGUS_CF;

    // Check for encrypted constants (XOR patterns)
    if (has_encrypted_consts(mba))
        detected |= OBF_CONST_ENC;

    // Check for indirect branches
    if (has_indirect_branches(mba))
        detected |= OBF_INDIRECT_BR;

    // Check for instruction substitution / MBA obfuscation patterns
    if (mba_simplify_handler_t::detect(mba))
        detected |= OBF_SUBSTITUTION;

    // Check for split blocks (many small blocks with unconditional jumps)
    if (block_merge_handler_t::detect_split_blocks(mba))
        detected |= OBF_SPLIT_BLOCKS;

    // Check for identity function call obfuscation
    if (identity_call_handler_t::detect(mba))
        detected |= OBF_IDENTITY_CALL;

    // Check for stack string construction
    if (stack_string_handler_t::detect(mba))
        detected |= OBF_STACK_STRING;

    // Check for Hikari function wrappers
    if (hikari_wrapper_handler_t::detect(mba))
        detected |= OBF_FUNC_WRAPPER;

    // Check for savedregs (register demotion) patterns
    if (savedregs_handler_t::detect(mba))
        detected |= OBF_SAVEDREGS;

    // Check for obfuscated ObjC method calls
    if (objc_resolve_handler_t::detect(mba))
        detected |= OBF_OBJC_OBFUSC;

    // Check for inlinable global constants
    if (global_const_handler_t::detect(mba))
        detected |= OBF_GLOBAL_CONST;

    // Check for indirect pointer references
    if (ptr_resolve_handler_t::detect(mba))
        detected |= OBF_PTR_INDIRECT;

    // Check for indirect call obfuscation (Hikari IndirectCall)
    if (indirect_call_handler_t::detect(mba))
        detected |= OBF_INDIRECT_CALL;

    return detected;
}

bool chernobog_t::is_flattened(mbl_array_t *mba, deobf_ctx_t *ctx) {
    return deflatten_handler_t::detect(mba, ctx);
}

bool chernobog_t::has_bogus_cf(mbl_array_t *mba, deobf_ctx_t *ctx) {
    return bogus_cf_handler_t::detect(mba, ctx);
}

bool chernobog_t::has_encrypted_strings(ea_t func_ea) {
    return string_decrypt_handler_t::detect(func_ea);
}

bool chernobog_t::has_encrypted_consts(mbl_array_t *mba) {
    return const_decrypt_handler_t::detect(mba);
}

bool chernobog_t::has_indirect_branches(mbl_array_t *mba) {
    return indirect_branch_handler_t::detect(mba);
}

//--------------------------------------------------------------------------
// Deobfuscation pass wrappers
//--------------------------------------------------------------------------
int chernobog_t::deflatten(mbl_array_t *mba, deobf_ctx_t *ctx) {
    return deflatten_handler_t::run(mba, ctx);
}

int chernobog_t::remove_bogus_cf(mbl_array_t *mba, deobf_ctx_t *ctx) {
    return bogus_cf_handler_t::run(mba, ctx);
}

int chernobog_t::decrypt_strings(mbl_array_t *mba, deobf_ctx_t *ctx) {
    return string_decrypt_handler_t::run(mba, ctx);
}

int chernobog_t::decrypt_consts(mbl_array_t *mba, deobf_ctx_t *ctx) {
    return const_decrypt_handler_t::run(mba, ctx);
}

int chernobog_t::resolve_indirect_branches(mbl_array_t *mba, deobf_ctx_t *ctx) {
    return indirect_branch_handler_t::run(mba, ctx);
}

int chernobog_t::merge_blocks(mbl_array_t *mba, deobf_ctx_t *ctx) {
    return block_merge_handler_t::run(mba, ctx);
}

int chernobog_t::simplify_substitutions(mbl_array_t *mba, deobf_ctx_t *ctx) {
    return mba_simplify_handler_t::run(mba, ctx);
}

//--------------------------------------------------------------------------
// Component registration
//--------------------------------------------------------------------------
bool deobf_avail() {
    // Available on all platforms with Hex-Rays
    return true;
}

bool deobf_active() {
    return chernobog_t::s_active;
}

void deobf_init() {
    // Initialize MBA simplification (pattern matching rules)
    mba_simplify_handler_t::initialize();

    // Install instruction-level optimizer
    g_deobf = new chernobog_t();
    install_optinsn_handler(g_deobf);

    // Install block-level optimizer for CFG modifications (deflattening)
    g_optblock = new chernobog_optblock_t();
    install_optblock_handler(g_optblock);

    chernobog_t::s_active = true;
    msg("[chernobog] Deobfuscator initialized (optinsn + optblock handlers, s_active=true)\n");
}

void deobf_done() {
    chernobog_t::s_active = false;

    // Remove instruction-level optimizer
    if (g_deobf) {
        remove_optinsn_handler(g_deobf);
        delete g_deobf;
        g_deobf = nullptr;
    }

    // Remove block-level optimizer
    if (g_optblock) {
        remove_optblock_handler(g_optblock);
        delete g_optblock;
        g_optblock = nullptr;
    }

    // Clear any pending analysis
    deflatten_handler_t::s_deferred_analysis.clear();
    s_processed_functions.clear();

    // Clear AST caches (the RuleRegistry singleton intentionally leaks
    // on exit to avoid crashes during static destruction)
    chernobog::ast::clear_ast_caches();
    // NOTE: Do NOT call RuleRegistry::instance().clear() here!
    // The RuleRegistry singleton intentionally leaks to avoid crashes from
    // mop_t destructors calling IDA functions that are unavailable at shutdown.

    deobf::log("[chernobog] Deobfuscator terminated\n");
}

//--------------------------------------------------------------------------
// Action handlers for popup menu
//--------------------------------------------------------------------------
struct deobf_action_handler_t : public action_handler_t {
    int (*action_func)(vdui_t *);

    deobf_action_handler_t(int (*f)(vdui_t *)) : action_func(f) {}

    virtual int idaapi activate(action_activation_ctx_t *ctx) override {
        // Check if hexrays is available before using its API
        if (!get_hexdsp())
            return 0;
        vdui_t *vu = get_widget_vdui(ctx->widget);
        if (vu)
            return action_func(vu);
        return 0;
    }

    virtual action_state_t idaapi update(action_update_ctx_t *ctx) override {
        // Check if hexrays is available before using its API
        if (!get_hexdsp())
            return AST_DISABLE_FOR_WIDGET;
        if (!ctx || !ctx->widget)
            return AST_DISABLE_FOR_WIDGET;
        vdui_t *vu = get_widget_vdui(ctx->widget);
        return vu ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
    }
};

static int do_deobfuscate(vdui_t *vu) {
    if (!vu || !vu->cfunc)
        return 0;

    chernobog_t::deobfuscate_function(vu->cfunc);
    vu->refresh_view(true);
    return 1;
}

static int do_analyze(vdui_t *vu) {
    if (!vu || !vu->cfunc)
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

void deobf_attach_popup(TWidget *widget, TPopupMenu *popup, vdui_t *vu) {
    if (!vu)
        return;

    for (const auto &act : actions) {
        attach_action_to_popup(widget, popup, act.name);
    }
}

// Register actions on init
static struct action_registrar_t {
    action_registrar_t() {
        for (const auto &act : actions) {
            register_action(act);
        }
    }
    ~action_registrar_t() {
        for (const auto &act : actions) {
            unregister_action(act.name);
        }
    }
} g_action_registrar;

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
