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
#include "handlers/substitution.h"
#include "handlers/identity_call.h"
#include "handlers/stack_string.h"
#include "handlers/hikari_wrapper.h"
#include "handlers/savedregs.h"
#include "handlers/objc_resolve.h"

bool chernobog_t::s_active = false;
deobf_ctx_t chernobog_t::s_ctx;

static chernobog_t *g_deobf = nullptr;

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
    if (!s_active)
        return 0;

    int changes = 0;

    // Try to simplify substituted expressions
    changes += substitution_handler_t::simplify_insn(blk, ins, &s_ctx);

    // Try to resolve constant XOR patterns
    changes += const_decrypt_handler_t::simplify_insn(blk, ins, &s_ctx);

    return changes;
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

    // Detect what obfuscations are present
    s_ctx.detected_obf = detect_obfuscations(cfunc->mba);

    deobf::log("[chernobog] Detected obfuscations: 0x%x\n", s_ctx.detected_obf);

    if (s_ctx.detected_obf & OBF_STRING_ENC) {
        deobf::log("[chernobog] - String encryption detected\n");
    }
    if (s_ctx.detected_obf & OBF_CONST_ENC) {
        deobf::log("[chernobog] - Constant encryption detected\n");
    }
    if (s_ctx.detected_obf & OBF_FLATTENED) {
        deobf::log("[chernobog] - Control flow flattening detected\n");
    }
    if (s_ctx.detected_obf & OBF_BOGUS_CF) {
        deobf::log("[chernobog] - Bogus control flow detected\n");
    }
    if (s_ctx.detected_obf & OBF_INDIRECT_BR) {
        deobf::log("[chernobog] - Indirect branches detected\n");
    }
    if (s_ctx.detected_obf & OBF_SUBSTITUTION) {
        deobf::log("[chernobog] - Instruction substitution detected\n");
    }
    if (s_ctx.detected_obf & OBF_SAVEDREGS) {
        deobf::log("[chernobog] - Register demotion (savedregs) detected\n");
    }
    if (s_ctx.detected_obf & OBF_OBJC_OBFUSC) {
        deobf::log("[chernobog] - Obfuscated ObjC calls detected\n");
    }

    // Initialize stack tracker for virtual stack analysis
    stack_tracker_t::analyze_function(cfunc->mba);

    // Apply deobfuscation passes in order
    int total_changes = 0;

    // 1. First merge split blocks (simplest transformation)
    if (s_ctx.detected_obf & OBF_SPLIT_BLOCKS) {
        total_changes += merge_blocks(cfunc->mba, &s_ctx);
    }

    // 2. Decrypt strings
    if (s_ctx.detected_obf & OBF_STRING_ENC) {
        total_changes += decrypt_strings(cfunc->mba, &s_ctx);
    }

    // 2.5. Reconstruct stack strings
    if (s_ctx.detected_obf & OBF_STACK_STRING) {
        total_changes += stack_string_handler_t::run(cfunc->mba, &s_ctx);
    }

    // 3. Decrypt constants
    if (s_ctx.detected_obf & OBF_CONST_ENC) {
        total_changes += decrypt_consts(cfunc->mba, &s_ctx);
    }

    // 4. Simplify substituted expressions
    if (s_ctx.detected_obf & OBF_SUBSTITUTION) {
        total_changes += simplify_substitutions(cfunc->mba, &s_ctx);
    }

    // 5. Resolve indirect branches
    if (s_ctx.detected_obf & OBF_INDIRECT_BR) {
        total_changes += resolve_indirect_branches(cfunc->mba, &s_ctx);
    }

    // 5.5. Resolve identity function calls
    if (s_ctx.detected_obf & OBF_IDENTITY_CALL) {
        total_changes += identity_call_handler_t::run(cfunc->mba, &s_ctx);
    }

    // 5.6. Resolve Hikari function wrappers
    if (s_ctx.detected_obf & OBF_FUNC_WRAPPER) {
        total_changes += hikari_wrapper_handler_t::run(cfunc->mba, &s_ctx);
    }

    // 5.7. Resolve savedregs (register demotion) patterns
    if (s_ctx.detected_obf & OBF_SAVEDREGS) {
        total_changes += savedregs_handler_t::run(cfunc->mba, &s_ctx);
    }

    // 5.8. Resolve obfuscated ObjC method calls
    if (s_ctx.detected_obf & OBF_OBJC_OBFUSC) {
        total_changes += objc_resolve_handler_t::run(cfunc->mba, &s_ctx);
    }

    // 6. Remove bogus control flow
    if (s_ctx.detected_obf & OBF_BOGUS_CF) {
        total_changes += remove_bogus_cf(cfunc->mba, &s_ctx);
    }

    // 7. Deflatten control flow (most complex, do last)
    if (s_ctx.detected_obf & OBF_FLATTENED) {
        total_changes += deflatten(cfunc->mba, &s_ctx);
    }

    deobf::log("[chernobog] Deobfuscation complete. Total changes: %d\n", total_changes);
    deobf::log("[chernobog]   Blocks merged: %d\n", s_ctx.blocks_merged);
    deobf::log("[chernobog]   Branches simplified: %d\n", s_ctx.branches_simplified);
    deobf::log("[chernobog]   Strings decrypted: %d\n", s_ctx.strings_decrypted);
    deobf::log("[chernobog]   Constants decrypted: %d\n", s_ctx.consts_decrypted);
    deobf::log("[chernobog]   Expressions simplified: %d\n", s_ctx.expressions_simplified);
    deobf::log("[chernobog]   Indirect calls resolved: %d\n", s_ctx.indirect_resolved);
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

    // Check for instruction substitution patterns
    if (substitution_handler_t::detect(mba))
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
    return substitution_handler_t::run(mba, ctx);
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
    g_deobf = new chernobog_t();
    install_optinsn_handler(g_deobf);
    chernobog_t::s_active = true;
    deobf::log("[chernobog] Deobfuscator initialized\n");
}

void deobf_done() {
    chernobog_t::s_active = false;
    if (g_deobf) {
        remove_optinsn_handler(g_deobf);
        delete g_deobf;
        g_deobf = nullptr;
    }
    deobf::log("[chernobog] Deobfuscator terminated\n");
}

//--------------------------------------------------------------------------
// Action handlers for popup menu
//--------------------------------------------------------------------------
struct deobf_action_handler_t : public action_handler_t {
    int (*action_func)(vdui_t *);

    deobf_action_handler_t(int (*f)(vdui_t *)) : action_func(f) {}

    virtual int idaapi activate(action_activation_ctx_t *ctx) override {
        vdui_t *vu = get_widget_vdui(ctx->widget);
        if (vu)
            return action_func(vu);
        return 0;
    }

    virtual action_state_t idaapi update(action_update_ctx_t *ctx) override {
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
