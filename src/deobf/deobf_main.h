#pragma once
#include "deobf_types.h"
#include "../plugin/component_registry.h"

//--------------------------------------------------------------------------
// Main deobfuscator class - Hex-Rays optimizer callback (instruction level)
//--------------------------------------------------------------------------
class chernobog_t : public optinsn_t {
public:
    chernobog_t();
    virtual ~chernobog_t();

    // optinsn_t interface - called for each instruction during optimization
    virtual int idaapi func(mblock_t *blk, minsn_t *ins, int optflags) override;

    // Main entry points
    static void deobfuscate_function(cfunc_t *cfunc);
    static void deobfuscate_function(ea_t ea);
    static void deobfuscate_mba(mbl_array_t *mba);
    static void analyze_function(ea_t ea);

    // Detection
    static uint32_t detect_obfuscations(mbl_array_t *mba);
    static bool is_flattened(mbl_array_t *mba, deobf_ctx_t *ctx);
    static bool has_bogus_cf(mbl_array_t *mba, deobf_ctx_t *ctx);
    static bool has_encrypted_strings(mbl_array_t *mba);
    static bool has_encrypted_consts(mbl_array_t *mba);
    static bool has_indirect_branches(mbl_array_t *mba);

    // Deobfuscation passes
    static int deflatten(mbl_array_t *mba, deobf_ctx_t *ctx);
    static int remove_bogus_cf(mbl_array_t *mba, deobf_ctx_t *ctx);
    static int decrypt_strings(mbl_array_t *mba, deobf_ctx_t *ctx);
    static int decrypt_consts(mbl_array_t *mba, deobf_ctx_t *ctx);
    static int resolve_indirect_branches(mbl_array_t *mba, deobf_ctx_t *ctx);
    static int merge_blocks(mbl_array_t *mba, deobf_ctx_t *ctx);
    static int simplify_substitutions(mbl_array_t *mba, deobf_ctx_t *ctx);

};

//--------------------------------------------------------------------------
// Block-level optimizer for CFG modifications (e.g., deflattening)
// This runs at different maturity levels during microcode optimization
//--------------------------------------------------------------------------
class chernobog_optblock_t : public optblock_t {
public:
    // optblock_t interface - called for each block during optimization
    virtual int idaapi func(mblock_t *blk) override;
};

//--------------------------------------------------------------------------
// Component registration functions
//--------------------------------------------------------------------------
bool deobf_avail();
bool deobf_active();
void deobf_init();
void deobf_done();
void deobf_attach_popup(TWidget *widget, TPopupMenu *popup, vdui_t *vu);

// Clear tracking for a function to allow re-deobfuscation
void chernobog_clear_function_tracking(ea_t func_ea);
// True until the whole-MBA LOCOPT pipeline has run for this database/function.
// The Hex-Rays flowchart callback uses this to gate one current-function rax
// prerequisite before any optimizer mutation.
bool chernobog_function_requires_deobfuscation(ea_t func_ea);
void chernobog_mark_function_deobfuscated(ea_t func_ea);

// Clear ALL tracking caches (called on database load if CHERNOBOG_RESET=1)
void chernobog_clear_all_tracking();
