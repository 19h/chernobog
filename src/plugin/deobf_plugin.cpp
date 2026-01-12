#include "../common/warn_off.h"
#include <hexrays.hpp>
#include "../common/warn_on.h"

#include "component_registry.h"

// Include component headers to trigger registration
#include "../deobf/deobf_main.h"
#include "../deobf/handlers/ctree_const_fold.h"
#include "../deobf/handlers/ctree_switch_fold.h"
#include "../deobf/handlers/ctree_indirect_call.h"
#include "../deobf/handlers/ctree_string_decrypt.h"

#include <set>
#include <cstdio>

// Debug file logging for batch mode where msg() might not be visible
// Using raw syscalls to bypass IDA's file wrappers
#include "../common/compat.h"

static void debug_log(const char *fmt, ...) {
#ifndef _WIN32
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    int len = qvsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    int fd = open("/tmp/chernobog_debug.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        write(fd, buf, len);
        close(fd);
    }
#else
    (void)fmt; // Debug logging disabled on Windows
#endif
}

#ifndef _WIN32
// Global constructor to trace when dylib is loaded (Unix only)
__attribute__((constructor))
static void dylib_loaded() {
    // Write directly to a marker file to prove we loaded
    int fd = open("/tmp/CHERNOBOG_LOADED", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *msg = "DYLIB LOADED\n";
        write(fd, msg, 13);
        close(fd);
    }
    debug_log("[chernobog] DYLIB LOADED (constructor called)\n");
}
#endif

// Track which functions we've already auto-deobfuscated to avoid infinite loops
static std::set<ea_t> s_auto_deobfuscated;

// Track which functions we've already run ctree_const_fold on to avoid re-entry
static std::set<ea_t> s_ctree_const_folded;

// Track which functions we've already run ctree_switch_fold on to avoid re-entry
static std::set<ea_t> s_ctree_switch_folded;

// Track which functions we've already run ctree_indirect_call on
static std::set<ea_t> s_ctree_indirect_call_processed;

// Track which functions we've already run ctree_string_decrypt on
static std::set<ea_t> s_ctree_string_decrypt_processed;

//--------------------------------------------------------------------------
// Check if auto mode is enabled
// Supports: CHERNOBOG_AUTO=1 env var, or ~/.chernobog_auto file
//--------------------------------------------------------------------------
static bool is_auto_mode_enabled() {
    static int cached = -1;
    if (cached == -1) {
        cached = 0;
        // Try qgetenv first
        qstring env_val;
        if (qgetenv("CHERNOBOG_AUTO", &env_val) && !env_val.empty() && env_val[0] == '1') {
            cached = 1;
            debug_log("[chernobog] AUTO mode detected via env var\n");
        }
        // Also check for ~/.chernobog_auto file as fallback
        if (cached == 0) {
            qstring home;
            if (qgetenv("HOME", &home)) {
                qstring auto_file = home + "/.chernobog_auto";
                FILE *f = qfopen(auto_file.c_str(), "r");
                if (f) {
                    qfclose(f);
                    cached = 1;
                }
            }
        }
    }
    return cached == 1;
}

//--------------------------------------------------------------------------
// Check if cache reset is enabled via environment variable
//--------------------------------------------------------------------------
static bool is_reset_mode_enabled() {
    qstring env;
    if (qgetenv("CHERNOBOG_RESET", &env) && !env.empty() && env[0] != '0')
        return true;
    return false;
}

//--------------------------------------------------------------------------
// Check if verbose mode is enabled
//--------------------------------------------------------------------------
static void check_verbose_mode() {
    static bool checked = false;
    if (!checked) {
        checked = true;
        qstring env_val;
        if (qgetenv("CHERNOBOG_VERBOSE", &env_val) && env_val == "1") {
            deobf::set_verbose(true);
            msg("[chernobog] Verbose mode enabled (CHERNOBOG_VERBOSE=1)\n");
        }
    }
}

//--------------------------------------------------------------------------
// Hexrays Callback - Add popup menu items and auto-deobfuscate
//--------------------------------------------------------------------------
static ssize_t idaapi hexrays_callback(void *, hexrays_event_t event, va_list va) {
    // Debug: log all events
    debug_log("[chernobog] hexrays_callback event=%d\n", (int)event);
    
    static bool first_call = true;
    if (first_call) {
        first_call = false;
        debug_log("[chernobog] First hexrays callback, auto_mode=%d\n", is_auto_mode_enabled() ? 1 : 0);
        msg("[chernobog] Hexrays callback registered and active\n");
    }

    if (event == hxe_populating_popup) {
        TWidget *widget = va_arg(va, TWidget *);
        TPopupMenu *popup = va_arg(va, TPopupMenu *);
        vdui_t *vu = va_arg(va, vdui_t *);

        // Add separator if we have any components
        if (component_registry_t::get_count() > 0)
            attach_action_to_popup(widget, popup, nullptr);

        // Attach all component actions
        component_registry_t::attach_to_popup(widget, popup, vu);
    }
    // Clear tracking when view is refreshed (e.g., after inlining)
    // This allows re-deobfuscation when user makes changes
    else if (event == hxe_refresh_pseudocode) {
        vdui_t *vu = va_arg(va, vdui_t *);
        if (vu && vu->cfunc) {
            ea_t func_ea = vu->cfunc->entry_ea;
            s_auto_deobfuscated.erase(func_ea);
            s_ctree_const_folded.erase(func_ea);
            s_ctree_switch_folded.erase(func_ea);
            s_ctree_string_decrypt_processed.erase(func_ea);
            chernobog_clear_function_tracking(func_ea);
        }
    }
    // Auto-deobfuscate at microcode stage for analysis
    else if (event == hxe_microcode) {
        mbl_array_t *mba = va_arg(va, mbl_array_t *);
        debug_log("[chernobog] hxe_microcode: mba=%p, auto=%d\n", mba, is_auto_mode_enabled() ? 1 : 0);
        if (mba && is_auto_mode_enabled()) {
            ea_t func_ea = mba->entry_ea;
            bool already_done = s_auto_deobfuscated.find(func_ea) != s_auto_deobfuscated.end();
            debug_log("[chernobog] func_ea=0x%llx, already_done=%d\n", (unsigned long long)func_ea, already_done ? 1 : 0);
            if (!already_done) {
                s_auto_deobfuscated.insert(func_ea);
                debug_log("[chernobog] Calling deobfuscate_mba...\n");
                chernobog_t::deobfuscate_mba(mba);
                debug_log("[chernobog] deobfuscate_mba returned\n");
            }
        }
    }
    // Apply ctree-level optimizations after decompilation
    else if (event == hxe_maturity) {
        cfunc_t *cfunc = va_arg(va, cfunc_t *);
        ctree_maturity_t maturity = va_argi(va, ctree_maturity_t);
        // Run at CMAT_FINAL when the ctree is complete
        // Track by function to avoid infinite recursion if ctree modification triggers reprocessing
        if (cfunc && maturity == CMAT_FINAL && is_auto_mode_enabled()) {
            ea_t func_ea = cfunc->entry_ea;
            // Constant folding for XOR patterns
            if (s_ctree_const_folded.find(func_ea) == s_ctree_const_folded.end()) {
                s_ctree_const_folded.insert(func_ea);
                ctree_const_fold_handler_t::run(cfunc);
            }
            // Switch folding for opaque predicates
            if (s_ctree_switch_folded.find(func_ea) == s_ctree_switch_folded.end()) {
                s_ctree_switch_folded.insert(func_ea);
                ctree_switch_fold_handler_t::run(cfunc);
            }
            // Indirect call resolution (Hikari IndirectCall)
            if (s_ctree_indirect_call_processed.find(func_ea) == s_ctree_indirect_call_processed.end()) {
                s_ctree_indirect_call_processed.insert(func_ea);
                if (ctree_indirect_call_handler_t::detect(cfunc)) {
                    ctree_indirect_call_handler_t::run(cfunc, nullptr);
                }
            }
            // String decryption (strcpy reveals, char-by-char, AES keys)
            if (s_ctree_string_decrypt_processed.find(func_ea) == s_ctree_string_decrypt_processed.end()) {
                s_ctree_string_decrypt_processed.insert(func_ea);
                if (ctree_string_decrypt_handler_t::detect(cfunc)) {
                    deobf_ctx_t str_ctx;
                    str_ctx.cfunc = cfunc;
                    str_ctx.func_ea = func_ea;
                    int changes = ctree_string_decrypt_handler_t::run(cfunc, &str_ctx);
                    if (changes > 0) {
                        msg("[chernobog] Ctree string decryption: found %d strings\n", changes);
                    }
                }
            }
        }
    }
    return 0;
}

//--------------------------------------------------------------------------
// Deferred initialization - called when hexrays becomes available
//--------------------------------------------------------------------------
static bool s_hexrays_initialized = false;

static bool try_init_hexrays() {
    debug_log("[chernobog] try_init_hexrays called, already_init=%d\n", s_hexrays_initialized ? 1 : 0);
    
    if (s_hexrays_initialized)
        return true;

    if (!init_hexrays_plugin()) {
        debug_log("[chernobog] init_hexrays_plugin() failed\n");
        return false;
    }

    debug_log("[chernobog] init_hexrays_plugin() succeeded\n");
    s_hexrays_initialized = true;

    // Clear decompiler cache if CHERNOBOG_RESET is set
    // This forces full redecompilation of all functions
    if (is_reset_mode_enabled()) {
        s_auto_deobfuscated.clear();
        s_ctree_const_folded.clear();
        s_ctree_switch_folded.clear();
        chernobog_clear_all_tracking();
        clear_cached_cfuncs();
        msg("[chernobog] Cleared Hex-Rays decompiler cache (CHERNOBOG_RESET=1)\n");
    }

    // Check verbose mode before any output
    check_verbose_mode();

    // Check auto mode early and print debug info
    bool auto_mode = is_auto_mode_enabled();
    
    debug_log("[chernobog] Components registered: %d, auto=%d\n",
        (int)component_registry_t::get_count(), auto_mode ? 1 : 0);
    msg("[chernobog] Chernobog (Hikari Deobfuscator) initializing (%d components registered, auto=%d)\n",
        (int)component_registry_t::get_count(), auto_mode ? 1 : 0);

    // Install hexrays callback for popup menus and auto-deobfuscation
    debug_log("[chernobog] Installing hexrays callback...\n");
    install_hexrays_callback(hexrays_callback, nullptr);
    debug_log("[chernobog] Hexrays callback installed\n");

    debug_log("[chernobog] Calling init_all()...\n");
    int initialized = component_registry_t::init_all();
    debug_log("[chernobog] init_all() returned %d components initialized\n", initialized);
    msg("[chernobog] Plugin ready (%d components initialized)\n", initialized);

    // Check auto mode at startup
    if (auto_mode) {
        msg("[chernobog] *** AUTO MODE ACTIVE - will deobfuscate on decompilation ***\n");
    }

    msg("[chernobog] Use Ctrl+Shift+D to deobfuscate current function\n");
    msg("[chernobog] Use Ctrl+Shift+A to analyze obfuscation types\n");

    return true;
}

//--------------------------------------------------------------------------
// IDB event handler - to catch when hexrays becomes available
//--------------------------------------------------------------------------
static ssize_t idaapi idb_callback(void *, int event_id, va_list) {
    (void)event_id;  // unused
    // Try to init hexrays on various events
    if (!s_hexrays_initialized) {
        try_init_hexrays();
    }
    return 0;
}

//--------------------------------------------------------------------------
// Plugin Initialization
//--------------------------------------------------------------------------
static plugmod_t * idaapi init(void) {
    debug_log("[chernobog] Plugin init() called\n");
    
    // Try immediate init (works if hexrays loaded first)
    if (try_init_hexrays()) {
        debug_log("[chernobog] init() returning PLUGIN_KEEP (hexrays ready)\n");
        return PLUGIN_KEEP;
    }

    // Hexrays not ready yet - hook IDB events to init later
    debug_log("[chernobog] Hexrays not ready, hooking IDB events\n");
    msg("[chernobog] Waiting for Hex-Rays decompiler...\n");
    hook_to_notification_point(HT_IDB, idb_callback, nullptr);

    return PLUGIN_KEEP;
}

static void idaapi term(void) {
    // Remove callbacks
    unhook_from_notification_point(HT_IDB, idb_callback, nullptr);

    if (s_hexrays_initialized) {
        remove_hexrays_callback(hexrays_callback, nullptr);

        // Unregister all component actions
        component_registry_t::unregister_all_actions();

        int terminated = component_registry_t::done_all();
        msg("[chernobog] Plugin terminated (%d components)\n", terminated);
    }
}

static bool idaapi run(size_t) {
    // Plugin can be invoked manually - show info
    msg("\n=== Chernobog - Hikari Deobfuscator ===\n");
    msg("This plugin deobfuscates code protected with Hikari LLVM obfuscator.\n\n");
    msg("Supported obfuscations:\n");
    msg("  - Control Flow Flattening (CFF)\n");
    msg("  - Bogus Control Flow (BCF)\n");
    msg("  - String Encryption\n");
    msg("  - Constant Encryption\n");
    msg("  - Instruction Substitution\n");
    msg("  - Indirect Branches\n");
    msg("  - Basic Block Splitting\n");
    msg("  - Identity Function Calls\n");
    msg("  - Stack String Construction\n");
    msg("  - Hikari Function Wrappers\n");
    msg("  - Register Demotion (savedregs)\n");
    msg("  - Obfuscated ObjC Method Calls\n\n");
    msg("Usage:\n");
    msg("  1. Open a function in the decompiler\n");
    msg("  2. Right-click and select 'Deobfuscate (Chernobog)'\n");
    msg("  3. Or press Ctrl+Shift+D\n\n");
    msg("To analyze without modifying:\n");
    msg("  Right-click and select 'Analyze obfuscation (Chernobog)'\n");
    msg("  Or press Ctrl+Shift+A\n\n");
    msg("Auto-deobfuscation mode:\n");
    msg("  Set CHERNOBOG_AUTO=1 environment variable before starting IDA\n");
    msg("  to automatically deobfuscate functions when they are decompiled.\n\n");

    return true;
}

//--------------------------------------------------------------------------
// Plugin Descriptor
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_FIX,                         // plugin flags
    init,                               // initialize
    term,                               // terminate
    run,                                // invoke plugin
    "Chernobog - Hikari LLVM Deobfuscator", // long comment
    "Deobfuscates Hikari-protected binaries for Hex-Rays", // help text
    "Chernobog",                        // preferred short name
    "Ctrl+Shift+H"                     // preferred hotkey
};
