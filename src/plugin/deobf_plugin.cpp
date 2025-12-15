#include "../common/warn_off.h"
#include <hexrays.hpp>
#include "../common/warn_on.h"

#include "component_registry.h"

// Include component headers to trigger registration
#include "../deobf/deobf_main.h"

#include <set>

// Track which functions we've already auto-deobfuscated to avoid infinite loops
static std::set<ea_t> s_auto_deobfuscated;

//--------------------------------------------------------------------------
// Check if auto mode is enabled
//--------------------------------------------------------------------------
static bool is_auto_mode_enabled() {
    static int cached = -1;
    if (cached == -1) {
        qstring env_val;
        if (qgetenv("CHERNOBOG_AUTO", &env_val) && env_val == "1") {
            cached = 1;
            msg("[chernobog] Auto-deobfuscation mode enabled (CHERNOBOG_AUTO=1)\n");
        } else {
            cached = 0;
        }
    }
    return cached == 1;
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
    // Debug: log all events in auto mode
    static bool first_call = true;
    if (first_call && is_auto_mode_enabled()) {
        first_call = false;
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
    // Auto-deobfuscate at microcode stage for analysis
    // Note: CFG modifications at maturity 0 are risky
    else if (event == hxe_microcode) {
        mbl_array_t *mba = va_arg(va, mbl_array_t *);
        if (mba && is_auto_mode_enabled()) {
            ea_t func_ea = mba->entry_ea;
            if (s_auto_deobfuscated.find(func_ea) == s_auto_deobfuscated.end()) {
                s_auto_deobfuscated.insert(func_ea);
                chernobog_t::deobfuscate_mba(mba);
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
    if (s_hexrays_initialized)
        return true;

    if (!init_hexrays_plugin())
        return false;

    s_hexrays_initialized = true;

    // Check verbose mode before any output
    check_verbose_mode();

    msg("[chernobog] Chernobog (Hikari Deobfuscator) initializing (%d components registered)\n",
        (int)component_registry_t::get_count());

    // Install hexrays callback for popup menus and auto-deobfuscation
    install_hexrays_callback(hexrays_callback, nullptr);

    int initialized = component_registry_t::init_all();
    msg("[chernobog] Plugin ready (%d components initialized)\n", initialized);

    // Check auto mode at startup
    if (is_auto_mode_enabled()) {
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
    // Try immediate init (works if hexrays loaded first)
    if (try_init_hexrays()) {
        return PLUGIN_KEEP;
    }

    // Hexrays not ready yet - hook IDB events to init later
    msg("[chernobog] Waiting for Hex-Rays decompiler...\n");
    hook_to_notification_point(HT_IDB, idb_callback, nullptr);

    return PLUGIN_KEEP;
}

static void idaapi term(void) {
    msg("[chernobog] Plugin terminating\n");

    // Remove callbacks
    unhook_from_notification_point(HT_IDB, idb_callback, nullptr);

    if (s_hexrays_initialized) {
        remove_hexrays_callback(hexrays_callback, nullptr);

        // Unregister all component actions
        component_registry_t::unregister_all_actions();

        int terminated = component_registry_t::done_all();
        msg("[chernobog] Plugin done (%d components terminated)\n", terminated);
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
