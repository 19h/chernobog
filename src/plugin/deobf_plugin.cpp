#include "../common/warn_off.h"
#include <hexrays.hpp>
#include "../common/warn_on.h"

#include "component_registry.h"

// Include component headers to trigger registration
#include "../deobf/deobf_main.h"

//--------------------------------------------------------------------------
// Hexrays Callback - Add popup menu items
//--------------------------------------------------------------------------
static ssize_t idaapi hexrays_callback(void *, hexrays_event_t event, va_list va) {
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
    return 0;
}

//--------------------------------------------------------------------------
// Plugin Initialization
//--------------------------------------------------------------------------
static plugmod_t * idaapi init(void) {
    if (!init_hexrays_plugin()) {
        msg("[chernobog] Plugin requires Hex-Rays decompiler\n");
        return PLUGIN_SKIP;
    }

    msg("[chernobog] Chernobog (Hikari Deobfuscator) initializing (%d components registered)\n",
        (int)component_registry_t::get_count());

    // Install hexrays callback for popup menus
    install_hexrays_callback(hexrays_callback, nullptr);

    int initialized = component_registry_t::init_all();
    msg("[chernobog] Plugin ready (%d components initialized)\n", initialized);

    msg("[chernobog] Use Ctrl+Shift+D to deobfuscate current function\n");
    msg("[chernobog] Use Ctrl+Shift+A to analyze obfuscation types\n");

    return PLUGIN_KEEP;
}

static void idaapi term(void) {
    msg("[chernobog] Plugin terminating\n");

    // Remove hexrays callback
    remove_hexrays_callback(hexrays_callback, nullptr);

    // Unregister all component actions
    component_registry_t::unregister_all_actions();

    int terminated = component_registry_t::done_all();
    msg("[chernobog] Plugin done (%d components terminated)\n", terminated);
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
