#include "../common/warn_off.h"
#include <hexrays.hpp>
#include <idacfg.hpp>
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

static void debug_log(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    deobf::debug_vlog("/tmp/chernobog_debug.log", fmt, args);
    va_end(args);
}

#ifndef _WIN32
// Global constructor to trace when dylib is loaded (Unix only)
__attribute__((constructor))
static void dylib_loaded()
{
    if ( !deobf::debug_enabled() )
        return;

    // Write directly to a marker file to prove we loaded
    int fd = open("/tmp/CHERNOBOG_LOADED", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if ( fd >= 0 )
    {
        const char *msg = "DYLIB LOADED\n";
        write(fd, msg, 13);
        close(fd);
    }
    debug_log("[chernobog] DYLIB LOADED (constructor called)\n");
}
#endif

struct chernobog_plugmod_t final : public plugmod_t
{
    bool hexrays_initialized = false;
    bool components_initialized = false;
    bool ui_hooked = false;
    bool idb_hooked = false;
    bool first_hexrays_callback = true;

    // All address-keyed state belongs to this database instance.
    std::set<ea_t> ctree_const_folded;
    std::set<ea_t> ctree_switch_folded;
    std::set<ea_t> ctree_indirect_call_processed;
    std::set<ea_t> ctree_string_decrypt_processed;

    chernobog_plugmod_t();
    virtual ~chernobog_plugmod_t();

    bool activate();
    void deactivate();
    void clear_processing_state();
    virtual bool idaapi run(size_t arg) override;
};

//--------------------------------------------------------------------------
// Check if auto mode is enabled
// Supports: CHERNOBOG_AUTO=1 env var, or ~/.chernobog_auto file
//--------------------------------------------------------------------------
static bool is_auto_mode_enabled()
{
    static int cached = -1;
    if ( cached == -1 )
    {
        cached = 0;
        // Try qgetenv first
        qstring env_val;
        if ( qgetenv("CHERNOBOG_AUTO", &env_val) && !env_val.empty() && env_val[0] == '1' )
        {
            cached = 1;
            debug_log("[chernobog] AUTO mode detected via env var\n");
        }
        // Also check for ~/.chernobog_auto file as fallback
        if ( cached == 0 )
        {
            qstring home;
            if ( qgetenv("HOME", &home) )
            {
                qstring auto_file = home + "/.chernobog_auto";
                FILE *f = qfopen(auto_file.c_str(), "r");
                if ( f )
                {
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
static bool is_reset_mode_enabled()
{
    qstring env;
    if ( qgetenv("CHERNOBOG_RESET", &env) && !env.empty() && env[0] != '0' )
        return true;
    return false;
}

//--------------------------------------------------------------------------
// Check whether all transformations are disabled. This retains the plugin's
// Hex-Rays lifecycle and optional cache reset, which provides a like-for-like
// control path and an emergency bypass for maturity-specific incompatibilities.
//--------------------------------------------------------------------------
static bool is_disabled_mode_enabled()
{
    qstring env;
    return qgetenv("CHERNOBOG_DISABLE", &env)
        && !env.empty() && env[0] != '0';
}

//--------------------------------------------------------------------------
// Optionally raise Hex-Rays' function-size admission ceiling for the current
// process. The stock value is 64 KiB. Keeping this environment-controlled
// avoids modifying either the installation-wide or per-user hexrays.cfg.
//--------------------------------------------------------------------------
static bool configure_max_funcsize()
{
    qstring env;
    if ( !qgetenv("CHERNOBOG_MAX_FUNCSIZE_KB", &env) || env.empty() )
        return true;

    // Decimal only, 1 KiB..1 GiB. Apart from rejecting ambiguous input, the
    // upper bound keeps MAX_FUNCSIZE * 1024 within a signed 32-bit byte count.
    uint64 value = 0;
    for ( size_t i = 0; i < env.length(); ++i )
    {
        const char c = env[i];
        if ( c < '0' || c > '9' )
        {
            msg("[chernobog] Invalid CHERNOBOG_MAX_FUNCSIZE_KB='%s' (decimal KiB required)\n",
                env.c_str());
            return false;
        }
        value = value * 10 + uint64(c - '0');
        if ( value > 1024 * 1024 )
        {
            msg("[chernobog] Invalid CHERNOBOG_MAX_FUNCSIZE_KB='%s' (maximum 1048576 KiB)\n",
                env.c_str());
            return false;
        }
    }
    if ( value == 0 )
    {
        msg("[chernobog] Invalid CHERNOBOG_MAX_FUNCSIZE_KB='0'\n");
        return false;
    }

    qstring directive;
    directive.sprnt("MAX_FUNCSIZE=%llu", static_cast<unsigned long long>(value));
    process_config_directive(directive.c_str());
    msg("[chernobog] Hex-Rays function-size ceiling set to %llu KiB for this process\n",
        static_cast<unsigned long long>(value));
    debug_log("[chernobog] Applied config directive: %s\n", directive.c_str());
    return true;
}

//--------------------------------------------------------------------------
// Check if verbose mode is enabled
//--------------------------------------------------------------------------
static void check_verbose_mode()
{
    static bool checked = false;
    if ( !checked )
    {
        checked = true;
        qstring env_val;
        if ( qgetenv("CHERNOBOG_VERBOSE", &env_val) && env_val == "1" )
        {
            deobf::set_verbose(true);
            msg("[chernobog] Verbose mode enabled (CHERNOBOG_VERBOSE=1)\n");
        }
    }
}

//--------------------------------------------------------------------------
// Hexrays Callback - Add popup menu items and auto-deobfuscate
//--------------------------------------------------------------------------
static ssize_t idaapi hexrays_callback(void *ud, hexrays_event_t event, va_list va)
{
    chernobog_plugmod_t *self = static_cast<chernobog_plugmod_t *>(ud);
    if ( self == nullptr )
        return 0;

    // Debug: log all events
    debug_log("[chernobog] hexrays_callback event=%d\n", (int)event);

    if ( self->first_hexrays_callback )
    {
        self->first_hexrays_callback = false;
        debug_log("[chernobog] First hexrays callback, auto_mode=%d\n", is_auto_mode_enabled() ? 1 : 0);
        msg("[chernobog] Hexrays callback registered and active\n");
    }

    if ( event == hxe_populating_popup )
    {
        TWidget *widget = va_arg(va, TWidget *);
        TPopupMenu *popup = va_arg(va, TPopupMenu *);
        vdui_t *vu = va_arg(va, vdui_t *);

        // Add separator if we have any components
        if ( component_registry_t::get_count() > 0 )
            attach_action_to_popup(widget, popup, nullptr);

        // Attach all component actions
        component_registry_t::attach_to_popup(widget, popup, vu);
    }
    // Clear tracking when view is refreshed (e.g., after inlining)
    // This allows re-deobfuscation when user makes changes
    else if ( event == hxe_refresh_pseudocode )
    {
        vdui_t *vu = va_arg(va, vdui_t *);
        if ( vu && vu->cfunc )
        {
            ea_t func_ea = vu->cfunc->entry_ea;
            self->ctree_const_folded.erase(func_ea);
            self->ctree_switch_folded.erase(func_ea);
            self->ctree_indirect_call_processed.erase(func_ea);
            self->ctree_string_decrypt_processed.erase(func_ea);
            chernobog_clear_function_tracking(func_ea);
        }
    }
    // The installed optinsn/optblock handlers own microcode deobfuscation.
    // In particular, the optblock handler runs the whole-MBA pipeline at
    // MMAT_LOCOPT, the first maturity at which its CFG transformations are
    // valid. Running the same pipeline here at hxe_microcode used to execute
    // every pass twice and could leave maturity-sensitive handlers operating
    // on preoptimized microcode.
    else if ( event == hxe_microcode )
    {
        mbl_array_t *mba = va_arg(va, mbl_array_t *);
        debug_log("[chernobog] hxe_microcode: mba=%p, auto=%d\n", mba, is_auto_mode_enabled() ? 1 : 0);
    }
    // Apply ctree-level optimizations after decompilation
    else if ( event == hxe_maturity )
    {
        cfunc_t *cfunc = va_arg(va, cfunc_t *);
        ctree_maturity_t maturity = va_argi(va, ctree_maturity_t);
        // Run at CMAT_FINAL when the ctree is complete
        // Track by function to avoid infinite recursion if ctree modification triggers reprocessing
        if ( cfunc && maturity == CMAT_FINAL && is_auto_mode_enabled()
          && !is_disabled_mode_enabled() )
        {
            ea_t func_ea = cfunc->entry_ea;
            // Constant folding for XOR patterns
            if ( self->ctree_const_folded.find(func_ea) == self->ctree_const_folded.end() )
            {
                self->ctree_const_folded.insert(func_ea);
                ctree_const_fold_handler_t::run(cfunc);
            }
            // Switch folding for opaque predicates
            if ( self->ctree_switch_folded.find(func_ea) == self->ctree_switch_folded.end() )
            {
                self->ctree_switch_folded.insert(func_ea);
                ctree_switch_fold_handler_t::run(cfunc);
            }
            // Indirect call resolution (Hikari IndirectCall)
            if ( self->ctree_indirect_call_processed.find(func_ea) == self->ctree_indirect_call_processed.end() )
            {
                self->ctree_indirect_call_processed.insert(func_ea);
                if ( ctree_indirect_call_handler_t::detect(cfunc) )
                {
                    ctree_indirect_call_handler_t::run(cfunc, nullptr);
                }
            }
            // String decryption (strcpy reveals, char-by-char, AES keys)
            if ( self->ctree_string_decrypt_processed.find(func_ea) == self->ctree_string_decrypt_processed.end() )
            {
                self->ctree_string_decrypt_processed.insert(func_ea);
                if ( ctree_string_decrypt_handler_t::detect(cfunc) )
                {
                    deobf_ctx_t str_ctx;
                    str_ctx.cfunc = cfunc;
                    str_ctx.func_ea = func_ea;
                    int changes = ctree_string_decrypt_handler_t::run(cfunc, &str_ctx);
                    if ( changes > 0 )
                    {
                        msg("[chernobog] Ctree string decryption: found %d strings\n", changes);
                    }
                }
            }
        }
    }
    return 0;
}

//--------------------------------------------------------------------------
// Per-database plugin lifecycle
//--------------------------------------------------------------------------
static bool is_hexrays_plugin(const plugin_t *entry)
{
    if ( entry == nullptr || entry->wanted_name == nullptr )
        return false;
    return streq(entry->wanted_name, "Hex-Rays Decompiler")
        || streq(entry->wanted_name, "Hex-Rays Cloud Decompiler");
}

void chernobog_plugmod_t::clear_processing_state()
{
    ctree_const_folded.clear();
    ctree_switch_folded.clear();
    ctree_indirect_call_processed.clear();
    ctree_string_decrypt_processed.clear();
    chernobog_clear_all_tracking();
}

bool chernobog_plugmod_t::activate()
{
    debug_log("[chernobog] activate called, already_init=%d, dbctx=%lld\n",
        hexrays_initialized ? 1 : 0,
        static_cast<long long>(get_dbctx_id()));

    if ( hexrays_initialized )
        return true;

    if ( !init_hexrays_plugin() )
    {
        debug_log("[chernobog] init_hexrays_plugin() failed\n");
        return false;
    }

    debug_log("[chernobog] init_hexrays_plugin() succeeded\n");

    if ( !configure_max_funcsize() )
        return false;

    // A unique plugmod pointer distinguishes callbacks in concurrent IDBs.
    debug_log("[chernobog] Installing Hex-Rays callback...\n");
    if ( !install_hexrays_callback(hexrays_callback, this) )
    {
        debug_log("[chernobog] install_hexrays_callback() failed\n");
        msg("[chernobog] Failed to install Hex-Rays callback\n");
        return false;
    }
    hexrays_initialized = true;
    debug_log("[chernobog] Hex-Rays callback installed\n");

    check_verbose_mode();
    const bool auto_mode = is_auto_mode_enabled();
    const bool disabled = is_disabled_mode_enabled();

    if ( disabled )
    {
        clear_processing_state();
        if ( is_reset_mode_enabled() )
        {
            clear_cached_cfuncs();
            msg("[chernobog] Cleared Hex-Rays decompiler cache (CHERNOBOG_RESET=1)\n");
        }
        debug_log("[chernobog] Transformations disabled by CHERNOBOG_DISABLE\n");
        msg("[chernobog] Plugin ready in disabled control mode (CHERNOBOG_DISABLE=1)\n");
        return true;
    }

    debug_log("[chernobog] Components registered: %d, auto=%d\n",
        (int)component_registry_t::get_count(), auto_mode ? 1 : 0);
    msg("[chernobog] Chernobog (Hikari Deobfuscator) initializing (%d components registered, auto=%d)\n",
        (int)component_registry_t::get_count(), auto_mode ? 1 : 0);

    debug_log("[chernobog] Calling init_all()...\n");
    const int initialized = component_registry_t::init_all();
    components_initialized = initialized > 0;
    debug_log("[chernobog] init_all() returned %d components initialized\n", initialized);

    if ( component_registry_t::get_count() != 0 && !components_initialized )
    {
        msg("[chernobog] No components initialized; activation failed\n");
        remove_hexrays_callback(hexrays_callback, this);
        hexrays_initialized = false;
        return false;
    }

    // Clear address-keyed state for this database. The optional cache reset
    // additionally invalidates Hex-Rays' persisted decompilation results.
    clear_processing_state();
    if ( is_reset_mode_enabled() )
    {
        clear_cached_cfuncs();
        msg("[chernobog] Cleared Hex-Rays decompiler cache (CHERNOBOG_RESET=1)\n");
    }

    msg("[chernobog] Plugin ready (%d components initialized)\n", initialized);
    if ( auto_mode )
        msg("[chernobog] *** AUTO MODE ACTIVE - will deobfuscate on decompilation ***\n");

    msg("[chernobog] Use Ctrl+Shift+D to deobfuscate current function\n");
    msg("[chernobog] Use Ctrl+Shift+A to analyze obfuscation types\n");
    return true;
}

void chernobog_plugmod_t::deactivate()
{
    if ( !hexrays_initialized && !components_initialized )
        return;

    // ui_destroying_plugmod invokes this while the decompiler dispatcher is
    // still valid. This prevents teardown calls after Hex-Rays module data is
    // destroyed, irrespective of plugin unload order.
    if ( get_hexdsp() == nullptr )
    {
        debug_log("[chernobog] Hex-Rays disappeared before teardown\n");
        hexrays_initialized = false;
        components_initialized = false;
        return;
    }

    if ( hexrays_initialized )
    {
        const int removed = remove_hexrays_callback(hexrays_callback, this);
        debug_log("[chernobog] Removed %d Hex-Rays callbacks\n", removed);
        hexrays_initialized = false;
    }

    int terminated = 0;
    if ( components_initialized )
    {
        terminated = component_registry_t::done_all();
        components_initialized = false;
    }

    first_hexrays_callback = true;
    clear_processing_state();
    msg("[chernobog] Plugin deactivated (%d components)\n", terminated);
}

static ssize_t idaapi ui_callback(void *ud, int event_id, va_list va)
{
    chernobog_plugmod_t *self = static_cast<chernobog_plugmod_t *>(ud);
    if ( self == nullptr )
        return 0;

    if ( event_id == ui_ready_to_run || event_id == ui_database_inited )
    {
        self->activate();
    }
    else if ( event_id == ui_plugin_loaded )
    {
        // Retrying once per plugin load is bounded and also supports renamed
        // or cloud decompiler variants without relying on display strings.
        (void)va_arg(va, const plugin_info_t *);
        if ( !self->hexrays_initialized )
            self->activate();
    }
    else if ( event_id == ui_destroying_plugmod )
    {
        (void)va_arg(va, const plugmod_t *);
        const plugin_t *entry = va_arg(va, const plugin_t *);
        if ( is_hexrays_plugin(entry) )
            self->deactivate();
    }
    return 0;
}

static ssize_t idaapi idb_callback(void *ud, int event_id, va_list)
{
    chernobog_plugmod_t *self = static_cast<chernobog_plugmod_t *>(ud);
    if ( self != nullptr && event_id == idb_event::closebase )
        self->clear_processing_state();
    return 0;
}

chernobog_plugmod_t::chernobog_plugmod_t()
{
    debug_log("[chernobog] Per-IDB plugmod created, dbctx=%lld\n",
        static_cast<long long>(get_dbctx_id()));

    idb_hooked = hook_to_notification_point(HT_IDB, idb_callback, this);
    ui_hooked = hook_to_notification_point(HT_UI, ui_callback, this);
    if ( !idb_hooked || !ui_hooked )
    {
        debug_log("[chernobog] Hook registration failed: IDB=%d UI=%d\n",
            idb_hooked ? 1 : 0, ui_hooked ? 1 : 0);
    }

    if ( !activate() )
    {
        debug_log("[chernobog] Hex-Rays not ready; activation deferred\n");
        msg("[chernobog] Waiting for Hex-Rays decompiler...\n");
    }
}

chernobog_plugmod_t::~chernobog_plugmod_t()
{
    if ( idb_hooked )
        unhook_from_notification_point(HT_IDB, idb_callback, this);
    if ( ui_hooked )
        unhook_from_notification_point(HT_UI, ui_callback, this);

    deactivate();
    clear_processing_state();
    debug_log("[chernobog] Per-IDB plugmod destroyed\n");
}

bool idaapi chernobog_plugmod_t::run(size_t)
{
    const bool ready = activate();

    // Plugin can be invoked manually - show info
    msg("\n=== Chernobog - Hikari Deobfuscator ===\n");
    if ( !ready )
        msg("Hex-Rays is not available for the current database.\n\n");
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
    msg("  - Obfuscated ObjC Method Calls\n");
    msg("  - VM-family MBA handlers (CHERNOBOG_VM=1)\n\n");
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

static plugmod_t *idaapi init()
{
    return new chernobog_plugmod_t();
}

//--------------------------------------------------------------------------
// Plugin Descriptor
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,                       // one plugmod instance per database
    init,                               // initialize
    nullptr,                            // PLUGIN_MULTI uses plugmod destructor
    nullptr,                            // PLUGIN_MULTI uses plugmod_t::run
    "Chernobog - Hikari LLVM Deobfuscator", // long comment
    "Deobfuscates Hikari-protected binaries for Hex-Rays", // help text
    "Chernobog",                        // preferred short name
    "Ctrl+Shift+H"                     // preferred hotkey
};
