#include "../common/warn_off.h"
#include <hexrays.hpp>
#include <idacfg.hpp>
#include "../common/warn_on.h"

#include "component_registry.h"
#include "../common/hexrays_compat.h"
#include <chernobog/build_provenance.hpp>

// Include component headers to trigger registration
#include "../deobf/deobf_main.h"
#include "../deobf/analysis/pattern_match.h"
#include "../deobf/handlers/ctree_const_fold.h"
#include "../deobf/handlers/ctree_switch_fold.h"
#include "../deobf/handlers/ctree_indirect_call.h"
#include "../deobf/handlers/ctree_string_decrypt.h"
#include "../deobf/handlers/hikari_cfg.h"
#include "../deobf/handlers/jump_optimizer.h"
#include "../deobf/handlers/native_opaque.h"
#include "../hybrid/session.hpp"
#include "../hybrid/z3_bridge.hpp"
#include "../ida_analysis/early_hexrays.hpp"
#include "../ida_analysis/native_engine.hpp"

#include <map>
#include <set>
#include <cstdio>
#include <memory>

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

// MERR_LOOP is an internal callback control value and therefore must match the
// loaded decompiler, not merely the header used to compile this plugin. The
// 2026-06-30 timeout addition inserted MERR_TIMEOUT at -36 and shifted
// MERR_LOOP to -37. Some public 9.4 SDK headers still define the old layout.
static merror_t compatible_merr_loop()
{
    static const merror_t runtime_value = []() -> merror_t
    {
        // A header containing the timeout addition already has the correct
        // runtime value. Unknown layouts are likewise safer when left intact.
        if constexpr ( static_cast<int>(MERR_MAX_ERR) != 35
                    || static_cast<int>(MERR_LOOP) != -36 )
        {
            return MERR_LOOP;
        }

        const char *runtime_version = get_hexrays_version();
        if ( chernobog::hexrays_compat::uses_timeout_merror_layout(
                 runtime_version) )
        {
            constexpr int timeout_layout_merr_loop = -37;
            debug_log(
                "[chernobog] Hex-Rays %s uses shifted merror layout; "
                "MERR_LOOP=%d\n",
                runtime_version,
                timeout_layout_merr_loop);
            return static_cast<merror_t>(timeout_layout_merr_loop);
        }
        return MERR_LOOP;
    }();
    return runtime_value;
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
    ssize_t database_id = -1;
    bool hexrays_initialized = false;
    bool components_initialized = false;
    bool ui_hooked = false;
    bool idb_hooked = false;
    bool first_hexrays_callback = true;
    bool hikari_cfg_attempted = false;
    bool native_opaque_attempted = false;
    // A flowchart callback does not identify its caller. Arm automatic rax
    // only for the synchronous duration of an explicit GUI pseudocode action;
    // get_screen_ea() alone is ambient UI state and must not authorize work.
    ea_t user_decompile_target = BADADDR;
    qtimer_t activation_timer = nullptr;
    int activation_attempts = 0;
    std::unique_ptr<chernobog::ida_analysis::NativeAnalysisEngine>
        ida_analysis;
    std::unique_ptr<chernobog::ida_analysis::EarlyHexRaysAnalysis>
        early_hexrays;
    std::unique_ptr<chernobog::hybrid::Session> hybrid_session;

    // All address-keyed state belongs to this database instance.
    std::set<ea_t> ctree_const_folded;
    std::set<ea_t> ctree_switch_folded;
    std::set<ea_t> ctree_indirect_call_processed;
    // A no-cache decompilation creates a new cfunc for the same function.
    // Track ctree string rewrites by tree identity so every rebuilt tree
    // receives transient runtime literals.
    std::map<ea_t, const cfunc_t *> ctree_string_decrypt_processed;

    chernobog_plugmod_t();
    virtual ~chernobog_plugmod_t();

    bool activate();
    void schedule_activation_retry();
    void cancel_activation_retry();
    static int idaapi activation_retry_callback(void *ud);
    void deactivate();
    void clear_processing_state();
    bool recover_hikari_cfg_if_ready(bool force = false);
    bool recover_native_opaque_if_ready(bool force = false);
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
        const bool environment_override = qgetenv("CHERNOBOG_AUTO", &env_val);
        if ( environment_override && !env_val.empty() && env_val[0] == '1' )
        {
            cached = 1;
            debug_log("[chernobog] AUTO mode detected via env var\n");
        }
        // An explicit environment value, including 0, takes precedence over
        // the per-user marker. Consult the marker only when the variable is
        // absent.
        if ( cached == 0 && !environment_override )
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
// Admit automatic rax work only for the function the user selected. This
// prevents "decompile all" and background Hex-Rays requests from turning the
// current-function prerequisite into a database sweep. Batch callers must name
// the authoritative target explicitly, as the existing rax batch action does.
//--------------------------------------------------------------------------
static bool explicit_rax_target_matches(ea_t function_ea)
{
    qstring raw;
    ea_t requested = BADADDR;
    if ( !qgetenv("CHERNOBOG_RAX_BATCH_EA", &raw) || raw.empty()
      || !str2ea(&requested, raw.c_str(), BADADDR) )
    {
        return false;
    }
    const func_t *function = get_func(requested);
    return function != nullptr && function->start_ea == function_ea;
}

static bool is_user_pseudocode_action(const char *name)
{
    return name != nullptr
        && (streq(name, "hx:GenPseudo")
         || streq(name, "hx:JumpPseudo")
         || streq(name, "hx:JumpNewPseudo"));
}

//--------------------------------------------------------------------------
// Admit automatic rax work only while an explicit user pseudocode action owns
// this function. Hex-Rays flowchart events have no caller metadata, and the
// GUI screen address may remain on a function while unrelated plugins or
// background/decompile-all clients request its decompilation. IDALIB and text
// mode have no GUI action boundary and therefore require an explicit address.
//--------------------------------------------------------------------------
static bool is_focused_function(
    const chernobog_plugmod_t *self, ea_t function_ea)
{
    if ( self == nullptr || function_ea == BADADDR )
        return false;

    if ( batch || is_ida_library() )
        return explicit_rax_target_matches(function_ea);

    return self->user_decompile_target == function_ea;
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
    if ( self == nullptr || get_dbctx_id() != self->database_id )
        return 0;

    // Debug: log all events
    debug_log("[chernobog] hexrays_callback event=%d\n", (int)event);

    if ( self->first_hexrays_callback )
    {
        self->first_hexrays_callback = false;
        debug_log("[chernobog] First hexrays callback, auto_mode=%d\n", is_auto_mode_enabled() ? 1 : 0);
        msg("[chernobog] Hexrays callback registered and active\n");
    }

    // This is the earliest decompiler event, before microcode generation and
    // optinsn/optblock mutation. Recover native CFG first; if it changed, the
    // restarted flowchart will snapshot those exact bytes. Then synchronously
    // ensure rax evidence only for the function whose MBA pipeline is about to
    // run. IDA 9.4 normally emits the ea-based event; retain the legacy event
    // because it is still part of the supported 9.4 callback ABI.
    const bool is_flowchart_event = event == hxe_flowchart
#if IDA_SDK_VERSION >= 940
        || event == hxe_flowchart_ea
#endif
        ;
    if ( is_flowchart_event )
    {
        ea_t function_ea = BADADDR;
        bitset_t *reachable = nullptr;
        const qflow_chart_t *legacy_flowchart = nullptr;
#if IDA_SDK_VERSION >= 940
        const qflow_chart_ea_t *ea_flowchart = nullptr;
#endif
#if IDA_SDK_VERSION >= 940
        if ( event == hxe_flowchart_ea )
        {
            ea_flowchart = va_arg(va, const qflow_chart_ea_t *);
            mba_t *mba = va_arg(va, mba_t *);
            reachable = va_arg(va, bitset_t *);
            function_ea = ea_flowchart != nullptr
                        ? ea_flowchart->func_ea : BADADDR;
            if ( function_ea == BADADDR && mba != nullptr )
                function_ea = mba->entry_ea;
        }
        else
#endif
        {
            legacy_flowchart = va_arg(va, const qflow_chart_t *);
            mba_t *mba = va_arg(va, mba_t *);
            reachable = va_arg(va, bitset_t *);
            if ( legacy_flowchart != nullptr
              && legacy_flowchart->pfn != nullptr )
            {
                function_ea = legacy_flowchart->pfn->start_ea;
            }
            else if ( mba != nullptr )
                function_ea = mba->entry_ea;
        }

        const bool hikari_changed = self->recover_hikari_cfg_if_ready(true);
        const bool native_changed = self->recover_native_opaque_if_ready(true);
        if ( hikari_changed || native_changed )
        {
            if ( function_ea != BADADDR )
                chernobog::hybrid::hybrid_abandon_deobfuscation_projection(
                    uint64_t(function_ea));
            return MERR_REDO;
        }

        if ( function_ea != BADADDR
          && is_focused_function(self, function_ea)
          && !is_disabled_mode_enabled()
          && chernobog_function_requires_deobfuscation(function_ea) )
        {
            const chernobog::hybrid::EnsureExploredResult result =
                self->hybrid_session != nullptr
                ? self->hybrid_session->ensure_explored(uint64_t(function_ea))
                : chernobog::hybrid::EnsureExploredResult::UNAVAILABLE;
            if ( result == chernobog::hybrid::EnsureExploredResult::FAILED
              || result == chernobog::hybrid::EnsureExploredResult::CANCELLED )
            {
                msg("[chernobog][rax] Pre-deobfuscation exploration for %a did not produce fresh evidence; continuing without rax evidence\n",
                    function_ea);
            }
            if ( self->hybrid_session != nullptr
              && self->hybrid_session->take_analysis_changes() )
            {
                // Static/dynamic evidence may have added exact IDB edges or
                // metadata while this flowchart prerequisite was running.
                // Rebuild once from the enriched database.
                chernobog::hybrid::hybrid_abandon_deobfuscation_projection(
                    uint64_t(function_ea));
                return MERR_REDO;
            }
        }

        // The generic deobf call/pop repair belongs to this event: Hex-Rays
        // has built a native flowchart, but has not generated microcode yet.
        // It is intentionally independent of CHERNOBOG_AUTO and distinct from
        // the later MMAT_LOCOPT deobfuscation pipeline.
        if ( self->early_hexrays != nullptr )
        {
            int changes = 0;
#if IDA_SDK_VERSION >= 940
            if ( ea_flowchart != nullptr )
            {
                changes = self->early_hexrays->on_flowchart(
                    ea_flowchart, reachable);
            }
            else
#endif
            if ( legacy_flowchart != nullptr )
            {
                changes = self->early_hexrays->on_flowchart(
                    legacy_flowchart, reachable);
            }
            if ( changes > 0 )
            {
                debug_log(
                    "[chernobog] hxe_flowchart added %d early CFG edges at %llx\n",
                    changes,
                    static_cast<unsigned long long>(function_ea));
            }
        }
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
    // A rebuilt cfunc needs its ctree-only rewrites applied to the new tree.
    // Do not clear whole-MBA tracking or rax evidence merely because a view was
    // rendered again: the manual action itself refreshes the view, and doing so
    // previously decrypted already-patched bytes a second time.
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
        }
    }
    // This event is reserved for generated-microcode repair. The installed
    // optinsn/optblock handlers still own the later deobfuscation pipeline;
    // running that whole pipeline here would duplicate work at an invalid
    // maturity.
    else if ( event == hxe_microcode )
    {
        mba_t *mba = va_arg(va, mba_t *);
        chernobog_begin_mba_tracking(mba);
        if ( mba != nullptr )
        {
            // Every generated MBA will produce a distinct ctree, even for the
            // same function under DECOMP_NO_CACHE. Reset only transient tree
            // guards; one-shot database/byte mutation state remains intact.
            const ea_t func_ea = mba->entry_ea;
            self->ctree_const_folded.erase(func_ea);
            self->ctree_switch_folded.erase(func_ea);
            self->ctree_indirect_call_processed.erase(func_ea);
            self->ctree_string_decrypt_processed.erase(func_ea);
        }
        const int changes = self->early_hexrays != nullptr
                          ? self->early_hexrays->on_microcode(mba) : 0;
        debug_log("[chernobog] hxe_microcode: mba=%p, auto=%d\n", mba, is_auto_mode_enabled() ? 1 : 0);
        if ( changes > 0 )
        {
            debug_log(
                "[chernobog] hxe_microcode converted %d resolved returns\n",
                changes);
        }
        if ( self->early_hexrays != nullptr )
        {
            const auto &stats = self->early_hexrays->stats();
            debug_log(
                "[chernobog] early Hex-Rays totals: flow_edges=%zu "
                "codegen_returns=%zu generated_gotos=%zu folds=%zu "
                "char_operands=%zu bounded_skips=%zu\n",
                stats.flowchart_edges, stats.codegen_returns,
                stats.generated_gotos, stats.folded_instructions,
                stats.character_operands, stats.bounded_skips);
        }
    }
    // Constant propagation and character-store numforms need the raw,
    // preoptimized MBA. LOCOPT is too late to be stage-equivalent because
    // these rewrites are intended to improve the optimizer's input.
    else if ( event == hxe_preoptimized )
    {
        mba_t *mba = va_arg(va, mba_t *);
        const int changes = self->early_hexrays != nullptr
                          ? self->early_hexrays->on_preoptimized(mba) : 0;
        if ( changes > 0 )
        {
            debug_log(
                "[chernobog] hxe_preoptimized applied %d early rewrites at %llx\n",
                changes,
                static_cast<unsigned long long>(
                    mba != nullptr ? mba->entry_ea : BADADDR));
        }
    }
    // Global optimization exposes exact register-defined tail targets that do
    // not exist at LOCOPT. Hex-Rays requires MERR_LOOP after any mutation at
    // this event so its global optimizer can rebuild coherent chains.
    else if ( event == hxe_glbopt )
    {
        mbl_array_t *mba = va_arg(va, mbl_array_t *);
        if ( mba && is_auto_mode_enabled() && !is_disabled_mode_enabled() )
        {
            deobf_ctx_t branch_ctx;
            branch_ctx.mba = mba;
            branch_ctx.func_ea = mba->entry_ea;
            int changes = 0;
            if ( chernobog_t::has_indirect_branches(mba) )
            {
                changes += chernobog_t::resolve_indirect_branches(
                    mba, &branch_ctx);
            }
            changes += chernobog::jump_optimizer_handler_t::
                run_local_constant_branches(mba, &branch_ctx);
            if ( changes > 0 )
            {
                chernobog::hybrid::hybrid_seal_deobfuscation_projection(
                    uint64_t(mba->entry_ea));
                debug_log(
                    "[chernobog] hxe_glbopt applied %d branch rewrites at %llx\n",
                    changes,
                    static_cast<unsigned long long>(mba->entry_ea));
                return compatible_merr_loop();
            }
        }
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
        }

        // Runtime plaintext is a current-function display feature, not an
        // automatic whole-database optimization. Outside AUTO mode, run this
        // handler only when this exact function owns display-eligible rax
        // strings; background/decompile-all cfuncs therefore remain untouched.
        const bool ctree_strings_ready = cfunc != nullptr
          && maturity == CMAT_FINAL && !is_disabled_mode_enabled();
        const bool runtime_strings_available = ctree_strings_ready
          && !chernobog::hybrid::
                hybrid_current_runtime_strings_for_decompilation(
                    uint64_t(cfunc->entry_ea)).empty();
        const bool static_strings_detected = ctree_strings_ready
          && is_auto_mode_enabled()
          && !runtime_strings_available
          && ctree_string_decrypt_handler_t::detect(cfunc);
        if ( ctree_strings_ready
          && (runtime_strings_available || static_strings_detected) )
        {
            const ea_t func_ea = cfunc->entry_ea;
            const auto processed =
                self->ctree_string_decrypt_processed.find(func_ea);
            if ( processed == self->ctree_string_decrypt_processed.end()
              || processed->second != cfunc )
            {
                self->ctree_string_decrypt_processed[func_ea] = cfunc;
                deobf_ctx_t str_ctx;
                str_ctx.cfunc = cfunc;
                str_ctx.func_ea = func_ea;
                const int changes = ctree_string_decrypt_handler_t::run(
                    cfunc, &str_ctx);
                if ( changes > 0 )
                    msg("[chernobog] Ctree string materialization: applied %d literals\n",
                        changes);
            }
        }
        if ( cfunc != nullptr && maturity == CMAT_FINAL )
        {
            chernobog::hybrid::hybrid_finish_deobfuscation_projection(
                uint64_t(cfunc->entry_ea));
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
    user_decompile_target = BADADDR;
    ctree_const_folded.clear();
    ctree_switch_folded.clear();
    ctree_indirect_call_processed.clear();
    ctree_string_decrypt_processed.clear();
    hikari_cfg_attempted = false;
    native_opaque_attempted = false;
    chernobog_clear_all_tracking();
    if ( hybrid_session )
        hybrid_session->clear();
    if ( early_hexrays )
        early_hexrays->reset();
}

bool chernobog_plugmod_t::recover_hikari_cfg_if_ready(bool force)
{
    debug_log(
        "[chernobog] CFG readiness: attempted=%d mode=%d auto_ok=%d force=%d\n",
        hikari_cfg_attempted ? 1 : 0, hikari_cfg_handler_t::mode(),
        auto_is_ok() ? 1 : 0, force ? 1 : 0);
    if ( hikari_cfg_attempted || hikari_cfg_handler_t::mode() == 0
      || (!force && !auto_is_ok()) )
    {
        return false;
    }

    // Mark before scheduling any analysis from reversible patches so the
    // ensuing auto_empty notification cannot recursively rerun the pass.
    hikari_cfg_attempted = true;
    const hikari_cfg_stats_t stats = hikari_cfg_handler_t::run();
    debug_log(
        "[chernobog] CFG stats: slots=%d indirect=%d recovered=%d patched=%d "
        "reachable=%d\n",
        stats.root_state_slots, stats.terminal_indirect_branches,
        stats.recovered_dispatchers, stats.patched_dispatchers,
        stats.reachable_functions);
    msg(
        "[chernobog] Hikari CFG recovery: %d/%d dispatchers, %d compact "
        "patches, %d reachable functions\n",
        stats.recovered_dispatchers, stats.terminal_indirect_branches,
        stats.patched_dispatchers, stats.reachable_functions);
    return stats.patched_dispatchers > 0;
}

bool chernobog_plugmod_t::recover_native_opaque_if_ready(bool force)
{
    debug_log(
        "[chernobog] Native predicate readiness: attempted=%d mode=%d "
        "auto_ok=%d force=%d\n",
        native_opaque_attempted ? 1 : 0, native_opaque_handler_t::mode(),
        auto_is_ok() ? 1 : 0, force ? 1 : 0);
    if ( native_opaque_attempted || native_opaque_handler_t::mode() == 0
      || is_disabled_mode_enabled() || (!force && !auto_is_ok()) )
    {
        return false;
    }

    native_opaque_attempted = true;
    const native_opaque_stats_t stats = native_opaque_handler_t::run();
    debug_log(
        "[chernobog] Native predicate stats: functions=%d blocks=%d "
        "conditional=%d proved=%d patched=%d\n",
        stats.functions_scanned, stats.blocks_scanned,
        stats.conditional_branches, stats.predicates_proved,
        stats.branches_patched);
    msg(
        "[chernobog] Native opaque predicates: %d/%d proved, %d reversible "
        "patches\n",
        stats.predicates_proved, stats.conditional_branches,
        stats.branches_patched);
    return stats.branches_patched > 0;
}

bool chernobog_plugmod_t::activate()
{
    debug_log("[chernobog] activate called, already_init=%d, dbctx=%lld\n",
        hexrays_initialized ? 1 : 0,
        static_cast<long long>(get_dbctx_id()));

    if ( hexrays_initialized )
        return true;

    msg("[chernobog] build=%s dirty=%s source=%s sdk=%s rax=%.12s "
        "dbctx=%lld\n",
        chernobog::build_provenance::revision,
        chernobog::build_provenance::dirty,
        chernobog::build_provenance::source_fingerprint,
        chernobog::build_provenance::ida_sdk,
        chernobog::build_provenance::rax_revision,
        static_cast<long long>(database_id));

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

    early_hexrays.reset(
        new chernobog::ida_analysis::EarlyHexRaysAnalysis());
    if ( !early_hexrays->install() )
    {
        msg("[chernobog] Early Hex-Rays call/pop codegen filter was not installed; callback-stage analysis remains active\n");
    }

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
        early_hexrays.reset();
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

    if ( ida_analysis && auto_is_ok() )
        ida_analysis->on_autoanalysis_complete();
    recover_hikari_cfg_if_ready();
    recover_native_opaque_if_ready();

    msg("[chernobog] Plugin ready (%d components initialized)\n", initialized);
    if ( auto_mode )
        msg("[chernobog] *** AUTO MODE ACTIVE - will deobfuscate on decompilation ***\n");

    msg("[chernobog] Use Ctrl+Shift+D to deobfuscate current function\n");
    msg("[chernobog] Use Ctrl+Shift+A to analyze obfuscation types\n");
    return true;
}

void chernobog_plugmod_t::schedule_activation_retry()
{
    if ( hexrays_initialized || activation_timer != nullptr )
        return;

    activation_attempts = 0;
    activation_timer = register_timer(
        100, activation_retry_callback, this);
    if ( activation_timer == nullptr )
    {
        // Timers are GUI-only. IDALib and idat retain event-driven retries at
        // database completion and at the first explicit plugin invocation.
        debug_log("[chernobog] Deferred activation timer unavailable\n");
    }
}

void chernobog_plugmod_t::cancel_activation_retry()
{
    if ( activation_timer != nullptr )
    {
        unregister_timer(activation_timer);
        activation_timer = nullptr;
    }
    activation_attempts = 0;
}

int idaapi chernobog_plugmod_t::activation_retry_callback(void *ud)
{
    chernobog_plugmod_t *self = static_cast<chernobog_plugmod_t *>(ud);
    if ( self == nullptr )
        return -1;

    ++self->activation_attempts;
    if ( self->activate() )
    {
        self->activation_timer = nullptr;
        self->activation_attempts = 0;
        return -1;
    }

    // Bound autonomous retries to 15 s. UI/plugin/database notifications can
    // still start a new bounded window after a material loader-state change.
    if ( self->activation_attempts >= 60 )
    {
        self->activation_timer = nullptr;
        msg("[chernobog] Hex-Rays activation retry window expired; "
            "manual plugin invocation will retry\n");
        return -1;
    }
    return 250;
}

void chernobog_plugmod_t::deactivate()
{
    if ( !hexrays_initialized && !components_initialized
      && early_hexrays == nullptr )
        return;

    // ui_destroying_plugmod invokes this while the decompiler dispatcher is
    // still valid. This prevents teardown calls after Hex-Rays module data is
    // destroyed, irrespective of plugin unload order.
    if ( get_hexdsp() == nullptr )
    {
        debug_log("[chernobog] Hex-Rays disappeared before teardown\n");
        if ( early_hexrays != nullptr )
        {
            early_hexrays->uninstall(false);
            early_hexrays.reset();
        }
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

    if ( early_hexrays != nullptr )
    {
        early_hexrays->uninstall(true);
        early_hexrays.reset();
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
    if ( self == nullptr || get_dbctx_id() != self->database_id )
        return 0;

    if ( event_id == ui_preprocess_action )
    {
        const char *name = va_arg(va, const char *);
        self->user_decompile_target = BADADDR;
        if ( is_user_pseudocode_action(name) )
        {
            const func_t *function = get_func(get_screen_ea());
            if ( function != nullptr )
                self->user_decompile_target = function->start_ea;
        }
    }
    else if ( event_id == ui_postprocess_action )
    {
        self->user_decompile_target = BADADDR;
    }
    else if ( event_id == ui_ready_to_run || event_id == ui_database_inited )
    {
        if ( !self->activate() )
            self->schedule_activation_retry();
    }
    else if ( event_id == ui_plugin_loaded )
    {
        // Retrying once per plugin load is bounded and also supports renamed
        // or cloud decompiler variants without relying on display strings.
        (void)va_arg(va, const plugin_info_t *);
        if ( !self->hexrays_initialized && !self->activate() )
            self->schedule_activation_retry();
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
    if ( self != nullptr && get_dbctx_id() == self->database_id )
    {
        if ( event_id == idb_event::closebase )
        {
            self->clear_processing_state();
            if ( self->ida_analysis )
                self->ida_analysis->reset();
        }
        else if ( event_id == idb_event::auto_empty_finally )
        {
            if ( !self->hexrays_initialized && !self->activate() )
                self->schedule_activation_retry();
            if ( self->ida_analysis )
                self->ida_analysis->on_autoanalysis_complete();
            self->recover_hikari_cfg_if_ready();
            self->recover_native_opaque_if_ready();
        }
    }
    return 0;
}

chernobog_plugmod_t::chernobog_plugmod_t()
{
    database_id = get_dbctx_id();
    debug_log("[chernobog] Per-IDB plugmod created, dbctx=%lld\n",
        static_cast<long long>(get_dbctx_id()));

    ida_analysis.reset(new chernobog::ida_analysis::NativeAnalysisEngine());
    hybrid_session.reset(new chernobog::hybrid::Session(
        static_cast<int64_t>(get_dbctx_id())));

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
        schedule_activation_retry();
    }
}

chernobog_plugmod_t::~chernobog_plugmod_t()
{
    cancel_activation_retry();
    if ( idb_hooked )
        unhook_from_notification_point(HT_IDB, idb_callback, this);
    if ( ui_hooked )
        unhook_from_notification_point(HT_UI, ui_callback, this);

    deactivate();
    clear_processing_state();
    hybrid_session.reset();
    debug_log("[chernobog] Per-IDB plugmod destroyed\n");
}

bool idaapi chernobog_plugmod_t::run(size_t argument)
{
    const bool ready = activate();
    if ( !ready )
        schedule_activation_retry();

    // IDA's text frontend does not register UI actions. A batch script can
    // invoke the same bounded session through ida_loader.run_plugin() after
    // setting CHERNOBOG_RAX_BATCH_EA. 0x524158 is ASCII "RAX".
    if ( argument == 0x524158 )
    {
        const bool explored = ready && hybrid_session != nullptr
            && hybrid_session->explore_batch_target();
        if ( explored )
            hybrid_session->show_last(nullptr);
        else
            msg("[chernobog][rax] Batch exploration failed: set "
                "CHERNOBOG_RAX_BATCH_EA to an address in a function\n");
        return explored;
    }

    // Headless, analysis-only CFF probe. This deliberately generates only
    // LOCOPT microcode and invokes the detector without enabling mutation
    // components, so regression tests can distinguish detector behavior from
    // full ctree construction cost. 0x434646 is ASCII "CFF".
    if ( argument == 0x434646 )
    {
        qstring raw;
        ea_t requested = BADADDR;
        if ( !qgetenv("CHERNOBOG_CFF_BATCH_EA", &raw) || raw.empty()
          || !str2ea(&requested, raw.c_str(), BADADDR) )
        {
            msg("[chernobog][cff-batch] Set CHERNOBOG_CFF_BATCH_EA to an "
                "address in a function\n");
            return false;
        }
        const ea_t function_ea = get_func_start(requested);
        if ( function_ea == BADADDR )
        {
            msg("[chernobog][cff-batch] No function contains %a\n", requested);
            return false;
        }

        hexrays_failure_t failure;
        std::unique_ptr<mba_t> mba(gen_microcode(
            decomp_ranges_t(function_ea),
            &failure,
            nullptr,
            DECOMP_NO_CACHE,
            MMAT_LOCOPT));
        if ( !mba )
        {
            msg("[chernobog][cff-batch] Microcode generation failed at %a: "
                "%s\n", function_ea, failure.desc().c_str());
            return false;
        }

        pattern_match::flatten_info_t info;
        const bool detected = pattern_match::detect_flatten_pattern(
            mba.get(), &info);
        msg("[chernobog][cff-batch] function=%a detected=%d kind=%d "
            "switch=%d dispatcher=%d cases=%zu returning=%zu direct=%zu "
            "frontier=%zu score=%u\n",
            function_ea,
            detected ? 1 : 0,
            static_cast<int>(info.kind),
            info.switch_block,
            info.dispatcher_block,
            info.case_count,
            info.returning_target_count,
            info.direct_return_target_count,
            info.return_frontier_count,
            info.confidence_score);
        return detected;
    }

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
    msg("To explore only the displayed function with rax:\n");
    msg("  Right-click and select 'Explore current function with rax'\n");
    msg("  Or press Ctrl+Shift+E\n\n");
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
