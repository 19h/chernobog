/*
 * The chernobog_* IDC function table.
 *
 * The interpreter table is process-wide; every entry point resolves the Host
 * bound to IDA's current database context and fails closed when none exists.
 * All functions run on the calling thread without EXTFUN_SAFE because they
 * reach Hex-Rays, the IDB, and the per-database rax session.
 *
 * Failures are reported through return values rather than IDC exceptions so a
 * script can branch on them: numeric entry points return 0/-1, address-valued
 * ones return BADADDR, and string-valued ones return "".
 */
#include "idc_api.h"

#include "../common/warn_off.h"
#include <hexrays.hpp>
#include <expr.hpp>
#include <auto.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <pro.h>
#include "../common/warn_on.h"

#include "component_registry.h"
#include "../deobf/deobf_main.h"
#include "../deobf/analysis/arch_utils.h"
#include "../deobf/analysis/pattern_match.h"
#include "../deobf/handlers/hikari_cfg.h"
#include "../deobf/handlers/native_opaque.h"
#include "../deobf/rules/rule_registry.h"
#include "../hybrid/evidence.hpp"
#include "../hybrid/hybrid_config.hpp"
#include "../hybrid/program_model.hpp"
#include "../hybrid/rax_loader.hpp"
#include "../hybrid/session.hpp"
#include "../hybrid/z3_bridge.hpp"
#include "../ida_analysis/early_hexrays.hpp"
#include "../ida_analysis/native_engine.hpp"

#include <chernobog/build_provenance.hpp>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace chernobog::idc {
namespace {

//--------------------------------------------------------------------------
// Host registry
//--------------------------------------------------------------------------
std::map<int64_t, Host *> &hosts()
{
    static std::map<int64_t, Host *> registry;
    return registry;
}

// The bound host for IDA's current database. Every entry point goes through
// this, so an IDC call issued while another IDB is active resolves to that
// IDB's plugmod or to nothing at all.
Host *current_host()
{
    const int64_t database_id = int64_t(get_dbctx_id());
    if ( database_id < 0 )
        return nullptr;
    const auto found = hosts().find(database_id);
    return found == hosts().end() ? nullptr : found->second;
}

// A host whose Hex-Rays lifecycle is installed. Deferred activation is
// retried here so a script that runs before ui_ready_to_run still works.
Host *ready_host()
{
    Host *host = current_host();
    if ( host == nullptr )
        return nullptr;
    if ( !host->hexrays_ready() && !host->ensure_activated() )
        return nullptr;
    return host;
}

//--------------------------------------------------------------------------
// idc_value_t helpers
//--------------------------------------------------------------------------
void make_object(idc_value_t *r)
{
    idcv_object(r);
}

void set_num(idc_value_t *obj, const char *key, sval_t value)
{
    const idc_value_t entry(value);
    set_idcv_attr(obj, key, entry);
}

void set_u64(idc_value_t *obj, const char *key, uint64_t value)
{
    // sval_t is 64-bit in every supported build, so an address or counter
    // round-trips exactly; IDC prints it with %a/%x as usual.
    set_num(obj, key, sval_t(value));
}

void set_size(idc_value_t *obj, const char *key, size_t value)
{
    set_num(obj, key, sval_t(value));
}

void set_bool(idc_value_t *obj, const char *key, bool value)
{
    set_num(obj, key, value ? 1 : 0);
}

void set_str(idc_value_t *obj, const char *key, const char *value)
{
    const idc_value_t entry(value != nullptr ? value : "");
    set_idcv_attr(obj, key, entry);
}

//--------------------------------------------------------------------------
// Argument helpers
//--------------------------------------------------------------------------
ea_t arg_ea(const idc_value_t &value)
{
    return ea_t(value.num);
}

// IDA converts declared arguments to the requested type, but reading qstr() on
// a value that is not VT_STR would reinterpret the union. Convert defensively
// and treat an unconvertible argument as empty.
qstring arg_string(const idc_value_t &value)
{
    if ( value.vtype == VT_STR )
        return value.qstr();
    idc_value_t converted(value);
    if ( idcv_string(&converted) != eOk || converted.vtype != VT_STR )
        return qstring();
    return converted.qstr();
}

// Option values arrive unconverted so that a number keeps its numeric type.
// IDC's own number-to-string conversion produces the *character* with that
// code, which is never what `chernobog_set_option("rax_runs", 4)` means, so
// format numbers here instead. Addresses need base-16 text because their
// consumers parse with str2ea(), whose default radix is processor-defined.
qstring arg_option_value(const idc_value_t &value, bool hexadecimal)
{
    qstring text;
    switch ( value.vtype )
    {
        case VT_LONG:
            if ( hexadecimal )
                text.sprnt("0x%llX", (unsigned long long)value.num);
            else
                text.sprnt("%lld", (long long)value.num);
            return text;
        case VT_INT64:
            if ( hexadecimal )
                text.sprnt("0x%llX", (unsigned long long)value.i64);
            else
                text.sprnt("%lld", (long long)value.i64);
            return text;
        default:
            return arg_string(value);
    }
}

// Resolve any address inside a function to its entry, matching how the popup
// actions and the batch probes interpret their targets.
ea_t resolve_function(const idc_value_t &value)
{
    const ea_t address = arg_ea(value);
    if ( address == BADADDR )
        return BADADDR;
    return get_func_start(address);
}

//--------------------------------------------------------------------------
// Obfuscation flag names
//--------------------------------------------------------------------------
#define CHERNOBOG_IDC_OBF_FLAGS(X)                     \
    X(flattened,      OBF_FLATTENED)                   \
    X(bogus_cf,       OBF_BOGUS_CF)                    \
    X(string_enc,     OBF_STRING_ENC)                  \
    X(const_enc,      OBF_CONST_ENC)                   \
    X(indirect_br,    OBF_INDIRECT_BR)                 \
    X(substitution,   OBF_SUBSTITUTION)                \
    X(split_blocks,   OBF_SPLIT_BLOCKS)                \
    X(func_wrapper,   OBF_FUNC_WRAPPER)                \
    X(identity_call,  OBF_IDENTITY_CALL)               \
    X(stack_string,   OBF_STACK_STRING)                \
    X(savedregs,      OBF_SAVEDREGS)                   \
    X(objc_obfusc,    OBF_OBJC_OBFUSC)                 \
    X(global_const,   OBF_GLOBAL_CONST)                \
    X(ptr_indirect,   OBF_PTR_INDIRECT)                \
    X(mba_complex,    OBF_MBA_COMPLEX)                 \
    X(chain_ops,      OBF_CHAIN_OPS)                   \
    X(opaque_jump,    OBF_OPAQUE_JUMP)                 \
    X(const_obfusc,   OBF_CONST_OBFUSC)                \
    X(indirect_call,  OBF_INDIRECT_CALL)               \
    X(vm_mba,         OBF_VM_MBA)                      \
    X(select_chain,   OBF_SELECT_CHAIN)

qstring obfuscation_names(uint32_t mask)
{
    qstring names;
#define X(name, flag)                                  \
    if ( (mask & uint32_t(flag)) != 0 )                \
    {                                                  \
        if ( !names.empty() )                          \
            names.append(',');                         \
        names.append(#name);                           \
    }
    CHERNOBOG_IDC_OBF_FLAGS(X)
#undef X
    return names;
}

void fill_obfuscation_object(idc_value_t *r, ea_t function_ea, uint32_t mask)
{
    make_object(r);
    set_u64(r, "ea", uint64_t(function_ea));
    set_num(r, "mask", sval_t(mask));
    set_str(r, "names", obfuscation_names(mask).c_str());
    set_bool(r, "any", mask != OBF_NONE);
#define X(name, flag) set_bool(r, #name, (mask & uint32_t(flag)) != 0);
    CHERNOBOG_IDC_OBF_FLAGS(X)
#undef X
}

//--------------------------------------------------------------------------
// Option table
//
// Chernobog's runtime policy is environment-driven throughout. The short
// aliases below cover every documented knob a script is likely to drive; any
// CHERNOBOG_-prefixed variable is also accepted verbatim so options added
// later need no change here.
//--------------------------------------------------------------------------
struct option_alias_t
{
    const char *alias;
    const char *variable;
    // True when a numeric value must be rendered as base-16 text because the
    // consumer parses it with str2ea() rather than a fixed-radix reader.
    bool address_valued;
    const char *summary;
};

const option_alias_t option_aliases[] = {
    { "auto", "CHERNOBOG_AUTO", false,
      "Emulate and deobfuscate every function submitted to Hex-Rays" },
    { "verbose", "CHERNOBOG_VERBOSE", false,
      "Verbose logging" },
    { "debug", "CHERNOBOG_DEBUG", false,
      "File-based debug logging (macOS/Linux)" },
    { "reset", "CHERNOBOG_RESET", false,
      "Clear the decompiler cache on activation" },
    { "disable", "CHERNOBOG_DISABLE", false,
      "Disable transformations, retaining the plugin lifecycle" },
    { "max_funcsize_kb", "CHERNOBOG_MAX_FUNCSIZE_KB", false,
      "Hex-Rays function-size ceiling in KiB for this process" },
    { "ida_analysis", "CHERNOBOG_IDA_ANALYSIS", false,
      "Native IDA analysis enrichment" },
    { "early_hexrays", "CHERNOBOG_IDA_EARLY_HEXRAYS", false,
      "Early flowchart/codegen/preoptimized passes" },
    { "hikari_cfg", "CHERNOBOG_HIKARI_CFG", false,
      "Hikari ARM64 dispatch recovery (1 annotate, 2 also patch)" },
    { "native_opaque", "CHERNOBOG_NATIVE_OPAQUE", false,
      "Pre-lifting ARM64 opaque predicate resolution" },
    { "patch_branches", "CHERNOBOG_PATCH_BRANCHES", false,
      "Reversibly patch proven ARM64 indirect tails" },
    { "writable_const", "CHERNOBOG_WRITABLE_CONST", false,
      "Writable scalar constant inlining tier (1 or 2)" },
    { "dead_global_stores", "CHERNOBOG_DEAD_GLOBAL_STORES", false,
      "Remove dead stores to auto-named writable scalars" },
    { "mba_affine", "CHERNOBOG_MBA_AFFINE", false,
      "Exact-Z3 affine MBA reconstruction" },
    { "vm", "CHERNOBOG_VM", false,
      "VM-family detection and rewriting" },
    { "vm_z3", "CHERNOBOG_VM_Z3", false,
      "Exact-Z3 VM residual simplification" },
    { "vm_carrier_pool", "CHERNOBOG_VM_CARRIER_POOL", false,
      "VM carrier constants" },
    { "rax", "CHERNOBOG_RAX_ENABLED", false,
      "rax exploratory emulation" },
    { "rax_runs", "CHERNOBOG_RAX_EXPLORE_RUNS", false,
      "Concrete runs per exploration (1..32)" },
    { "rax_max_insns", "CHERNOBOG_RAX_MAX_INSNS", false,
      "Instruction budget per concrete run" },
    { "rax_timeout_ms", "CHERNOBOG_RAX_TIMEOUT_MS", false,
      "Wall-clock budget per concrete run" },
    { "rax_log_level", "CHERNOBOG_RAX_LOG_LEVEL", false,
      "0 quiet, 1 summary, 2 trace" },
    { "rax_poll_ms", "CHERNOBOG_RAX_POLL_MS", false,
      "Completion polling interval" },
    { "rax_static", "CHERNOBOG_RAX_STATIC", false,
      "Static decode observations" },
    { "rax_smir", "CHERNOBOG_RAX_SMIR", false,
      "SMIR effect observations" },
    { "rax_runtime_strings", "CHERNOBOG_RAX_RUNTIME_STRINGS", false,
      "Consensus runtime string witnesses" },
    { "rax_apply_analysis", "CHERNOBOG_RAX_APPLY_ANALYSIS", false,
      "Materialize rax evidence into the IDB" },
    { "rax_min_dynamic_runs", "CHERNOBOG_RAX_MIN_DYNAMIC_RUNS", false,
      "Runs required before dynamic xrefs/types are applied" },
    { "rax_set_noret", "CHERNOBOG_RAX_SET_NORET", false,
      "Opt in to setting FUNC_NORET from evidence" },
    { "rax_switch", "CHERNOBOG_RAX_SWITCH", false,
      "Opt in to observed-target custom switch metadata" },
    { "rax_opaque", "CHERNOBOG_RAX_OPAQUE", false,
      "Opt in to observed-only opaque predicate comments" },
    { "rax_batch_ea", "CHERNOBOG_RAX_BATCH_EA", true,
      "Target for the 0x524158 batch plugin argument" },
    { "cff_batch_ea", "CHERNOBOG_CFF_BATCH_EA", true,
      "Target for the 0x434646 batch plugin argument" },
};

bool is_chernobog_variable(const char *name)
{
    static const char prefix[] = "CHERNOBOG_";
    return name != nullptr
        && strncmp(name, prefix, sizeof(prefix) - 1) == 0
        && name[sizeof(prefix) - 1] != '\0';
}

bool ends_with_address_suffix(const char *name)
{
    static const char suffix[] = "_EA";
    const size_t length = name != nullptr ? strlen(name) : 0;
    return length >= sizeof(suffix) - 1
        && strieq(name + length - (sizeof(suffix) - 1), suffix);
}

// An alias, or a CHERNOBOG_-prefixed variable used verbatim. Returns nullptr
// for anything else so a typo cannot silently create an unrelated variable.
// `address_valued` reports how a numeric value should be rendered; a verbatim
// variable is treated as address-valued when its name ends in _EA.
const char *resolve_option(const char *name, bool *address_valued = nullptr)
{
    if ( address_valued != nullptr )
        *address_valued = false;
    if ( name == nullptr || name[0] == '\0' )
        return nullptr;
    for ( const option_alias_t &option : option_aliases )
    {
        if ( strieq(option.alias, name) || strieq(option.variable, name) )
        {
            if ( address_valued != nullptr )
                *address_valued = option.address_valued;
            return option.variable;
        }
    }
    if ( !is_chernobog_variable(name) )
        return nullptr;
    if ( address_valued != nullptr )
        *address_valued = ends_with_address_suffix(name);
    return name;
}

bool option_is_true(const char *variable)
{
    qstring value;
    return qgetenv(variable, &value) && !value.empty()
        && value != "0" && !strieq(value.c_str(), "false")
        && !strieq(value.c_str(), "no") && !strieq(value.c_str(), "off");
}

//--------------------------------------------------------------------------
// Hex-Rays helpers
//--------------------------------------------------------------------------
// Uncached microcode at a chosen maturity. Analysis-only entry points use
// this so they never disturb the decompiler cache or the ctree pipeline.
std::unique_ptr<mba_t> generate_microcode(
    ea_t function_ea, mba_maturity_t maturity, qstring *error)
{
    hexrays_failure_t failure;
    std::unique_ptr<mba_t> mba(gen_microcode(
        decomp_ranges_t(function_ea),
        &failure,
        nullptr,
        DECOMP_NO_CACHE,
        maturity));
    if ( mba == nullptr && error != nullptr )
        *error = failure.desc();
    return mba;
}

bool decompile_text(ea_t function_ea, bool no_cache, qstring *out)
{
    func_t *function = get_func(function_ea);
    if ( function == nullptr )
        return false;
    hexrays_failure_t failure;
    cfuncptr_t cfunc = decompile(
        function, &failure, no_cache ? DECOMP_NO_CACHE : 0);
    if ( cfunc == nullptr )
    {
        msg("[chernobog][idc] Decompilation of %a failed: %s\n",
            function_ea, failure.desc().c_str());
        return false;
    }
    qstring_printer_t printer(cfunc, *out, false);
    cfunc->print_func(printer);
    return true;
}

//--------------------------------------------------------------------------
// chernobog_version() -> string
//--------------------------------------------------------------------------
error_t idaapi idc_version(idc_value_t *, idc_value_t *r)
{
    qstring text;
    text.sprnt("chernobog %s%s (source %s, IDA SDK %s, rax %.12s)",
        build_provenance::revision,
        streq(build_provenance::dirty, "1") ? "-dirty" : "",
        build_provenance::source_fingerprint,
        build_provenance::ida_sdk,
        build_provenance::rax_revision);
    r->set_string(text);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_status() -> object
//--------------------------------------------------------------------------
error_t idaapi idc_status(idc_value_t *, idc_value_t *r)
{
    Host *host = current_host();
    make_object(r);

    set_str(r, "revision", build_provenance::revision);
    set_bool(r, "dirty", streq(build_provenance::dirty, "1"));
    set_str(r, "source", build_provenance::source_fingerprint);
    set_str(r, "sdk", build_provenance::ida_sdk);
    set_str(r, "rax_revision", build_provenance::rax_revision);

    set_bool(r, "loaded", host != nullptr);
    set_num(r, "database_id", sval_t(get_dbctx_id()));
    set_bool(r, "hexrays", host != nullptr && host->hexrays_ready());
    set_bool(r, "components", host != nullptr && host->components_ready());
    set_size(r, "component_count", component_registry_t::get_count());
    // Not "auto": IDC reserves that word, so `status.auto` would not parse.
    set_bool(r, "auto_mode", host != nullptr && host->auto_mode());
    set_bool(r, "disabled",
        host != nullptr && host->transformations_disabled());
    set_bool(r, "verbose", deobf::verbose_enabled());

    const hybrid::HybridConfig rax = hybrid::hybrid_load_config();
    set_bool(r, "rax_enabled", rax.enabled);
    set_bool(r, "rax_available", hybrid::rax_available());
    set_str(r, "rax_unavailable_reason", hybrid::rax_unavailable_reason());
    set_num(r, "rax_runs", sval_t(rax.explore_runs));
    set_u64(r, "rax_max_insns", rax.max_insns);
    set_u64(r, "rax_timeout_ms", rax.timeout_ms);
    set_num(r, "rax_log_level", sval_t(rax.log_level));

    set_num(r, "hikari_cfg_mode", sval_t(hikari_cfg_handler_t::mode()));
    set_num(r, "native_opaque_mode", sval_t(native_opaque_handler_t::mode()));

    const rules::RuleRegistry &registry = rules::RuleRegistry::instance();
    set_size(r, "rule_count", registry.rule_count());
    set_size(r, "pattern_count", registry.pattern_count());

    set_bool(r, "arm64", arch::is_arm64());
    set_bool(r, "x86_64", arch::is_x86_64());
    set_size(r, "idc_functions", function_count());
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_activate() -> long
//--------------------------------------------------------------------------
error_t idaapi idc_activate(idc_value_t *, idc_value_t *r)
{
    Host *host = current_host();
    r->set_long(host != nullptr && host->ensure_activated() ? 1 : 0);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_get_option(name) -> string
//--------------------------------------------------------------------------
error_t idaapi idc_get_option(idc_value_t *argv, idc_value_t *r)
{
    const qstring name = arg_string(argv[0]);
    const char *variable = resolve_option(name.c_str());
    qstring value;
    if ( variable != nullptr )
        qgetenv(variable, &value);
    r->set_string(value);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_set_option(name, value) -> long
//
// Declared variadic so the value keeps its IDC type: a converted VT_STR
// argument would turn the number 4 into the character with code 4.
//--------------------------------------------------------------------------
error_t idaapi idc_set_option(idc_value_t *argv, idc_value_t *r)
{
    const sval_t argument_count = r->num;
    if ( argument_count < 2 )
    {
        msg("[chernobog][idc] chernobog_set_option(name, value) needs two "
            "arguments\n");
        r->set_long(0);
        return eOk;
    }

    const qstring name = arg_string(argv[0]);
    bool address_valued = false;
    const char *variable = resolve_option(name.c_str(), &address_valued);
    if ( variable == nullptr )
    {
        msg("[chernobog][idc] Unknown option '%s'; use an alias from "
            "chernobog_list_options() or a CHERNOBOG_-prefixed variable\n",
            name.c_str());
        r->set_long(0);
        return eOk;
    }

    const qstring value = arg_option_value(argv[1], address_valued);
    if ( !qsetenv(variable, value.c_str()) )
    {
        msg("[chernobog][idc] Could not set %s\n", variable);
        r->set_long(0);
        return eOk;
    }

    // Two settings are cached rather than re-read per use; apply them now so
    // the option takes effect for the current process instead of the next.
    if ( streq(variable, "CHERNOBOG_AUTO") )
    {
        Host *host = current_host();
        if ( host != nullptr )
            host->set_auto_mode(option_is_true(variable));
    }
    else if ( streq(variable, "CHERNOBOG_VERBOSE") )
    {
        deobf::set_verbose(option_is_true(variable));
    }
    r->set_long(1);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_list_options() -> string
//--------------------------------------------------------------------------
error_t idaapi idc_list_options(idc_value_t *, idc_value_t *r)
{
    qstring text;
    for ( const option_alias_t &option : option_aliases )
    {
        qstring value;
        qgetenv(option.variable, &value);
        text.cat_sprnt("%-22s %-34s %-12s %s\n",
            option.alias, option.variable,
            value.empty() ? "<unset>" : value.c_str(), option.summary);
    }
    r->set_string(text);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_obf_names(mask) -> string
//--------------------------------------------------------------------------
error_t idaapi idc_obf_names(idc_value_t *argv, idc_value_t *r)
{
    r->set_string(obfuscation_names(uint32_t(argv[0].num)));
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_detect(ea) -> object
//
// Analysis only: uncached LOCOPT microcode, no mutation components, no
// decompiler cache entry.
//--------------------------------------------------------------------------
error_t idaapi idc_detect(idc_value_t *argv, idc_value_t *r)
{
    const ea_t function_ea = resolve_function(argv[0]);
    if ( ready_host() == nullptr || function_ea == BADADDR )
    {
        fill_obfuscation_object(r, function_ea, OBF_NONE);
        set_bool(r, "ok", false);
        set_str(r, "error",
            function_ea == BADADDR ? "no function at the given address"
                                   : "Hex-Rays is not available");
        return eOk;
    }

    qstring error;
    const std::unique_ptr<mba_t> mba =
        generate_microcode(function_ea, MMAT_LOCOPT, &error);
    if ( mba == nullptr )
    {
        fill_obfuscation_object(r, function_ea, OBF_NONE);
        set_bool(r, "ok", false);
        set_str(r, "error", error.c_str());
        msg("[chernobog][idc] Microcode generation failed at %a: %s\n",
            function_ea, error.c_str());
        return eOk;
    }

    const uint32_t mask = chernobog_t::detect_obfuscations(mba.get());
    fill_obfuscation_object(r, function_ea, mask);
    set_bool(r, "ok", true);
    set_str(r, "error", "");
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_analyze(ea) -> long
//
// The Ctrl+Shift+A action: decompiles and prints the candidate report.
//--------------------------------------------------------------------------
error_t idaapi idc_analyze(idc_value_t *argv, idc_value_t *r)
{
    const ea_t function_ea = resolve_function(argv[0]);
    if ( ready_host() == nullptr || function_ea == BADADDR )
    {
        r->set_long(-1);
        return eOk;
    }
    chernobog_t::analyze_function(function_ea);
    r->set_long(1);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_detect_flatten(ea) -> object
//
// The 0x434646 (ASCII "CFF") batch probe, callable without an environment
// variable or a plugin argument.
//--------------------------------------------------------------------------
void fill_flatten_object(
    idc_value_t *r,
    ea_t function_ea,
    bool ok,
    bool detected,
    const pattern_match::flatten_info_t &info,
    const char *error)
{
    make_object(r);
    set_u64(r, "ea", uint64_t(function_ea));
    set_bool(r, "ok", ok);
    set_str(r, "error", error);
    set_bool(r, "detected", detected);
    set_num(r, "kind", sval_t(info.kind));
    set_num(r, "dispatcher_block", sval_t(info.dispatcher_block));
    set_num(r, "switch_block", sval_t(info.switch_block));
    set_num(r, "loop_entry_block", sval_t(info.loop_entry_block));
    set_num(r, "loop_end_block", sval_t(info.loop_end_block));
    set_size(r, "case_count", info.case_count);
    set_size(r, "returning_target_count", info.returning_target_count);
    set_size(r, "direct_return_target_count",
        info.direct_return_target_count);
    set_size(r, "return_frontier_count", info.return_frontier_count);
    set_size(r, "dispatcher_block_count", info.dispatcher_blocks.size());
    set_size(r, "state_count", info.state_to_block.size());
    set_num(r, "confidence_score", sval_t(info.confidence_score));
}

error_t idaapi idc_detect_flatten(idc_value_t *argv, idc_value_t *r)
{
    const pattern_match::flatten_info_t empty;
    const ea_t function_ea = resolve_function(argv[0]);
    if ( ready_host() == nullptr || function_ea == BADADDR )
    {
        fill_flatten_object(r, function_ea, false, false, empty,
            function_ea == BADADDR ? "no function at the given address"
                                   : "Hex-Rays is not available");
        return eOk;
    }

    qstring error;
    const std::unique_ptr<mba_t> mba =
        generate_microcode(function_ea, MMAT_LOCOPT, &error);
    if ( mba == nullptr )
    {
        fill_flatten_object(
            r, function_ea, false, false, empty, error.c_str());
        return eOk;
    }

    pattern_match::flatten_info_t info;
    const bool detected =
        pattern_match::detect_flatten_pattern(mba.get(), &info);
    fill_flatten_object(r, function_ea, true, detected, info, "");
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_deobfuscate(ea) -> long
//
// Exactly the Ctrl+Shift+D action, without a pseudocode widget.
//--------------------------------------------------------------------------
error_t idaapi idc_deobfuscate(idc_value_t *argv, idc_value_t *r)
{
    const ea_t function_ea = resolve_function(argv[0]);
    if ( ready_host() == nullptr || function_ea == BADADDR )
    {
        r->set_long(0);
        return eOk;
    }
    chernobog_request_function_deobfuscation(function_ea);
    chernobog_t::deobfuscate_function(function_ea);
    r->set_long(1);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_deobfuscate_text(ea) -> string
//
// One-call orchestration primitive: admit the function, drop its tracking so
// the optimizer pipeline runs again, decompile without the cache, and return
// the resulting pseudocode.
//--------------------------------------------------------------------------
error_t idaapi idc_deobfuscate_text(idc_value_t *argv, idc_value_t *r)
{
    const ea_t function_ea = resolve_function(argv[0]);
    if ( ready_host() == nullptr || function_ea == BADADDR )
    {
        r->set_string("");
        return eOk;
    }

    chernobog_request_function_deobfuscation(function_ea);
    chernobog_clear_function_tracking(function_ea);

    qstring text;
    if ( !decompile_text(function_ea, true, &text) )
    {
        r->set_string("");
        return eOk;
    }
    r->set_string(text);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_decompile(ea) -> string
//--------------------------------------------------------------------------
error_t idaapi idc_decompile(idc_value_t *argv, idc_value_t *r)
{
    const ea_t function_ea = resolve_function(argv[0]);
    qstring text;
    if ( ready_host() == nullptr || function_ea == BADADDR
      || !decompile_text(function_ea, false, &text) )
    {
        r->set_string("");
        return eOk;
    }
    r->set_string(text);
    return eOk;
}

//--------------------------------------------------------------------------
// Bounded database sweep shared by the range and whole-database entry points
//--------------------------------------------------------------------------
void deobfuscate_range(ea_t start, ea_t end, idc_value_t *r)
{
    make_object(r);
    set_bool(r, "ok", true);
    set_u64(r, "start", uint64_t(start));
    set_u64(r, "end", uint64_t(end));
    set_size(r, "considered", 0);
    set_size(r, "processed", 0);
    set_bool(r, "cancelled", false);

    size_t considered = 0;
    size_t processed = 0;
    size_t cancelled = 0;

    const size_t function_count = get_func_qty();
    for ( size_t index = 0; index < function_count; ++index )
    {
        func_t *function = getn_func(index);
        if ( function == nullptr || (function->flags & FUNC_TAIL) != 0 )
            continue;
        if ( function->start_ea < start || function->start_ea >= end )
            continue;
        ++considered;

        if ( user_cancelled() )
        {
            cancelled = 1;
            break;
        }

        const ea_t function_ea = function->start_ea;
        chernobog_request_function_deobfuscation(function_ea);
        chernobog_clear_function_tracking(function_ea);
        chernobog_t::deobfuscate_function(function_ea);
        ++processed;
    }

    set_size(r, "considered", considered);
    set_size(r, "processed", processed);
    set_bool(r, "cancelled", cancelled != 0);
    msg("[chernobog][idc] Deobfuscated %zu of %zu functions in %a..%a%s\n",
        processed, considered, start, end,
        cancelled != 0 ? " (cancelled)" : "");
}

void empty_sweep_object(idc_value_t *r, ea_t start, ea_t end)
{
    make_object(r);
    set_bool(r, "ok", false);
    set_u64(r, "start", uint64_t(start));
    set_u64(r, "end", uint64_t(end));
    set_size(r, "considered", 0);
    set_size(r, "processed", 0);
    set_bool(r, "cancelled", false);
}

//--------------------------------------------------------------------------
// chernobog_deobfuscate_range(start, end) -> object
//--------------------------------------------------------------------------
error_t idaapi idc_deobfuscate_range(idc_value_t *argv, idc_value_t *r)
{
    const ea_t start = arg_ea(argv[0]);
    const ea_t end = arg_ea(argv[1]);
    if ( ready_host() == nullptr )
    {
        empty_sweep_object(r, start, end);
        return eOk;
    }
    deobfuscate_range(start, end, r);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_deobfuscate_all() -> object
//--------------------------------------------------------------------------
error_t idaapi idc_deobfuscate_all(idc_value_t *, idc_value_t *r)
{
    if ( ready_host() == nullptr )
    {
        empty_sweep_object(r, 0, BADADDR);
        return eOk;
    }
    deobfuscate_range(0, BADADDR, r);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_request(ea) -> long
//
// Admit one function without decompiling it now. The next decompilation --
// interactive, scripted, or automatic -- runs the full pipeline for it.
//--------------------------------------------------------------------------
error_t idaapi idc_request(idc_value_t *argv, idc_value_t *r)
{
    const ea_t function_ea = resolve_function(argv[0]);
    if ( function_ea == BADADDR )
    {
        r->set_long(0);
        return eOk;
    }
    chernobog_request_function_deobfuscation(function_ea);
    r->set_long(1);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_enabled_for(ea) -> long
//--------------------------------------------------------------------------
error_t idaapi idc_enabled_for(idc_value_t *argv, idc_value_t *r)
{
    const ea_t function_ea = resolve_function(argv[0]);
    r->set_long(function_ea != BADADDR
             && chernobog_function_deobfuscation_enabled(function_ea) ? 1 : 0);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_pending(ea) -> long
//--------------------------------------------------------------------------
error_t idaapi idc_pending(idc_value_t *argv, idc_value_t *r)
{
    const ea_t function_ea = resolve_function(argv[0]);
    r->set_long(function_ea != BADADDR
             && chernobog_function_requires_deobfuscation(function_ea)
              ? 1 : 0);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_clear_function(ea) -> long
//--------------------------------------------------------------------------
error_t idaapi idc_clear_function(idc_value_t *argv, idc_value_t *r)
{
    const ea_t function_ea = resolve_function(argv[0]);
    if ( function_ea == BADADDR )
    {
        r->set_long(0);
        return eOk;
    }
    chernobog_clear_function_tracking(function_ea);
    hybrid::Session *session = current_host() != nullptr
                             ? current_host()->rax_session() : nullptr;
    if ( session != nullptr )
        session->invalidate_function(uint64_t(function_ea));
    r->set_long(1);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_clear_all() -> long
//--------------------------------------------------------------------------
error_t idaapi idc_clear_all(idc_value_t *, idc_value_t *r)
{
    Host *host = current_host();
    if ( host == nullptr )
    {
        chernobog_clear_all_tracking();
        r->set_long(0);
        return eOk;
    }
    host->clear_state();
    r->set_long(1);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_clear_cache() -> long
//--------------------------------------------------------------------------
error_t idaapi idc_clear_cache(idc_value_t *, idc_value_t *r)
{
    if ( ready_host() == nullptr )
    {
        r->set_long(0);
        return eOk;
    }
    clear_cached_cfuncs();
    r->set_long(1);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_hikari_cfg() -> object
//--------------------------------------------------------------------------
error_t idaapi idc_hikari_cfg(idc_value_t *, idc_value_t *r)
{
    make_object(r);
    hikari_cfg_stats_t stats;
    Host *host = current_host();
    const bool ran = host != nullptr && host->run_hikari_cfg(&stats);
    set_bool(r, "ran", ran);
    set_num(r, "mode", sval_t(hikari_cfg_handler_t::mode()));
    set_num(r, "root_state_slots", sval_t(stats.root_state_slots));
    set_num(r, "terminal_indirect_branches",
        sval_t(stats.terminal_indirect_branches));
    set_num(r, "recovered_dispatchers", sval_t(stats.recovered_dispatchers));
    set_num(r, "patched_dispatchers", sval_t(stats.patched_dispatchers));
    set_num(r, "reachable_functions", sval_t(stats.reachable_functions));
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_native_opaque() -> object
//--------------------------------------------------------------------------
error_t idaapi idc_native_opaque(idc_value_t *, idc_value_t *r)
{
    make_object(r);
    native_opaque_stats_t stats;
    Host *host = current_host();
    const bool ran = host != nullptr && host->run_native_opaque(&stats);
    set_bool(r, "ran", ran);
    set_num(r, "mode", sval_t(native_opaque_handler_t::mode()));
    set_num(r, "functions_scanned", sval_t(stats.functions_scanned));
    set_num(r, "blocks_scanned", sval_t(stats.blocks_scanned));
    set_num(r, "conditional_branches", sval_t(stats.conditional_branches));
    set_num(r, "predicates_proved", sval_t(stats.predicates_proved));
    set_num(r, "branches_patched", sval_t(stats.branches_patched));
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_native_analysis() -> object
//
// Re-runs the one-shot native enrichment engine and reports its cumulative
// per-database counters.
//--------------------------------------------------------------------------
error_t idaapi idc_native_analysis(idc_value_t *, idc_value_t *r)
{
    Host *host = current_host();
    ida_analysis::NativeAnalysisEngine *engine =
        host != nullptr ? host->native_analysis_engine() : nullptr;
    const bool enabled = engine != nullptr && engine->enabled();
    if ( enabled )
        engine->on_autoanalysis_complete();

    const ida_analysis::NativeAnalysisStats fallback;
    const ida_analysis::NativeAnalysisStats &stats =
        engine != nullptr ? engine->stats() : fallback;

    make_object(r);
    set_bool(r, "ran", enabled);
    set_bool(r, "enabled", enabled);
    set_size(r, "redundant_prefixes", stats.redundant_prefixes);
    set_size(r, "get_pc_gadgets", stats.get_pc_gadgets);
    set_size(r, "push_return_targets", stats.push_return_targets);
    set_size(r, "zero_register_branches", stats.zero_register_branches);
    set_size(r, "opposite_branch_pairs", stats.opposite_branch_pairs);
    set_size(r, "entry_predicates", stats.entry_predicates);
    set_size(r, "known_flag_branches", stats.known_flag_branches);
    set_size(r, "indirect_targets", stats.indirect_targets);
    set_size(r, "gaps_retyped", stats.gaps_retyped);
    set_size(r, "get_pc_tail_extensions", stats.get_pc_tail_extensions);
    set_size(r, "orphan_functions", stats.orphan_functions);
    set_size(r, "outlined_wrappers", stats.outlined_wrappers);
    set_size(r, "post_scan_heads", stats.post_scan_heads);
    set_size(r, "post_scan_functions", stats.post_scan_functions);
    set_bool(r, "post_scan_truncated", stats.post_scan_truncated);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_early_stats() -> object
//--------------------------------------------------------------------------
error_t idaapi idc_early_stats(idc_value_t *, idc_value_t *r)
{
    Host *host = current_host();
    ida_analysis::EarlyHexRaysAnalysis *early =
        host != nullptr ? host->early_hexrays_analysis() : nullptr;
    const ida_analysis::EarlyHexRaysStats fallback;
    const ida_analysis::EarlyHexRaysStats &stats =
        early != nullptr ? early->stats() : fallback;

    make_object(r);
    set_bool(r, "available", early != nullptr);
    set_bool(r, "enabled", early != nullptr && early->enabled());
    set_size(r, "flowchart_edges", stats.flowchart_edges);
    set_size(r, "codegen_returns", stats.codegen_returns);
    set_size(r, "generated_gotos", stats.generated_gotos);
    set_size(r, "folded_instructions", stats.folded_instructions);
    set_size(r, "character_operands", stats.character_operands);
    set_size(r, "bounded_skips", stats.bounded_skips);
    return eOk;
}

//--------------------------------------------------------------------------
// rax exploratory emulation
//--------------------------------------------------------------------------
const char *ensure_result_name(hybrid::EnsureExploredResult result)
{
    switch ( result )
    {
        case hybrid::EnsureExploredResult::ALREADY_FRESH: return "already_fresh";
        case hybrid::EnsureExploredResult::EXPLORED:      return "explored";
        case hybrid::EnsureExploredResult::DISABLED:      return "disabled";
        case hybrid::EnsureExploredResult::UNAVAILABLE:   return "unavailable";
        case hybrid::EnsureExploredResult::CANCELLED:     return "cancelled";
        case hybrid::EnsureExploredResult::FAILED:        return "failed";
    }
    return "unknown";
}

const char *arch_name(hybrid::HybridArch value)
{
    switch ( value )
    {
        case hybrid::HybridArch::UNSUPPORTED: return "unsupported";
        case hybrid::HybridArch::X86_16:      return "x86_16";
        case hybrid::HybridArch::X86_32:      return "x86_32";
        case hybrid::HybridArch::X86_64:      return "x86_64";
        case hybrid::HybridArch::ARM64:       return "arm64";
        case hybrid::HybridArch::ARM32:       return "arm32";
        case hybrid::HybridArch::RISCV64:     return "riscv64";
        case hybrid::HybridArch::CORTEX_M:    return "cortex_m";
        case hybrid::HybridArch::HEXAGON:     return "hexagon";
    }
    return "unknown";
}

const char *edge_kind_name(hybrid::ExecEdge::Kind kind)
{
    switch ( kind )
    {
        case hybrid::ExecEdge::Kind::Unknown: return "unknown";
        case hybrid::ExecEdge::Kind::Call:    return "call";
        case hybrid::ExecEdge::Kind::Jump:    return "jump";
        case hybrid::ExecEdge::Kind::Return:  return "return";
    }
    return "unknown";
}

hybrid::Session *current_session()
{
    Host *host = current_host();
    return host != nullptr ? host->rax_session() : nullptr;
}

//--------------------------------------------------------------------------
// chernobog_rax_explore(ea) -> long
//
// The bounded, synchronous prerequisite the deobfuscation pipeline uses. It
// reuses exact fresh evidence, waits for a matching in-flight job, or
// explores only this function; it never sweeps the database.
//--------------------------------------------------------------------------
error_t idaapi idc_rax_explore(idc_value_t *argv, idc_value_t *r)
{
    const ea_t function_ea = resolve_function(argv[0]);
    hybrid::Session *session =
        ready_host() != nullptr ? current_session() : nullptr;
    if ( session == nullptr || function_ea == BADADDR )
    {
        r->set_long(sval_t(hybrid::EnsureExploredResult::UNAVAILABLE));
        return eOk;
    }
    const hybrid::EnsureExploredResult result =
        session->ensure_explored(uint64_t(function_ea));
    r->set_long(sval_t(result));
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_rax_result_name(code) -> string
//--------------------------------------------------------------------------
error_t idaapi idc_rax_result_name(idc_value_t *argv, idc_value_t *r)
{
    r->set_string(ensure_result_name(
        hybrid::EnsureExploredResult(uint8_t(argv[0].num))));
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_rax_fresh(ea) -> long
//--------------------------------------------------------------------------
error_t idaapi idc_rax_fresh(idc_value_t *argv, idc_value_t *r)
{
    const ea_t function_ea = resolve_function(argv[0]);
    r->set_long(function_ea != BADADDR
             && hybrid::hybrid_current_evidence_is_fresh(
                    uint64_t(function_ea)) ? 1 : 0);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_rax_show() -> long
//--------------------------------------------------------------------------
error_t idaapi idc_rax_show(idc_value_t *, idc_value_t *r)
{
    hybrid::Session *session = current_session();
    if ( session == nullptr )
    {
        r->set_long(0);
        return eOk;
    }
    session->show_last(nullptr);
    r->set_long(1);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_rax_cancel() -> long
//--------------------------------------------------------------------------
error_t idaapi idc_rax_cancel(idc_value_t *, idc_value_t *r)
{
    hybrid::Session *session = current_session();
    if ( session == nullptr )
    {
        r->set_long(0);
        return eOk;
    }
    session->cancel();
    r->set_long(1);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_rax_clear() -> long
//--------------------------------------------------------------------------
error_t idaapi idc_rax_clear(idc_value_t *, idc_value_t *r)
{
    hybrid::Session *session = current_session();
    if ( session == nullptr )
    {
        r->set_long(0);
        return eOk;
    }
    session->clear();
    r->set_long(1);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_rax_summary(ea) -> object
//--------------------------------------------------------------------------
#define CHERNOBOG_IDC_EVIDENCE_FIELDS(X)               \
    X(ida_instruction_heads)                           \
    X(static_instructions)                             \
    X(ida_macro_heads)                                 \
    X(ida_macro_components)                            \
    X(smir_effects)                                    \
    X(completed_runs)                                  \
    X(returned_runs)                                   \
    X(definitive_terminal_runs)                        \
    X(instruction_budget_runs)                         \
    X(timeout_runs)                                    \
    X(escaped_image_runs)                              \
    X(function_boundary_runs)                          \
    X(unmodeled_external_runs)                         \
    X(environment_model_failure_runs)                  \
    X(external_model_runs)                             \
    X(synthetic_entry_context_runs)                    \
    X(attempted_steps_unknown_runs)                    \
    X(summarized_calls)                                \
    X(executed_instruction_addresses)                  \
    X(executed_addresses_without_static_record)        \
    X(conditional_observations)                        \
    X(conditional_sites)                               \
    X(predicate_state_inputs)                          \
    X(indirect_targets)                                \
    X(indirect_sites)                                  \
    X(unique_indirect_targets)                         \
    X(image_reads)                                     \
    X(image_writes)                                    \
    X(final_write_ranges)                              \
    X(pointer_value_reads)                             \
    X(executable_pointer_reads)                        \
    X(self_modifying_ranges)                           \
    X(decoder_disagreements)                           \
    X(decoder_disagreement_flags)                      \
    X(decoder_comparisons)                             \
    X(decoder_size_disagreements)                      \
    X(decoder_flow_disagreements)                      \
    X(decoder_target_disagreements)                    \
    X(decoder_fallthrough_disagreements)               \
    X(context_identity_ranges)                         \
    X(permission_violating_runs)                       \
    X(memory_observation_requested_runs)               \
    X(memory_observation_available_runs)               \
    X(context_incomplete_runs)

error_t idaapi idc_rax_summary(idc_value_t *argv, idc_value_t *r)
{
    const ea_t function_ea = resolve_function(argv[0]);
    hybrid::Session *session = current_session();
    std::shared_ptr<const hybrid::TargetEvidence> evidence =
        session != nullptr ? session->evidence() : nullptr;
    // Evidence belongs to exactly one function at a time; a request for any
    // other function reports "unavailable" rather than the wrong function's
    // observations.
    const bool matches = evidence != nullptr && function_ea != BADADDR
        && evidence->scope.function_start == uint64_t(function_ea);

    const hybrid::TargetEvidence fallback;
    const hybrid::TargetEvidence &data = matches ? *evidence : fallback;

    make_object(r);
    set_u64(r, "ea", uint64_t(function_ea));
    set_bool(r, "available", matches);
    set_bool(r, "fresh", matches
        && hybrid::hybrid_current_evidence_is_fresh(uint64_t(function_ea)));
    set_u64(r, "generation", data.scope.generation);
    set_u64(r, "function_hash", data.scope.function_hash);
    set_u64(r, "image_hash", data.scope.image_hash);
    set_u64(r, "focus", data.scope.focus_address);
    set_str(r, "arch", arch_name(data.architecture));
    set_str(r, "name", data.function_profile.name.c_str());
    set_str(r, "objc_selector", data.function_profile.objc_selector.c_str());
    set_size(r, "explicit_arguments",
        data.function_profile.explicit_arguments);
    set_bool(r, "explicit_arguments_known",
        data.function_profile.explicit_arguments_known);
    set_size(r, "inputs", data.inputs.size());
    set_size(r, "runs", data.runs.size());
    set_size(r, "branches", data.branches.size());
    set_size(r, "indirect_observations", data.indirect_targets.size());
    set_str(r, "diagnostic", data.diagnostic.c_str());
    set_u64(r, "context_identity_bytes",
        data.summary.context_identity_bytes);
#define X(field) set_size(r, #field, data.summary.field);
    CHERNOBOG_IDC_EVIDENCE_FIELDS(X)
#undef X
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_rax_string_count(ea) -> long
// chernobog_rax_string(ea, index) -> object
//
// Consensus NUL-terminated runtime witnesses: identical bytes at the same
// image address in every run for which final memory was observable. They are
// cross-run witnesses, never universal claims.
//--------------------------------------------------------------------------
std::vector<hybrid::RuntimeStringCandidate> runtime_strings(ea_t function_ea)
{
    if ( function_ea == BADADDR )
        return {};
    return hybrid::hybrid_current_runtime_strings(uint64_t(function_ea));
}

error_t idaapi idc_rax_string_count(idc_value_t *argv, idc_value_t *r)
{
    r->set_long(sval_t(runtime_strings(resolve_function(argv[0])).size()));
    return eOk;
}

error_t idaapi idc_rax_string(idc_value_t *argv, idc_value_t *r)
{
    const std::vector<hybrid::RuntimeStringCandidate> candidates =
        runtime_strings(resolve_function(argv[0]));
    const sval_t index = argv[1].num;
    const bool valid = index >= 0 && size_t(index) < candidates.size();

    const hybrid::RuntimeStringCandidate fallback;
    const hybrid::RuntimeStringCandidate &candidate =
        valid ? candidates[size_t(index)] : fallback;

    make_object(r);
    set_bool(r, "ok", valid);
    set_u64(r, "address", candidate.address);
    set_str(r, "value", candidate.value.c_str());
    set_size(r, "length", candidate.value.size());
    set_size(r, "observations", candidate.observations);
    set_size(r, "eligible_runs", candidate.eligible_runs);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_rax_target_count(ea, insn_ea) -> long
// chernobog_rax_target(ea, insn_ea, index) -> object
//
// Observation-only candidates for an unresolved call/jump. Repeated concrete
// runs cannot establish that no other target exists, so there is deliberately
// no "unique target" entry point.
//--------------------------------------------------------------------------
std::vector<hybrid::HybridObservedTargetCandidate> indirect_targets(
    ea_t function_ea, ea_t instruction)
{
    if ( function_ea == BADADDR || instruction == BADADDR )
        return {};
    return hybrid::hybrid_current_indirect_target_candidates(
        uint64_t(function_ea), uint64_t(instruction));
}

error_t idaapi idc_rax_target_count(idc_value_t *argv, idc_value_t *r)
{
    r->set_long(sval_t(indirect_targets(
        resolve_function(argv[0]), arg_ea(argv[1])).size()));
    return eOk;
}

error_t idaapi idc_rax_target(idc_value_t *argv, idc_value_t *r)
{
    const std::vector<hybrid::HybridObservedTargetCandidate> candidates =
        indirect_targets(resolve_function(argv[0]), arg_ea(argv[1]));
    const sval_t index = argv[2].num;
    const bool valid = index >= 0 && size_t(index) < candidates.size();

    const hybrid::HybridObservedTargetCandidate fallback;
    const hybrid::HybridObservedTargetCandidate &candidate =
        valid ? candidates[size_t(index)] : fallback;

    make_object(r);
    set_bool(r, "ok", valid);
    set_u64(r, "target", candidate.target);
    set_str(r, "kind", edge_kind_name(candidate.kind));
    set_size(r, "observations", candidate.observations);
    set_size(r, "runs", candidate.runs.size());
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_rax_branch(ea, insn_ea, expected_taken) -> object
//
// Cross-check a universal branch claim against concrete observations. `veto`
// is true only when a context-complete run contradicts the claim.
//--------------------------------------------------------------------------
error_t idaapi idc_rax_branch(idc_value_t *argv, idc_value_t *r)
{
    const ea_t function_ea = resolve_function(argv[0]);
    const ea_t instruction = arg_ea(argv[1]);
    const bool addressable = function_ea != BADADDR && instruction != BADADDR;

    const hybrid::HybridBranchCheck check = addressable
        ? hybrid::hybrid_check_current_branch_claim(
              uint64_t(function_ea), uint64_t(instruction), argv[2].num != 0)
        : hybrid::HybridBranchCheck();

    make_object(r);
    set_bool(r, "available", check.evidence_available);
    set_bool(r, "current", check.snapshot_current);
    set_u64(r, "generation", check.generation);
    set_bool(r, "veto", check.veto());
    set_num(r, "verdict", sval_t(check.claim.verdict));
    set_str(r, "verdict_name",
        hybrid::hybrid_branch_verdict_name(check.claim.verdict));
    set_size(r, "matching", check.claim.matching);
    set_size(r, "opposing", check.claim.opposing);
    set_size(r, "opposing_context_complete",
        check.claim.opposing_context_complete);
    set_size(r, "other", check.claim.other);
    return eOk;
}

//--------------------------------------------------------------------------
// MBA rule registry
//--------------------------------------------------------------------------
error_t idaapi idc_rule_stats(idc_value_t *, idc_value_t *r)
{
    make_object(r);
    const rules::RuleRegistry &registry = rules::RuleRegistry::instance();
    set_bool(r, "initialized", registry.is_initialized());
    set_size(r, "rules", registry.rule_count());
    set_size(r, "patterns", registry.pattern_count());
    set_size(r, "verified", registry.verified_rule_count());
    set_size(r, "rejected", registry.rejected_rule_count());
    set_size(r, "total_matches", registry.total_matches());
    set_size(r, "successful_matches", registry.successful_matches());
    return eOk;
}

error_t idaapi idc_rule_count(idc_value_t *, idc_value_t *r)
{
    r->set_long(sval_t(rules::RuleRegistry::instance().rule_count()));
    return eOk;
}

error_t idaapi idc_rule_name(idc_value_t *argv, idc_value_t *r)
{
    const std::vector<std::string> names =
        rules::RuleRegistry::instance().list_rules();
    const sval_t index = argv[0].num;
    r->set_string(index >= 0 && size_t(index) < names.size()
        ? names[size_t(index)].c_str() : "");
    return eOk;
}

error_t idaapi idc_rule_hits(idc_value_t *argv, idc_value_t *r)
{
    const std::map<std::string, size_t> statistics =
        rules::RuleRegistry::instance().get_hit_statistics();
    const auto found = statistics.find(arg_string(argv[0]).c_str());
    r->set_long(found == statistics.end() ? -1 : sval_t(found->second));
    return eOk;
}

error_t idaapi idc_rule_reset_stats(idc_value_t *, idc_value_t *r)
{
    rules::RuleRegistry::instance().clear_statistics();
    r->set_long(1);
    return eOk;
}

//--------------------------------------------------------------------------
// chernobog_help() -> string
//--------------------------------------------------------------------------
error_t idaapi idc_help(idc_value_t *, idc_value_t *r);

//--------------------------------------------------------------------------
// Function table
//--------------------------------------------------------------------------
const char args_none[] = { 0 };
const char args_ea[] = { VT_LONG, 0 };
const char args_long[] = { VT_LONG, 0 };
const char args_str[] = { VT_STR, 0 };
// Variadic so the option value reaches the handler unconverted.
const char args_str_value[] = { VT_STR, VT_WILD, 0 };
const char args_ea_ea[] = { VT_LONG, VT_LONG, 0 };
const char args_ea_long[] = { VT_LONG, VT_LONG, 0 };
const char args_ea_ea_long[] = { VT_LONG, VT_LONG, VT_LONG, 0 };

struct idc_entry_t
{
    const char *name;
    idc_func_t *handler;
    const char *args;
    const char *signature;
    const char *summary;
};

const idc_entry_t idc_entries[] = {
    // Introspection and lifecycle
    { "chernobog_help", idc_help, args_none,
      "chernobog_help()",
      "This table as text" },
    { "chernobog_version", idc_version, args_none,
      "chernobog_version()",
      "Build revision, source fingerprint, SDK, and pinned rax revision" },
    { "chernobog_status", idc_status, args_none,
      "chernobog_status()",
      "Lifecycle, mode, rax, rule, and architecture state" },
    { "chernobog_activate", idc_activate, args_none,
      "chernobog_activate()",
      "Install the Hex-Rays lifecycle now; 1 when ready" },

    // Options
    { "chernobog_get_option", idc_get_option, args_str,
      "chernobog_get_option(name)",
      "Current value of an option alias or CHERNOBOG_ variable" },
    { "chernobog_set_option", idc_set_option, args_str_value,
      "chernobog_set_option(name, value)",
      "Set an option for this process; 1 on success" },
    { "chernobog_list_options", idc_list_options, args_none,
      "chernobog_list_options()",
      "Aliases, variables, current values, and descriptions" },

    // Analysis
    { "chernobog_detect", idc_detect, args_ea,
      "chernobog_detect(ea)",
      "Obfuscation candidates from uncached LOCOPT microcode" },
    { "chernobog_obf_names", idc_obf_names, args_long,
      "chernobog_obf_names(mask)",
      "Comma-separated names for an obfuscation mask" },
    { "chernobog_analyze", idc_analyze, args_ea,
      "chernobog_analyze(ea)",
      "Print the Ctrl+Shift+A candidate report" },
    { "chernobog_detect_flatten", idc_detect_flatten, args_ea,
      "chernobog_detect_flatten(ea)",
      "Control-flow flattening detector evidence" },

    // Transformation
    { "chernobog_deobfuscate", idc_deobfuscate, args_ea,
      "chernobog_deobfuscate(ea)",
      "Run the Ctrl+Shift+D action on one function" },
    { "chernobog_deobfuscate_text", idc_deobfuscate_text, args_ea,
      "chernobog_deobfuscate_text(ea)",
      "Admit, re-decompile uncached, and return the pseudocode" },
    { "chernobog_decompile", idc_decompile, args_ea,
      "chernobog_decompile(ea)",
      "Pseudocode for a function without forcing a new pass" },
    { "chernobog_deobfuscate_range", idc_deobfuscate_range, args_ea_ea,
      "chernobog_deobfuscate_range(start, end)",
      "Deobfuscate every function entry in [start, end)" },
    { "chernobog_deobfuscate_all", idc_deobfuscate_all, args_none,
      "chernobog_deobfuscate_all()",
      "Deobfuscate every function in the database" },

    // Admission and tracking
    { "chernobog_request", idc_request, args_ea,
      "chernobog_request(ea)",
      "Admit a function for the next decompilation" },
    { "chernobog_enabled_for", idc_enabled_for, args_ea,
      "chernobog_enabled_for(ea)",
      "1 when auto mode or an explicit request admits this function" },
    { "chernobog_pending", idc_pending, args_ea,
      "chernobog_pending(ea)",
      "1 when the LOCOPT pipeline has not completed for this function" },
    { "chernobog_clear_function", idc_clear_function, args_ea,
      "chernobog_clear_function(ea)",
      "Drop per-function tracking and rax evidence" },
    { "chernobog_clear_all", idc_clear_all, args_none,
      "chernobog_clear_all()",
      "Drop every cache and tracking set for this database" },
    { "chernobog_clear_cache", idc_clear_cache, args_none,
      "chernobog_clear_cache()",
      "Clear the Hex-Rays decompiler cache" },

    // Native, pre-Hex-Rays passes
    { "chernobog_hikari_cfg", idc_hikari_cfg, args_none,
      "chernobog_hikari_cfg()",
      "Run Hikari ARM64 dispatch recovery and report its statistics" },
    { "chernobog_native_opaque", idc_native_opaque, args_none,
      "chernobog_native_opaque()",
      "Run pre-lifting opaque predicate resolution" },
    { "chernobog_native_analysis", idc_native_analysis, args_none,
      "chernobog_native_analysis()",
      "Run native IDA analysis enrichment and report its counters" },
    { "chernobog_early_stats", idc_early_stats, args_none,
      "chernobog_early_stats()",
      "Cumulative early Hex-Rays pass counters" },

    // rax exploratory emulation
    { "chernobog_rax_explore", idc_rax_explore, args_ea,
      "chernobog_rax_explore(ea)",
      "Bounded synchronous exploration of one function" },
    { "chernobog_rax_result_name", idc_rax_result_name, args_long,
      "chernobog_rax_result_name(code)",
      "Name for a chernobog_rax_explore() result code" },
    { "chernobog_rax_fresh", idc_rax_fresh, args_ea,
      "chernobog_rax_fresh(ea)",
      "1 when exact evidence for this function is still current" },
    { "chernobog_rax_show", idc_rax_show, args_none,
      "chernobog_rax_show()",
      "Print the last evidence report" },
    { "chernobog_rax_cancel", idc_rax_cancel, args_none,
      "chernobog_rax_cancel()",
      "Stop queued runs at the next instruction boundary" },
    { "chernobog_rax_clear", idc_rax_clear, args_none,
      "chernobog_rax_clear()",
      "Discard the session and its published evidence" },
    { "chernobog_rax_summary", idc_rax_summary, args_ea,
      "chernobog_rax_summary(ea)",
      "Scope, provenance, and every evidence counter" },
    { "chernobog_rax_string_count", idc_rax_string_count, args_ea,
      "chernobog_rax_string_count(ea)",
      "Number of consensus runtime string witnesses" },
    { "chernobog_rax_string", idc_rax_string, args_ea_long,
      "chernobog_rax_string(ea, index)",
      "One runtime string witness by index" },
    { "chernobog_rax_target_count", idc_rax_target_count, args_ea_ea,
      "chernobog_rax_target_count(ea, insn_ea)",
      "Number of observed targets for an indirect call/jump" },
    { "chernobog_rax_target", idc_rax_target, args_ea_ea_long,
      "chernobog_rax_target(ea, insn_ea, index)",
      "One observed indirect target by index" },
    { "chernobog_rax_branch", idc_rax_branch, args_ea_ea_long,
      "chernobog_rax_branch(ea, insn_ea, expected_taken)",
      "Cross-check a universal branch claim against observations" },

    // MBA rule registry
    { "chernobog_rule_stats", idc_rule_stats, args_none,
      "chernobog_rule_stats()",
      "Registry size, verification outcome, and match counters" },
    { "chernobog_rule_count", idc_rule_count, args_none,
      "chernobog_rule_count()",
      "Number of registered MBA rules" },
    { "chernobog_rule_name", idc_rule_name, args_long,
      "chernobog_rule_name(index)",
      "Name of a registered rule by index" },
    { "chernobog_rule_hits", idc_rule_hits, args_str,
      "chernobog_rule_hits(name)",
      "Hit count for one rule; -1 when the name is unknown" },
    { "chernobog_rule_reset_stats", idc_rule_reset_stats, args_none,
      "chernobog_rule_reset_stats()",
      "Reset per-rule hit counters" },
};

error_t idaapi idc_help(idc_value_t *, idc_value_t *r)
{
    qstring text("Chernobog IDC functions:\n");
    for ( const idc_entry_t &entry : idc_entries )
        text.cat_sprnt("  %-50s %s\n", entry.signature, entry.summary);
    text.append(
        "\nAddress arguments accept any address inside a function. Numeric\n"
        "entry points return 0 or -1 on failure and string entry points\n"
        "return \"\"; object results carry an 'ok' or 'available' attribute.\n");
    r->set_string(text);
    return eOk;
}

// Functions actually accepted by the interpreter, which is what the status
// object and the startup banner report.
size_t registered_functions = 0;

void register_functions()
{
    if ( registered_functions != 0 )
        return;
    for ( const idc_entry_t &entry : idc_entries )
    {
        ext_idcfunc_t descriptor;
        descriptor.name = entry.name;
        descriptor.fptr = entry.handler;
        descriptor.args = entry.args;
        descriptor.defvals = nullptr;
        descriptor.ndefvals = 0;
        descriptor.flags = EXTFUN_BASE;
        if ( add_idc_func(descriptor) )
            ++registered_functions;
        else
            msg("[chernobog][idc] Could not register %s\n", entry.name);
    }
}

void unregister_functions()
{
    if ( registered_functions == 0 )
        return;
    for ( const idc_entry_t &entry : idc_entries )
        del_idc_func(entry.name);
    registered_functions = 0;
}

} // namespace

//--------------------------------------------------------------------------
// Public entry points
//--------------------------------------------------------------------------
bool install(Host *host)
{
    if ( host == nullptr )
        return false;
    register_functions();
    // A partial table would leave scripts calling undefined functions, so
    // report failure and keep whatever did register for diagnosis.
    if ( registered_functions != qnumber(idc_entries) )
        return false;
    hosts()[host->database_context()] = host;
    return true;
}

void uninstall(Host *host)
{
    if ( host == nullptr )
        return;
    const auto found = hosts().find(host->database_context());
    // A database context can be reused after close/open; only remove the
    // binding when it still points at this host.
    if ( found != hosts().end() && found->second == host )
        hosts().erase(found);
    if ( hosts().empty() )
        unregister_functions();
}

size_t function_count()
{
    return registered_functions;
}

} // namespace chernobog::idc
