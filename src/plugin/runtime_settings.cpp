#include "runtime_settings.h"

#include "../common/warn_off.h"
#include <hexrays.hpp>
#include <kernwin.hpp>
#include "../common/warn_on.h"

#include "idc_api.h"
#include "../hybrid/hybrid_config.hpp"

#include <utility>
#include <vector>

namespace chernobog::runtime_settings
{
namespace
{
using option_values_t = std::vector<std::pair<std::string, std::string>>;

bool apply_options(const option_values_t &values, const option_values_t &original)
{
    for (const auto &option : values)
    {
        if (idc::set_runtime_option(option.first.c_str(), option.second.c_str()))
            continue;
        for (const auto &saved : original)
            idc::set_runtime_option(saved.first.c_str(), saved.second.c_str());
        warning("Chernobog could not apply the runtime settings.");
        return false;
    }
    return true;
}
} // namespace

bool show(vdui_t *view)
{
    static const char *names[] = {"auto",
                                  "rax",
                                  "rax_runs",
                                  "rax_timeout_ms",
                                  "rax_max_insns",
                                  "mba_smt",
                                  "mba_affine",
                                  "mba_backend",
                                  "inline_forwarders",
                                  "writable_const",
                                  "stack_alias_objects",
                                  "verbose"};
    option_values_t original;
    for (const char *name : names)
        original.emplace_back(name, idc::runtime_option(name));
    const bool automatic = idc::runtime_auto_mode();
    original.front().second = automatic ? "1" : "0";
    const auto rax = hybrid::hybrid_load_config();
    ushort execution = (automatic ? 1 : 0) | (rax.enabled ? 2 : 0);
    uval_t runs = rax.explore_runs;
    uval_t timeout = rax.timeout_ms;
    uval_t instructions = rax.max_insns;
    const auto affine = idc::runtime_option("mba_affine");
    ushort processing = (idc::runtime_option("mba_smt") != "0" ? 1 : 0) |
                        (!affine.empty() && affine[0] == '1' ? 2 : 0) |
                        (idc::runtime_option("inline_forwarders") != "0" ? 4 : 0);
    const auto backend_option = idc::runtime_option("mba_backend");
    int backend = backend_option == "cobra" ? 1 : backend_option == "legacy" ? 2 : 0;
    qstrvec_t backends;
    backends.push_back("Default");
    backends.push_back("CoBRA");
    backends.push_back("Legacy");
    const auto old_writable = idc::runtime_option("writable_const");
    int writable = !old_writable.empty() && old_writable[0] == '2'   ? 2
                   : !old_writable.empty() && old_writable[0] == '1' ? 1
                                                                     : 0;
    ushort objects = idc::runtime_option("stack_alias_objects") == "1" ? 1 : 0;
    const auto verbose_option = idc::runtime_option("verbose");
    ushort verbose = !verbose_option.empty() && verbose_option != "0" &&
                             !strieq(verbose_option.c_str(), "false") &&
                             !strieq(verbose_option.c_str(), "no") &&
                             !strieq(verbose_option.c_str(), "off")
                         ? 1
                         : 0;
    qstrvec_t choices;
    choices.push_back("Disabled");
    choices.push_back("Scalars");
    choices.push_back("Scalars and arrays");

    static const char form[] =
        "BUTTON YES* Apply\n"
        "BUTTON CANCEL Cancel\n"
        "Chernobog runtime settings\n"
        "\n"
        "Applies to this IDA process. Settings reset when IDA closes.\n"
        "Apply refreshes the current pseudocode.\n"
        "\n"
        "Execution\n"
        "<#Process each function when it is decompiled#Automatic deobfuscation:C1>\n"
        "<#Use bounded emulation to gather runtime evidence#RAX emulation:C2>>\n"
        "RAX can be disabled while static processing remains enabled.\n"
        "<Runs:u3:2:4::> <Time per run (ms):u4:5:7::>\n"
        "<Instructions per run:u5:9:12::>\n"
        "\n"
        "Static processing\n"
        "<#Synthesize and prove MBA simplifications with bounded SMT queries#SMT MBA synthesis:C6>\n"
        "<#Enable additional exact-Z3 affine reconstruction#Affine MBA reconstruction:C7>\n"
        "<#Inline supported AMD64 call/return adapters#Inline forwarding wrappers:C8>>\n"
        "<MBA backend:b9:0:24::>\n"
        "Fast MBA rules and other static simplifications do not require RAX.\n"
        "\n"
        "Memory assumptions\n"
        "<#Assume admitted writable bytes retain their initial values#Writable data constants:b10:0:24::>\n"
        "<#Assume exposed stack objects cannot access unrelated stack objects#Bounded stack objects:C11>>\n"
        "These options assume stable writable values and bounded object accesses.\n"
        "\n"
        "<#Print detailed Chernobog progress in the output window#Verbose logging:C12>>\n"
        "\n";

    while (true)
    {
        if (ask_form(form, &execution, &runs, &timeout, &instructions, &processing, &backends,
                     &backend, &choices, &writable, &objects, &verbose) <= 0)
            return false;
        if (runs >= 1 && runs <= 32 && timeout >= 1 && timeout <= hybrid::kHybridHardTimeoutMs &&
            instructions >= 1 && instructions <= hybrid::kHybridHardMaxInstructions &&
            backend >= 0 && backend < 3 && writable >= 0 && writable < 3)
            break;
        warning("Use 1..32 RAX runs, 1..60000 ms per run, and 1..100000000 instructions per run.");
    }

    const option_values_t values = {
        {"rax", (execution & 2) ? "1" : "0"},
        {"rax_runs", std::to_string(runs)},
        {"rax_timeout_ms", std::to_string(timeout)},
        {"rax_max_insns", std::to_string(instructions)},
        {"mba_smt", (processing & 1) ? "1" : "0"},
        {"mba_affine", (processing & 2) ? "1" : "0"},
        {"inline_forwarders", (processing & 4) ? "1" : "0"},
        {"mba_backend", backend == 1   ? "cobra"
                        : backend == 2 ? "legacy"
                                       : "auto"},
        {"writable_const", std::to_string(writable)},
        {"stack_alias_objects", objects ? "1" : "0"},
        {"verbose", verbose ? "1" : "0"},
        {"auto", (execution & 1) ? "1" : "0"},
    };
    if (!apply_options(values, original))
        return false;

    const ea_t entry = view != nullptr && view->cfunc ? view->cfunc->entry_ea : BADADDR;
    idc::clear_runtime_state();
    clear_cached_cfuncs();
    if (entry != BADADDR)
    {
        mark_cfunc_dirty(entry, false);
        view->refresh_view(true);
    }
    return true;
}
} // namespace chernobog::runtime_settings
