#include "runtime_settings.h"

#include "../common/warn_off.h"
#include <hexrays.hpp>
#include <kernwin.hpp>
#include "../common/warn_on.h"

#include "idc_api.h"

namespace chernobog::runtime_settings
{
bool show(vdui_t *view)
{
    ushort automatic = idc::runtime_auto_mode() ? 1 : 0;
    const auto old_writable = idc::runtime_option("writable_const");
    const auto old_objects = idc::runtime_option("stack_alias_objects");
    int writable = !old_writable.empty() && old_writable[0] == '2'   ? 2
                   : !old_writable.empty() && old_writable[0] == '1' ? 1
                                                                     : 0;
    ushort objects = old_objects == "1" ? 1 : 0;
    const ushort old_automatic = automatic;
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
        "Apply refreshes the current pseudocode with the selected settings.\n"
        "\n"
        "<#Run Chernobog whenever a function is decompiled#Automatic deobfuscation:C1>>\n"
        "\n"
        "<#Assume admitted writable bytes retain their initial values#Writable data constants:b2:0:28::>\n"
        "Writable data is treated as stable initial values in either enabled mode.\n"
        "\n"
        "<#Assume exposed stack objects cannot access unrelated stack objects#Bounded stack objects:C3>>\n"
        "Allows private state-pointer recovery across calls and indirect writes.\n"
        "Assumes accesses stay within the exposed stack objects.\n"
        "\n";

    if (ask_form(form, &automatic, &choices, &writable, &objects) <= 0)
        return false;
    if (writable < 0 || writable >= int(choices.size()))
        return false;

    const char *mode = writable == 2 ? "2" : writable == 1 ? "1" : "0";
    if (!idc::set_runtime_option("writable_const", mode) ||
        !idc::set_runtime_option("stack_alias_objects", objects ? "1" : "0") ||
        !idc::set_runtime_option("auto", automatic ? "1" : "0"))
    {
        idc::set_runtime_option("writable_const", old_writable.c_str());
        idc::set_runtime_option("stack_alias_objects", old_objects.c_str());
        idc::set_runtime_option("auto", old_automatic ? "1" : "0");
        warning("Chernobog could not apply the runtime settings.");
        return false;
    }

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
