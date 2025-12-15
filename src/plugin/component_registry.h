#pragma once
#include "../common/warn_off.h"
#include <hexrays.hpp>
#include "../common/warn_on.h"

// Component registry for modular deobfuscator architecture
// Each deobfuscation pass registers as a component

struct component_desc_t {
    bool (*avail)();
    bool (*active)();
    void (*init)();
    void (*done)();
    void (*attach_popup)(TWidget *widget, TPopupMenu *popup, vdui_t *vu);
    const char *long_name;
    const char *short_name;
    const char *action_prefix;
};

class component_registry_t {
public:
    static void register_component(const component_desc_t &d);
    static size_t get_count();
    static int init_all();
    static int done_all();
    static void attach_to_popup(TWidget *widget, TPopupMenu *popup, vdui_t *vu);
    static void unregister_all_actions();
};

// Registration helper macro
#define REGISTER_COMPONENT(AVAIL, ACTIVE, INIT, DONE, ATTACH, LNAME, SNAME, APREFIX) \
namespace {                                                                        \
 struct component_registrar_t_##SNAME {                                           \
   component_registrar_t_##SNAME() {                                              \
     component_desc_t d;                                                          \
     d.avail = AVAIL; d.active = ACTIVE; d.init = INIT; d.done = DONE;            \
     d.attach_popup = ATTACH;                                                     \
     d.long_name = LNAME; d.short_name = #SNAME; d.action_prefix = #APREFIX;      \
     component_registry_t::register_component(d);                                 \
   }                                                                              \
 };                                                                               \
 static component_registrar_t_##SNAME g_component_registrar_##SNAME;              \
}
