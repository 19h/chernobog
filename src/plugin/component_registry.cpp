#include "component_registry.h"
#include "../common/warn_off.h"
#include <vector>
#include "../common/warn_on.h"

struct stored_component_t {
    component_desc_t d;
    bool initialized = false;
};

static std::vector<stored_component_t> &repo() {
    static std::vector<stored_component_t> v;
    return v;
}

void component_registry_t::register_component(const component_desc_t &d) {
    stored_component_t sc;
    sc.d = d;
    sc.initialized = false;
    repo().push_back(sc);
}

size_t component_registry_t::get_count() {
    return repo().size();
}

int component_registry_t::init_all() {
    int inited = 0;
    for (stored_component_t &sc: repo()) {
        if (sc.d.avail && sc.d.avail()) {
            if (sc.d.init)
                sc.d.init();
            sc.initialized = true;
            ++inited;
        }
    }
    return inited;
}

int component_registry_t::done_all() {
    int donec = 0;
    for (stored_component_t &sc: repo()) {
        if (sc.initialized && sc.d.done) {
            sc.d.done();
            sc.initialized = false;
            ++donec;
        }
    }
    return donec;
}

void component_registry_t::attach_to_popup(TWidget *widget, TPopupMenu *popup, vdui_t *vu) {
    for (stored_component_t &sc: repo()) {
        if (sc.initialized && sc.d.attach_popup) {
            sc.d.attach_popup(widget, popup, vu);
        }
    }
}

void component_registry_t::unregister_all_actions() {
    // Components manage their own action registration/unregistration in init/done
}
