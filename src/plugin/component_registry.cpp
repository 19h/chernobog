#include "component_registry.h"
#include "../common/warn_off.h"
#include <vector>
#include "../common/warn_on.h"

struct stored_component_t {
    component_desc_t d;
};

static std::vector<stored_component_t> &repo()
{
    static std::vector<stored_component_t> v;
    return v;
}

void component_registry_t::register_component(const component_desc_t &d)
{
    stored_component_t sc;
    sc.d = d;
    repo().push_back(sc);
}

size_t component_registry_t::get_count()
{
    return repo().size();
}

int component_registry_t::init_all()
{
    int inited = 0;
    for ( stored_component_t &sc: repo() )
    {
        const bool available = sc.d.avail == nullptr || sc.d.avail();
        const bool active = sc.d.active != nullptr && sc.d.active();
        if ( available && !active )
        {
            if ( sc.d.init )
                sc.d.init();
            if ( sc.d.active == nullptr || sc.d.active() )
                ++inited;
        }
    }
    return inited;
}

int component_registry_t::done_all()
{
    int donec = 0;
    for ( stored_component_t &sc: repo() )
    {
        if ( sc.d.active && sc.d.active() && sc.d.done )
        {
            sc.d.done();
            ++donec;
        }
    }
    return donec;
}

void component_registry_t::attach_to_popup(TWidget *widget, TPopupMenu *popup, vdui_t *vu)
{
    for ( stored_component_t &sc: repo() )
    {
        if ( sc.d.active && sc.d.active() && sc.d.attach_popup )
        {
            sc.d.attach_popup(widget, popup, vu);
        }
    }
}
