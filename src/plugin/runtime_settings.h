#pragma once

struct vdui_t;

namespace chernobog::runtime_settings
{
// Returns false on Cancel or failure. The view is optional for IDC callers.
bool show(vdui_t *view);
}
