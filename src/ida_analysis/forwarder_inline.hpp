#pragma once

#include "../common/warn_off.h"
#include <hexrays.hpp>
#include "../common/warn_on.h"

namespace chernobog::ida_analysis
{
// Inline bounded native call/return adapters during initial code generation.
merror_t inline_forwarders(codegen_t *codegen, int decomp_flags);
}
