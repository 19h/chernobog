/* Main-thread discovery of well-known callable environment summaries. */
#pragma once

#include <cstddef>
#include <vector>

#include "emu_driver.hpp"
#include "program_model.hpp"

namespace chernobog::hybrid {

// Classify only named direct call targets referenced by the selected function.
// This is a bounded context read, not a database-wide name/function scan; the
// returned entries are POD and safe to hand to workers.
std::vector<EmuCallSummary> hybrid_collect_call_summaries(
    const FuncRange &function, size_t maximum_instruction_heads);

} // namespace chernobog::hybrid
