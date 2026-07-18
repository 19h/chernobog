/* IDA-free classification of named external call boundaries. */
#pragma once

#include <optional>
#include <string>

#include "emu_driver.hpp"

namespace chernobog::hybrid {

std::string hybrid_canonical_call_name(const std::string &raw);
std::optional<EmuSummaryKind> hybrid_classify_call_summary_name(
    const std::string &raw);

} // namespace chernobog::hybrid
