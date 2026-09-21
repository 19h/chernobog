#pragma once
#include <cstdint>
#include <string>
namespace chernobog::hybrid { struct TargetEvidence; }
namespace chernobog::vm {
// Main-thread, bounded, read-only recognition in the selected IDA function.
std::string inspect_regions(uint64_t function, bool include_summaries=false,
    const hybrid::TargetEvidence *source=nullptr, uint64_t revision=0, bool fresh=false,
    bool validate_transitions=false);
}
