#pragma once
#include <cstdint>
#include <string>
#include "native_region.hpp"
#include <map>
namespace chernobog::hybrid
{
struct TargetEvidence;
struct EmuEvents;
struct EmuOutcome;
}
namespace chernobog::vm
{
// Main-thread, bounded, read-only recognition anchored at the selected function.
// Existing xrefs can expose ownerless code; foreign functions stop traversal.
// This inspection never assigns VM execution ownership.
std::string inspect_regions(uint64_t function, bool include_summaries = false,
                            const hybrid::TargetEvidence *source = nullptr, uint64_t revision = 0,
                            bool fresh = false, bool validate_transitions = false);
// Re-decode exact planned bytes without inferring IDA/VM ownership or entries.
// Unsupported local semantic instructions remain explicit Op::unsupported.
bool decode_native_semantic_heads(const NativeRegion &, unsigned mode,
                                  std::map<uint64_t, Instruction> &);
// Read-only local hypotheses from exact entered native instructions. No IDB
// ownership, single-entry or VM identity assertion follows from a captured path.
std::string inspect_observed_vm_candidates(const NativeRegion &, const hybrid::EmuEvents &,
                                           const hybrid::EmuOutcome &, unsigned mode);
}
