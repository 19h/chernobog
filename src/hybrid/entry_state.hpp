/*
 * entry_state.hpp -- ABI-aware, call-site-derived emulation inputs.
 *
 * This is a main-thread IDA producer. It asks IDA's register tracker for values
 * at real incoming call sites and expresses them in EmuInput's positional form;
 * EmuDriver remains entirely IDA-free.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "abi_policy.hpp"
#include "emu_driver.hpp"
#include "program_model.hpp"

namespace chernobog::hybrid {

struct EntryInputPlan
{
  HybridAbi abi = HybridAbi::UNKNOWN;
  std::string abi_name;
  std::vector<EmuInput> inputs;
};

HybridAbi hybrid_detect_abi(HybridArch arch);

// Collect up to max_inputs distinct incoming-call contexts. Unknown arguments
// retain the deterministic seeded value; only tracker-proven constants/addresses
// are overridden. Main thread only.
EntryInputPlan hybrid_build_entry_inputs(HybridArch arch, uint64_t function_start,
                                      size_t max_inputs);

} // namespace chernobog::hybrid
