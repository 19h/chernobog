/*
 * emu_input.hpp -- IDA-free explicit entry state for one emulation run.
 */
#pragma once

#include <cstdint>
#include <vector>

namespace chernobog::hybrid {

// Explicit entry-state material supplied by ABI/call-site analysis. When
// values are absent the deterministic seed corpus remains the fallback.
struct EmuInput
{
  struct ArgOverride
  {
    uint32_t index = 0;
    uint64_t value = 0;
  };
  struct RegisterOverride
  {
    int reg = -1; // rax register id, for explicit/custom calling conventions
    uint64_t value = 0;
  };
  uint64_t seed = 0;
  uint32_t run_id = 0;
  // Physical ABI position at which `args[0]` is placed.  Zero preserves the
  // historical whole-ABI convention. Objective-C solver replays use two so
  // source-level explicit parameters do not overwrite `self` and `_cmd`.
  uint32_t positional_argument_offset = 0;
  std::vector<uint64_t> args;
  std::vector<ArgOverride> arg_overrides;
  std::vector<RegisterOverride> register_overrides;
  std::vector<uint64_t> stack_args;

  // Compatibility field for persisted/scheduled requests built before the
  // ABI policy was centralized. Zero means "infer from ABI". A non-zero value
  // must match the selected ABI's home/shadow area or the input is rejected.
  uint32_t stack_arg_offset = 0;
};

} // namespace chernobog::hybrid
