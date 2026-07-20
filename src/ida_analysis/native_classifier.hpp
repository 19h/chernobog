/*
 * Small IDA-independent classifiers used by the native and Hex-Rays adapters.
 *
 * Keeping the state machine independent of IDA makes semantic boundary cases
 * executable in the ordinary CTest suite.  The host adapter remains
 * responsible for decoding instructions, canonicalizing register aliases, and
 * identifying alternate CFG predecessors.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace chernobog::ida_analysis::classifier {

constexpr uint64_t k_bad_address = ~uint64_t(0);

struct register_slice_t
{
  int32_t reg = -1;
  uint16_t bit_offset = 0;
  uint16_t bit_width = 0;

  bool valid() const { return reg >= 0 && bit_width != 0; }
  bool same(const register_slice_t &other) const;
  bool overlaps(const register_slice_t &other) const;
};

enum class instruction_kind_t : uint8_t
{
  other = 0,
  direct_call,
  indirect_call,
  direct_jump,
  indirect_jump,
  conditional_branch,
  return_instruction,
  pop_register,
  push_register,
  push_immediate,
  read_stack_top,
  add_stack_top_immediate,
  adjust_stack_pointer_immediate,
  add_register_immediate,
  sub_register_immediate,
  register_write,
  stack_mutation,
};

struct instruction_t
{
  uint64_t address = k_bad_address;
  uint16_t size = 0;
  instruction_kind_t kind = instruction_kind_t::other;
  register_slice_t destination;
  register_slice_t source;
  uint64_t immediate = 0;
  uint64_t target = k_bad_address;
  uint16_t stack_width_bits = 0;
  bool alternate_predecessor = false;

  uint64_t end() const;
};

enum class get_pc_mode_t : uint8_t
{
  pop_return_address = 0,
  read_return_address,
  adjust_return_address,
  discard_return_address,
};

struct get_pc_candidate_t
{
  uint64_t call = k_bad_address;
  uint64_t gadget = k_bad_address;
  uint64_t pushed_return = k_bad_address;
  uint64_t return_instruction = k_bad_address;
  std::optional<uint64_t> resumed_at;
  std::optional<uint64_t> register_value_at_return;
  register_slice_t pc_register;
  int64_t delta = 0;
  get_pc_mode_t mode = get_pc_mode_t::pop_return_address;
  std::vector<uint64_t> support;
};

// The gadget vector starts at the direct call target and is in exact physical
// address order. `other_callers` includes any alternate control-flow entry to
// the first gadget instruction.
std::optional<get_pc_candidate_t> classify_get_pc_gadget(
    const instruction_t &call,
    const std::vector<instruction_t> &gadget,
    bool other_callers,
    size_t maximum_depth);

} // namespace chernobog::ida_analysis::classifier
