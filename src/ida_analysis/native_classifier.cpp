#include "native_classifier.hpp"

#include <algorithm>
#include <limits>

namespace chernobog::ida_analysis::classifier {
namespace {

bool add_address(uint64_t base, int64_t delta, uint64_t *result)
{
  if ( result == nullptr )
    return false;
  if ( delta >= 0 )
  {
    const uint64_t amount = static_cast<uint64_t>(delta);
    if ( base > std::numeric_limits<uint64_t>::max() - amount )
      return false;
    *result = base + amount;
  }
  else
  {
    const uint64_t amount = static_cast<uint64_t>(-(delta + 1)) + 1;
    if ( base < amount )
      return false;
    *result = base - amount;
  }
  return *result != k_bad_address;
}

bool add_delta(int64_t *value, int64_t delta)
{
  if ( value == nullptr )
    return false;
  if ( (delta > 0 && *value > std::numeric_limits<int64_t>::max() - delta)
    || (delta < 0 && *value < std::numeric_limits<int64_t>::min() - delta) )
  {
    return false;
  }
  *value += delta;
  return true;
}

bool is_control_transfer(instruction_kind_t kind)
{
  return kind == instruction_kind_t::direct_call
      || kind == instruction_kind_t::indirect_call
      || kind == instruction_kind_t::direct_jump
      || kind == instruction_kind_t::indirect_jump
      || kind == instruction_kind_t::conditional_branch;
}

bool is_unmodeled_stack_mutation(instruction_kind_t kind)
{
  return kind == instruction_kind_t::push_immediate
      || kind == instruction_kind_t::pop_register
      || kind == instruction_kind_t::add_stack_top_immediate
      || kind == instruction_kind_t::adjust_stack_pointer_immediate
      || kind == instruction_kind_t::stack_mutation;
}

} // namespace

bool register_slice_t::same(const register_slice_t &other) const
{
  return valid() && other.valid() && reg == other.reg
      && bit_offset == other.bit_offset && bit_width == other.bit_width;
}

bool register_slice_t::overlaps(const register_slice_t &other) const
{
  if ( !valid() || !other.valid() || reg != other.reg )
    return false;
  const uint32_t end = uint32_t(bit_offset) + uint32_t(bit_width);
  const uint32_t other_end = uint32_t(other.bit_offset)
                           + uint32_t(other.bit_width);
  return uint32_t(bit_offset) < other_end
      && uint32_t(other.bit_offset) < end;
}

uint64_t instruction_t::end() const
{
  if ( address == k_bad_address || size == 0
    || address > std::numeric_limits<uint64_t>::max() - size )
  {
    return k_bad_address;
  }
  return address + size;
}

std::optional<get_pc_candidate_t> classify_get_pc_gadget(
    const instruction_t &call,
    const std::vector<instruction_t> &gadget,
    bool other_callers,
    size_t maximum_depth)
{
  const uint64_t call_end = call.end();
  if ( call.kind != instruction_kind_t::direct_call || call.size == 0
    || call.address == k_bad_address || call_end == k_bad_address
    || call.target == k_bad_address || call.target == call_end
    || gadget.empty() || gadget.front().address != call.target
    || other_callers || maximum_depth == 0
    || (call.stack_width_bits != 16 && call.stack_width_bits != 32
      && call.stack_width_bits != 64) )
  {
    return std::nullopt;
  }

  get_pc_candidate_t result;
  result.call = call.address;
  result.gadget = call.target;
  result.pushed_return = call_end;
  result.support = { call.address, gadget.front().address };

  const instruction_t &entry = gadget.front();
  bool register_known = false;
  bool stack_target_adjusted = false;
  bool pushed_tracked_register = false;
  int64_t pushed_register_delta = 0;
  switch ( entry.kind )
  {
    case instruction_kind_t::pop_register:
      if ( !entry.destination.valid()
        || entry.destination.bit_width != call.stack_width_bits )
        return std::nullopt;
      result.mode = get_pc_mode_t::pop_return_address;
      result.pc_register = entry.destination;
      register_known = true;
      break;
    case instruction_kind_t::read_stack_top:
      if ( !entry.destination.valid()
        || entry.destination.bit_width != call.stack_width_bits )
        return std::nullopt;
      result.mode = get_pc_mode_t::read_return_address;
      result.pc_register = entry.destination;
      register_known = true;
      break;
    case instruction_kind_t::add_stack_top_immediate:
      if ( entry.stack_width_bits != call.stack_width_bits )
        return std::nullopt;
      result.mode = get_pc_mode_t::adjust_return_address;
      result.delta = static_cast<int64_t>(entry.immediate);
      stack_target_adjusted = true;
      break;
    case instruction_kind_t::adjust_stack_pointer_immediate:
      if ( entry.stack_width_bits != call.stack_width_bits
        || entry.immediate != call.stack_width_bits / 8 )
        return std::nullopt;
      result.mode = get_pc_mode_t::discard_return_address;
      // The return address has been consumed completely. Execution continues
      // at the instruction after this exact stack adjustment; later branches
      // are application control flow, not part of the proof obligation.
      result.resumed_at = entry.end();
      if ( *result.resumed_at == k_bad_address )
        return std::nullopt;
      return result;
    default:
      return std::nullopt;
  }

  uint64_t expected = entry.end();
  if ( expected == k_bad_address )
    return std::nullopt;
  const size_t count = gadget.size() <= maximum_depth
                     ? gadget.size() : maximum_depth + 1;
  for ( size_t index = 1; index < count; ++index )
  {
    const instruction_t &instruction = gadget[index];
    if ( instruction.address != expected || instruction.alternate_predecessor )
      return std::nullopt;
    expected = instruction.end();
    if ( expected == k_bad_address )
      return std::nullopt;
    result.support.push_back(instruction.address);

    if ( instruction.kind == instruction_kind_t::return_instruction )
    {
      result.return_instruction = instruction.address;
      if ( stack_target_adjusted || pushed_tracked_register )
      {
        const int64_t return_delta = pushed_tracked_register
                                   ? pushed_register_delta : result.delta;
        uint64_t resumed = 0;
        if ( !add_address(result.pushed_return, return_delta, &resumed) )
          return std::nullopt;
        result.resumed_at = resumed;
      }
      if ( register_known )
      {
        uint64_t value = 0;
        if ( !add_address(result.pushed_return, result.delta, &value) )
          return std::nullopt;
        result.register_value_at_return = value;
      }
      // A plain read/pop followed by RET consumes an unrelated stack value.
      if ( (result.mode == get_pc_mode_t::read_return_address
         || result.mode == get_pc_mode_t::pop_return_address)
        && !pushed_tracked_register )
      {
        return std::nullopt;
      }
      return result;
    }

    if ( is_control_transfer(instruction.kind) )
    {
      // A pop-entry gadget has already consumed the CALL's return address.
      // If the captured value remains exact up to the next control transfer,
      // retain the physical inline continuation without speculating past it.
      if ( result.mode == get_pc_mode_t::pop_return_address && register_known )
      {
        result.resumed_at = entry.end();
        result.register_value_at_return = result.pushed_return;
        return result;
      }
      return std::nullopt;
    }
    if ( is_unmodeled_stack_mutation(instruction.kind) )
    {
      return std::nullopt;
    }

    if ( register_known
      && instruction.destination.overlaps(result.pc_register) )
    {
      int64_t adjustment = 0;
      if ( instruction.destination.same(result.pc_register)
        && instruction.source.same(result.pc_register)
        && instruction.kind == instruction_kind_t::add_register_immediate )
      {
        adjustment = static_cast<int64_t>(instruction.immediate);
      }
      else if ( instruction.destination.same(result.pc_register)
             && instruction.source.same(result.pc_register)
             && instruction.kind == instruction_kind_t::sub_register_immediate )
      {
        const int64_t value = static_cast<int64_t>(instruction.immediate);
        if ( value == std::numeric_limits<int64_t>::min() )
          return std::nullopt;
        adjustment = -value;
      }
      else
      {
        register_known = false;
      }
      if ( register_known && !add_delta(&result.delta, adjustment) )
        return std::nullopt;
    }

    if ( instruction.kind == instruction_kind_t::push_register
      && register_known && instruction.source.same(result.pc_register) )
    {
      pushed_tracked_register = true;
      pushed_register_delta = result.delta;
    }
    else if ( instruction.kind == instruction_kind_t::push_register )
    {
      return std::nullopt;
    }
  }

  // A bounded pop-entry scan may reach its limit before a control transfer.
  // The CALL is still an intra-function transfer if the popped PC register
  // remains exact throughout the scanned prefix.
  if ( result.mode == get_pc_mode_t::pop_return_address && register_known )
  {
    result.resumed_at = entry.end();
    result.register_value_at_return = result.pushed_return;
    return result;
  }
  return std::nullopt;
}

} // namespace chernobog::ida_analysis::classifier
