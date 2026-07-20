#include "get_pc_ida.hpp"

#include "../common/warn_off.h"
#include <bytes.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <intel.hpp>
#include <segment.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include "../common/warn_on.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <string>
#include <vector>

namespace chernobog::ida_analysis {
namespace {

using classifier::instruction_kind_t;
using classifier::instruction_t;
using classifier::register_slice_t;

bool stack_pointer_deref(const insn_t &instruction, const op_t &operand)
{
  if ( operand.type != o_phrase && operand.type != o_displ )
    return false;
  if ( operand.type == o_displ && operand.addr != 0 )
    return false;
  // Decode the ModRM/SIB form explicitly. `op_t::reg` aliases other operand
  // fields and does not prove that RSP is the sole address component.
  return x86_base_reg(instruction, operand) == R_sp
      && x86_index_reg(instruction, operand) == R_none;
}

register_slice_t slice_from_operand(const op_t &operand)
{
  register_slice_t result;
  if ( operand.type != o_reg )
    return result;
  size_t width = get_dtype_size(operand.dtype);
  if ( width == 0 || width > 64 )
    return result;
  qstring name;
  if ( get_reg_name(&name, operand.reg, width) <= 0 )
    return result;
  bitrange_t range;
  const char *main_name = PH.get_reg_info(name.c_str(), &range);
  if ( main_name == nullptr )
    return result;
  result.reg = str2reg(main_name);
  if ( result.reg < 0 )
    return register_slice_t{};
  result.bit_offset = static_cast<uint16_t>(range.empty() ? 0 : range.bitoff());
  const size_t bit_width = range.empty() ? width * 8 : range.bitsize();
  if ( bit_width == 0 || bit_width > std::numeric_limits<uint16_t>::max() )
    return register_slice_t{};
  result.bit_width = static_cast<uint16_t>(bit_width);
  return result;
}

register_slice_t slice_from_access(
    const reg_access_t &access,
    const insn_t &instruction)
{
  register_slice_t result;
  result.reg = access.regnum;
  result.bit_offset = static_cast<uint16_t>(
      access.range.empty() ? 0 : access.range.bitoff());
  size_t bits = access.range.empty() ? 0 : access.range.bitsize();
  if ( bits == 0 && access.opnum < UA_MAXOP )
  {
    const size_t width = get_dtype_size(instruction.ops[access.opnum].dtype);
    if ( width <= std::numeric_limits<uint16_t>::max() / 8 )
      bits = width * 8;
  }
  if ( bits == 0 )
    bits = inf_is_64bit() ? 64 : inf_is_32bit_exactly() ? 32 : 16;
  if ( bits > std::numeric_limits<uint16_t>::max() )
    return register_slice_t{};
  result.bit_width = static_cast<uint16_t>(bits);
  return result;
}

std::vector<register_slice_t> written_registers(const insn_t &instruction)
{
  std::vector<register_slice_t> result;
  reg_accesses_t accesses;
  if ( PH.get_reg_accesses(&accesses, instruction, 0) > 0 )
  {
    for ( const reg_access_t &access : accesses )
    {
      if ( (access.access_type & WRITE_ACCESS) == 0 )
        continue;
      const register_slice_t slice = slice_from_access(access, instruction);
      if ( slice.valid() )
        result.push_back(slice);
    }
    return result;
  }

  const uint32_t features = instruction.get_canon_feature(PH);
  for ( int index = 0; index < UA_MAXOP; ++index )
  {
    const op_t &operand = instruction.ops[index];
    if ( operand.type == o_void )
      break;
    if ( operand.type == o_reg && has_cf_chg(features, index) )
    {
      const register_slice_t slice = slice_from_operand(operand);
      if ( slice.valid() )
        result.push_back(slice);
    }
  }
  return result;
}

bool is_stack_pointer_register(const register_slice_t &candidate)
{
  if ( !candidate.valid() )
    return false;
  static constexpr std::array<const char *, 3> names = {{ "rsp", "esp", "sp" }};
  for ( const char *name : names )
  {
    bitrange_t range;
    const char *main_name = PH.get_reg_info(name, &range);
    if ( main_name != nullptr && str2reg(main_name) == candidate.reg )
      return true;
  }
  return false;
}

bool writes_stack_pointer(const insn_t &instruction)
{
  const std::vector<register_slice_t> writes = written_registers(instruction);
  return std::any_of(
      writes.begin(), writes.end(), is_stack_pointer_register);
}

bool has_alternate_inbound_flow(ea_t address, ea_t expected_source)
{
  xrefblk_t xref;
  for ( bool ok = xref.first_to(address, XREF_FLOW); ok; ok = xref.next_to() )
  {
    if ( xref.from != expected_source )
      return true;
  }
  return false;
}

bool has_other_entry(ea_t address, ea_t call_ea)
{
  return has_alternate_inbound_flow(address, call_ea);
}

bool same_owner_and_segment(
    ea_t address,
    const func_t *owner,
    const segment_t *segment)
{
  if ( segment == nullptr || getseg(address) != segment )
    return false;
  const func_t *candidate = get_func(address);
  return owner == nullptr ? candidate == nullptr : candidate == owner;
}

instruction_t translate_instruction(
    const insn_t &instruction,
    const register_slice_t &tracked)
{
  instruction_t result;
  result.address = instruction.ea;
  result.size = instruction.size;
  result.target = classifier::k_bad_address;

  if ( is_ret_insn(instruction) )
  {
    result.kind = instruction_kind_t::return_instruction;
    return result;
  }
  if ( is_call_insn(instruction) )
  {
    const bool direct = instruction.Op1.type == o_near
                     || instruction.Op1.type == o_far;
    result.kind = direct ? instruction_kind_t::direct_call
                         : instruction_kind_t::indirect_call;
    if ( direct )
      result.target = instruction.Op1.addr;
    return result;
  }
  if ( instruction.itype == NN_jmp )
  {
    const bool direct = instruction.Op1.type == o_near
                     || instruction.Op1.type == o_far;
    result.kind = direct ? instruction_kind_t::direct_jump
                         : instruction_kind_t::indirect_jump;
    if ( direct )
      result.target = instruction.Op1.addr;
    return result;
  }
  if ( is_basic_block_end(instruction, false) )
  {
    result.kind = instruction_kind_t::conditional_branch;
    for ( int index = 0; index < UA_MAXOP; ++index )
    {
      if ( instruction.ops[index].type == o_near
        || instruction.ops[index].type == o_far )
      {
        result.target = instruction.ops[index].addr;
        break;
      }
    }
    return result;
  }

  if ( instruction.itype == NN_pop && instruction.Op1.type == o_reg )
  {
    result.kind = instruction_kind_t::pop_register;
    result.destination = slice_from_operand(instruction.Op1);
    return result;
  }
  if ( instruction.itype == NN_push )
  {
    if ( instruction.Op1.type == o_reg )
    {
      result.kind = instruction_kind_t::push_register;
      result.source = slice_from_operand(instruction.Op1);
    }
    else
    {
      result.kind = instruction_kind_t::push_immediate;
    }
    return result;
  }
  if ( instruction.itype == NN_mov && instruction.Op1.type == o_reg
    && stack_pointer_deref(instruction, instruction.Op2) )
  {
    result.kind = instruction_kind_t::read_stack_top;
    result.destination = slice_from_operand(instruction.Op1);
    return result;
  }
  if ( instruction.itype == NN_add
    && stack_pointer_deref(instruction, instruction.Op1)
    && instruction.Op2.type == o_imm )
  {
    result.kind = instruction_kind_t::add_stack_top_immediate;
    result.immediate = instruction.Op2.value;
    result.stack_width_bits = static_cast<uint16_t>(
        get_dtype_size(instruction.Op1.dtype) * 8);
    return result;
  }
  if ( instruction.itype == NN_add && instruction.Op1.type == o_reg
    && instruction.Op1.reg == R_sp && instruction.Op2.type == o_imm )
  {
    result.kind = instruction_kind_t::adjust_stack_pointer_immediate;
    result.immediate = instruction.Op2.value;
    result.stack_width_bits = static_cast<uint16_t>(
        get_dtype_size(instruction.Op1.dtype) * 8);
    return result;
  }

  register_slice_t destination;
  const std::vector<register_slice_t> writes = written_registers(instruction);
  for ( const register_slice_t &write : writes )
  {
    if ( tracked.valid() && write.overlaps(tracked) )
    {
      destination = write;
      break;
    }
  }
  if ( destination.valid() )
  {
    result.destination = destination;
    if ( instruction.Op1.type == o_reg )
      result.source = slice_from_operand(instruction.Op1);
    if ( (instruction.itype == NN_add || instruction.itype == NN_sub)
      && instruction.Op2.type == o_imm
      && result.destination.same(result.source) )
    {
      result.kind = instruction.itype == NN_add
                  ? instruction_kind_t::add_register_immediate
                  : instruction_kind_t::sub_register_immediate;
      result.immediate = instruction.Op2.value;
      return result;
    }
    if ( (instruction.itype == NN_inc || instruction.itype == NN_dec)
      && result.destination.same(result.source) )
    {
      result.kind = instruction.itype == NN_inc
                  ? instruction_kind_t::add_register_immediate
                  : instruction_kind_t::sub_register_immediate;
      result.immediate = 1;
      return result;
    }
    if ( instruction.itype == NN_lea && instruction.Op1.type == o_reg
      && instruction.Op2.type == o_displ
      && x86_index_reg(instruction, instruction.Op2) == R_none )
    {
      // Resolve the sole address-base register at the destination width.
      op_t base = instruction.Op1;
      base.reg = x86_base_reg(instruction, instruction.Op2);
      result.source = slice_from_operand(base);
      if ( result.destination.same(result.source) )
      {
        const sval_t displacement = static_cast<sval_t>(instruction.Op2.addr);
        result.kind = displacement < 0
                    ? instruction_kind_t::sub_register_immediate
                    : instruction_kind_t::add_register_immediate;
        result.immediate = displacement < 0
                         ? uint64_t(-(displacement + 1)) + 1
                         : uint64_t(displacement);
        return result;
      }
    }
    result.kind = instruction_kind_t::register_write;
    return result;
  }

  if ( writes_stack_pointer(instruction) )
  {
    result.kind = instruction_kind_t::stack_mutation;
    return result;
  }
  return result;
}

} // namespace

std::optional<classifier::get_pc_candidate_t> classify_ida_get_pc_call(
    const insn_t &call,
    size_t maximum_depth,
    bool reject_other_entries)
{
  if ( PH.id != PLFM_386 || maximum_depth == 0
    || call.itype != NN_call || call.Op1.type != o_near
    || call.size == 0 )
  {
    return std::nullopt;
  }
  const ea_t target = call.Op1.addr;
  if ( target == BADADDR || target == call.ea + call.size )
    return std::nullopt;
  const segment_t *segment = getseg(target);
  const func_t *owner = get_func(target);
  if ( segment == nullptr || !is_mapped(target) )
    return std::nullopt;

  std::vector<instruction_t> gadget;
  gadget.reserve(maximum_depth + 1);
  ea_t cursor = target;
  register_slice_t tracked;
  ea_t previous = call.ea;
  for ( size_t index = 0; index <= maximum_depth; ++index )
  {
    if ( !same_owner_and_segment(cursor, owner, segment) )
      return std::nullopt;
    insn_t decoded;
    if ( decode_insn(&decoded, cursor) <= 0 || decoded.size == 0 )
      break;
    instruction_t translated = translate_instruction(decoded, tracked);
    translated.alternate_predecessor = index != 0
        && has_alternate_inbound_flow(cursor, previous);
    if ( index == 0 )
    {
      if ( translated.kind == instruction_kind_t::pop_register
        || translated.kind == instruction_kind_t::read_stack_top )
      {
        tracked = translated.destination;
      }
    }
    gadget.push_back(translated);
    previous = cursor;
    if ( cursor > BADADDR - decoded.size )
      break;
    cursor += decoded.size;
    if ( translated.kind == instruction_kind_t::return_instruction )
      break;
  }

  instruction_t core_call;
  core_call.address = call.ea;
  core_call.size = call.size;
  core_call.kind = instruction_kind_t::direct_call;
  core_call.target = target;
  core_call.stack_width_bits = inf_is_64bit() ? 64
                             : inf_is_32bit_exactly() ? 32 : 16;
  const bool other_entries = reject_other_entries
      && has_other_entry(target, call.ea);
  const auto result = classifier::classify_get_pc_gadget(
      core_call, gadget, other_entries, maximum_depth);
  qstring trace;
  if ( qgetenv("CHERNOBOG_IDA_GET_PC_TRACE", &trace)
    && !trace.empty() && trace[0] != '0'
    && !gadget.empty()
    && (gadget.front().kind == instruction_kind_t::pop_register
      || gadget.front().kind == instruction_kind_t::read_stack_top
      || gadget.front().kind == instruction_kind_t::add_stack_top_immediate
      || gadget.front().kind
           == instruction_kind_t::adjust_stack_pointer_immediate) )
  {
    msg("[chernobog][ida-analysis][get-pc-trace] call=%a target=%a "
        "other-entry=%d result=%s count=%zu\n",
        call.ea, target, other_entries ? 1 : 0,
        result ? "accepted" : "rejected", gadget.size());
    for ( const instruction_t &item : gadget )
    {
      msg("[chernobog][ida-analysis][get-pc-trace]   ea=%a size=%u "
          "kind=%u dst={%d,%u,%u} src={%d,%u,%u} imm=%llu alt=%d\n",
          ea_t(item.address), unsigned(item.size), unsigned(item.kind),
          item.destination.reg, unsigned(item.destination.bit_offset),
          unsigned(item.destination.bit_width), item.source.reg,
          unsigned(item.source.bit_offset), unsigned(item.source.bit_width),
          static_cast<unsigned long long>(item.immediate),
          item.alternate_predecessor ? 1 : 0);
    }
  }
  return result;
}

} // namespace chernobog::ida_analysis
