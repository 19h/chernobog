#include "entry_state.hpp"

#include <algorithm>
#include <limits>
#include <set>
#include <tuple>
#include <vector>

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <allins.hpp>
#include <bytes.hpp>
#include <nalt.hpp>
#include <xref.hpp>
#include <typeinf.hpp>
#include <regfinder.hpp>

namespace chernobog::hybrid {

namespace {

bool tracker_value(ea_t at, const char *regname, uint64_t *out)
{
  const int reg = str2reg(regname);
  if ( reg < 0 )
    return false;
  reg_value_info_t rvi;
  if ( !find_reg_value_info(&rvi, at, reg, -1) )
    return false;
  uval_t value = 0;
  if ( rvi.get_num(&value) )
  {
    *out = uint64_t(value);
    return true;
  }
  return false;
}

bool is_real_call(ea_t ea)
{
  insn_t insn;
  return decode_insn(&insn, ea) > 0 && is_call_insn(insn);
}

struct FunctionTypePlan
{
  bool available = false;
  size_t formal_arguments = 0;
  size_t stack_arguments = 0;
  std::vector<int> register_arguments;
};

FunctionTypePlan function_type_plan(ea_t function_start)
{
  FunctionTypePlan plan;
  tinfo_t type;
  func_type_data_t details;
  if ( !get_tinfo(&type, function_start)
    || !type.get_func_details(&details, GTD_CALC_ARGLOCS) )
    return plan;
  plan.available = true;
  plan.formal_arguments = details.size();
  for ( const funcarg_t &argument : details )
  {
    if ( argument.argloc.is_reg1() )
      plan.register_arguments.push_back(argument.argloc.reg1());
    else if ( argument.argloc.has_stkoff() )
      ++plan.stack_arguments;
  }
  return plan;
}

int positional_register(const HybridAbiLayout &abi, int ida_register)
{
  for ( size_t index = 0; index < abi.ida_argument_registers.size(); ++index )
    if ( str2reg(abi.ida_argument_registers[index]) == ida_register )
      return int(index);
  return -1;
}

int x86_rax_register(int ida_register)
{
  const int ecx = str2reg("ecx");
  const int edx = str2reg("edx");
  if ( ida_register == ecx )
    return RAX_X86_REG_ECX;
  if ( ida_register == edx )
    return RAX_X86_REG_EDX;
  return -1;
}

bool load_x86_push_value(ea_t instruction_ea, const op_t &operand,
                         uint64_t *out)
{
  switch ( operand.type )
  {
    case o_imm:
      *out = uint64_t(operand.value);
      return true;
    case o_near:
    case o_far:
      *out = uint64_t(operand.addr);
      return true;
    case o_reg:
    {
      qstring name;
      if ( get_reg_name(&name, operand.reg, 4) < 0 )
        return false;
      return tracker_value(instruction_ea, name.c_str(), out);
    }
    case o_mem:
      if ( is_mapped(operand.addr) && is_loaded(operand.addr)
        && operand.addr <= std::numeric_limits<ea_t>::max() - 3
        && is_loaded(operand.addr + 3) )
      {
        *out = uint64_t(get_dword(operand.addr));
        return true;
      }
      return false;
    default:
      return false;
  }
}

bool has_non_linear_predecessor(ea_t at, ea_t linear)
{
  xrefblk_t xb;
  for ( bool ok = xb.first_to(at, XREF_CODE); ok; ok = xb.next_to() )
    if ( xb.iscode && xb.from != linear )
      return true;
  return false;
}

uint64_t unknown_stack_value(uint64_t seed, size_t index)
{
  uint64_t value = seed ^ (uint64_t(index) * 0x9E3779B97F4A7C15ull);
  value ^= value >> 30;
  value *= 0xBF58476D1CE4E5B9ull;
  value ^= value >> 27;
  value *= 0x94D049BB133111EBull;
  return value ^ (value >> 31);
}

// Recover the common cdecl/stdcall pattern where arguments are pushed
// immediately before the call.  Unknown push operands retain their positional
// slot through a deterministic value; we never slide later arguments down.
std::vector<uint64_t> x86_stack_arguments(ea_t callsite,
                                          size_t requested,
                                          uint64_t seed,
                                          size_t *known_values)
{
  std::vector<uint64_t> result;
  *known_values = 0;
  const size_t limit = requested != 0 ? std::min<size_t>(requested, 32) : 8;
  ea_t cursor = callsite;
  for ( size_t depth = 0; depth < 48 && result.size() < limit; ++depth )
  {
    const ea_t floor = callsite > 192 ? callsite - 192 : 0;
    const ea_t previous = prev_head(cursor, floor);
    if ( previous == BADADDR || previous >= cursor
      || has_non_linear_predecessor(cursor, previous) )
      break;
    insn_t instruction;
    if ( decode_insn(&instruction, previous) <= 0 )
      break;
    if ( instruction.itype == NN_push )
    {
      uint64_t value = 0;
      if ( load_x86_push_value(previous, instruction.Op1, &value) )
        ++*known_values;
      else
        value = unknown_stack_value(seed, result.size());
      result.push_back(value);
    }
    else
    {
      // Do not cross a call, return, jump, or an explicit ESP update: beyond
      // those points the relationship between a push and this call is not
      // established by this local proof.
      if ( is_call_insn(instruction) || is_ret_insn(instruction)
        || is_basic_block_end(instruction, false) )
        break;
      const uint32_t features = instruction.get_canon_feature(PH);
      for ( int operand_index = 0; operand_index < UA_MAXOP; ++operand_index )
      {
        const op_t &operand = instruction.ops[operand_index];
        if ( operand.type == o_void )
          break;
        if ( operand.type == o_reg && operand.reg == str2reg("esp")
          && has_cf_chg(features, operand_index) )
          return result;
      }
    }
    cursor = previous;
  }
  return result;
}

} // namespace

HybridAbi hybrid_detect_abi(HybridArch arch)
{
  return hybrid_abi_for_arch(arch,
                          arch == HybridArch::X86_64 && inf_get_filetype() == f_PE);
}

EntryInputPlan hybrid_build_entry_inputs(HybridArch arch, uint64_t function_start,
                                      size_t max_inputs)
{
  EntryInputPlan plan;
  plan.abi = hybrid_detect_abi(arch);
  plan.abi_name = hybrid_abi_name(plan.abi);
  if ( max_inputs == 0 )
    return plan;

  const HybridAbiLayout &regs = hybrid_abi_layout(plan.abi);
  const FunctionTypePlan type_plan = function_type_plan(ea_t(function_start));

  using SignatureItem = std::tuple<uint8_t, uint32_t, uint64_t>;
  std::set<std::vector<SignatureItem>> seen;
  xrefblk_t xb;
  for ( bool ok = xb.first_to((ea_t)function_start, XREF_CODE); ok; ok = xb.next_to() )
  {
    if ( plan.inputs.size() >= max_inputs )
      break;
    if ( !xb.iscode || !is_real_call(xb.from) )
      continue;

    EmuInput input;
    input.seed = uint64_t(xb.from) ^ 0xA0761D6478BD642Full;
    input.run_id = uint32_t(plan.inputs.size());
    input.stack_arg_offset = regs.stack_argument_offset;
    std::vector<SignatureItem> signature;
    for ( size_t i = 0; i < regs.ida_argument_registers.size(); ++i )
    {
      uint64_t value = 0;
      if ( tracker_value(xb.from, regs.ida_argument_registers[i], &value) )
      {
        input.arg_overrides.push_back(EmuInput::ArgOverride{ uint32_t(i), value });
        signature.emplace_back(0, uint32_t(i), value);
      }
    }

    // Explicit/custom register locations from type information. For standard
    // ABIs this merely corroborates the positional collection above; on i386
    // it additionally handles common fastcall ECX/EDX entry values.
    for ( int ida_register : type_plan.register_arguments )
    {
      qstring name;
      if ( get_reg_name(&name, ida_register, inf_is_64bit() ? 8 : 4) < 0 )
        continue;
      uint64_t value = 0;
      if ( !tracker_value(xb.from, name.c_str(), &value) )
        continue;
      const int position = positional_register(regs, ida_register);
      if ( position >= 0 )
      {
        const auto duplicate = std::find_if(
          input.arg_overrides.begin(), input.arg_overrides.end(),
          [&](const EmuInput::ArgOverride &arg) { return arg.index == uint32_t(position); });
        if ( duplicate == input.arg_overrides.end() )
          input.arg_overrides.push_back({ uint32_t(position), value });
        signature.emplace_back(0, uint32_t(position), value);
      }
      else if ( plan.abi == HybridAbi::X86_32 )
      {
        const int rax_register = x86_rax_register(ida_register);
        if ( rax_register >= 0 )
        {
          input.register_overrides.push_back({ rax_register, value });
          signature.emplace_back(1, uint32_t(rax_register), value);
        }
      }
    }

    if ( plan.abi == HybridAbi::X86_32 )
    {
      size_t known = 0;
      if ( !type_plan.available || type_plan.stack_arguments != 0 )
        input.stack_args = x86_stack_arguments(
            xb.from, type_plan.stack_arguments, input.seed, &known);
      if ( known != 0 )
        for ( size_t index = 0; index < input.stack_args.size(); ++index )
          signature.emplace_back(2, uint32_t(index), input.stack_args[index]);
      else
        input.stack_args.clear(); // no observed value: retain driver's baseline
    }

    std::sort(signature.begin(), signature.end());
    signature.erase(std::unique(signature.begin(), signature.end()), signature.end());
    if ( signature.empty() || !seen.insert(signature).second )
      continue;
    plan.inputs.push_back(std::move(input));
  }
  return plan;
}

} // namespace chernobog::hybrid
