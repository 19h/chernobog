/*
 * Native IDA analysis-quality additions.
 *
 * The pattern set is derived from viy's IDA-native/structural providers and
 * Hex-Rays' generic deobfuscator.  This implementation is per-IDB, preserves
 * existing annotations, and validates a complete candidate before changing
 * item boundaries or function metadata.
 */
#include "native_engine.hpp"

#include "analysis_config.hpp"

#include "../common/warn_off.h"
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <segment.hpp>
#include <funcs.hpp>
#include <frame.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <auto.hpp>
#include <range.hpp>
#include <regfinder.hpp>
#include <typeinf.hpp>
#include <kernwin.hpp>
#ifndef ALLINS_HPP_INCLUDED
#define ALLINS_HPP_INCLUDED
#include <allins.hpp>
#endif
#include "../common/warn_on.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace chernobog::ida_analysis {
namespace {

constexpr const char *kCommentPrefix = "[chernobog][ida-analysis] ";

enum class Architecture : uint8_t
{
  Unsupported = 0,
  X86,
  Arm,
};

enum class BranchDecision : uint8_t
{
  Unknown = 0,
  Taken,
  NotTaken,
};

enum class FlagEffect : uint8_t
{
  None = 0,
  Set,
  Clear,
  Flip,
};

enum class FlagValue : int8_t
{
  Unknown = -1,
  Clear = 0,
  Set = 1,
};

struct FlagEffects
{
  FlagEffect carry = FlagEffect::None;
  FlagEffect zero = FlagEffect::None;
};

struct GadgetInfo
{
  int reg = -1;
  sval_t delta = 0;
  ea_t return_ea = BADADDR;
  bool pops_return = false;
  bool pushes_return = false;
  bool has_return = false;
  bool discards_return = false;
  bool has_jump = false;
};

ea_t branch_target(const insn_t &instruction)
{
  for ( int index = 0; index < UA_MAXOP; ++index )
  {
    const op_t &operand = instruction.ops[index];
    if ( operand.type == o_void )
      break;
    if ( operand.type == o_near || operand.type == o_far )
      return operand.addr;
  }
  return BADADDR;
}

bool target_is_executable(ea_t target)
{
  const segment_t *segment = getseg(target);
  return target != BADADDR && is_mapped(target) && segment != nullptr
      && (segment->perm == 0 || (segment->perm & SEGPERM_EXEC) != 0)
      && !is_tail(get_flags(target));
}

bool cref_exists(ea_t from, ea_t to)
{
  xrefblk_t xref;
  for ( bool ok = xref.first_from(from, XREF_CODE);
        ok; ok = xref.next_from() )
  {
    if ( xref.to == to )
      return true;
  }
  return false;
}

bool add_user_cref(ea_t from, ea_t to, cref_t type)
{
  if ( from == BADADDR || !target_is_executable(to)
    || !is_code(get_flags(from)) || !is_head(get_flags(from))
    || cref_exists(from, to) )
  {
    return false;
  }
  return add_cref(from, to, cref_t(int(type) | XREF_USER));
}

bool flow_xref_exists(ea_t address, bool outgoing, ea_t excluded = BADADDR,
                      cref_t required_type = cref_t(-1))
{
  xrefblk_t xref;
  bool ok = outgoing ? xref.first_from(address, XREF_FLOW)
                     : xref.first_to(address, XREF_FLOW);
  while ( ok )
  {
    if ( xref.from != excluded
      && (required_type == cref_t(-1) || xref.type == required_type) )
    {
      return true;
    }
    ok = outgoing ? xref.next_from() : xref.next_to();
  }
  return false;
}

bool append_analysis_comment(ea_t address, const char *text)
{
  qstring tagged = kCommentPrefix;
  tagged.append(text);
  qstring current;
  get_cmt(&current, address, true);
  if ( current.find(tagged.c_str()) != qstring::npos )
    return false;
  if ( !current.empty() )
    current.append("\n");
  current.append(tagged);
  return set_cmt(address, current.c_str(), true);
}

bool has_inbound_reference(ea_t address)
{
  xrefblk_t xref;
  return xref.first_to(address, XREF_ALL);
}

bool has_protected_metadata(ea_t address, flags64_t flags)
{
  if ( has_any_name(flags) || has_cmt(flags) || has_extra_cmts(flags)
    || is_manual_insn(address) )
  {
    return true;
  }
  for ( int index = 0; index < UA_MAXOP; ++index )
  {
    if ( is_defarg(flags, index) )
      return true;
  }
  if ( is_head(flags) )
  {
    tinfo_t type;
    if ( get_tinfo(&type, address) )
      return true;
  }
  return false;
}

bool safe_gap_candidate(ea_t start, ea_t end, uint64_t maximum_gap)
{
  if ( start >= end || uint64_t(end - start) > maximum_gap )
    return false;
  const func_t *owner = get_func(start);
  for ( ea_t address = start; address < end; ++address )
  {
    const flags64_t flags = get_flags(address);
    if ( !is_mapped(address) || !is_loaded(address)
      || has_protected_metadata(address, flags)
      || has_inbound_reference(address) )
    {
      return false;
    }
    const func_t *function = get_func(address);
    if ( function != nullptr && function->start_ea == address )
      return false;
    if ( owner == nullptr && function != nullptr )
      return false;
    if ( owner != nullptr && function != nullptr && function != owner )
      return false;
  }
  return true;
}

size_t retype_gap_as_bytes(ea_t start, ea_t end, uint64_t maximum_gap,
                           bool revisiting)
{
  if ( revisiting || !safe_gap_candidate(start, end, maximum_gap) )
    return 0;
  size_t changed = 0;
  for ( ea_t address = start; address < end; ++address )
  {
    const flags64_t flags = get_flags(address);
    if ( is_byte(flags) && get_item_size(address) == 1 )
      continue;
    if ( !del_items(address, DELIT_SIMPLE, 1) )
      continue;
    if ( create_byte(address, 1) )
      ++changed;
  }
  return changed;
}

bool has_other_callers(ea_t target, ea_t source)
{
  xrefblk_t xref;
  for ( bool ok = xref.first_to(target, XREF_FLOW);
        ok; ok = xref.next_to() )
  {
    if ( xref.from == source || !xref.iscode )
      continue;
    insn_t instruction;
    if ( decode_insn(&instruction, xref.from) > 0
      && is_call_insn(instruction) )
    {
      return true;
    }
  }
  return false;
}

bool is_stack_pointer_deref(const op_t &operand)
{
  // IDA's x86 register enumeration keeps SP/ESP/RSP at register id 4.
  return operand.reg == 4
      && (operand.type == o_phrase
       || (operand.type == o_displ && operand.addr == 0));
}

void track_register_delta(sval_t &delta, const insn_t &instruction, int reg)
{
  switch ( instruction.itype )
  {
    case NN_inc:
      ++delta;
      break;
    case NN_dec:
      --delta;
      break;
    case NN_add:
      if ( instruction.Op2.type == o_imm )
        delta += sval_t(instruction.Op2.value);
      break;
    case NN_sub:
      if ( instruction.Op2.type == o_imm )
        delta -= sval_t(instruction.Op2.value);
      break;
    case NN_lea:
      if ( instruction.Op2.type == o_displ && instruction.Op2.reg == reg )
        delta += sval_t(instruction.Op2.addr);
      break;
    default:
      break;
  }
}

bool classify_gadget_entry(const insn_t &instruction, GadgetInfo &result)
{
  if ( instruction.itype == NN_pop && instruction.Op1.type == o_reg )
  {
    result.reg = instruction.Op1.reg;
    result.pops_return = true;
    return true;
  }
  if ( instruction.itype == NN_mov && instruction.Op1.type == o_reg
    && is_stack_pointer_deref(instruction.Op2) )
  {
    result.reg = instruction.Op1.reg;
    return true;
  }
  if ( instruction.itype == NN_add
    && is_stack_pointer_deref(instruction.Op1)
    && instruction.Op2.type == o_imm )
  {
    result.delta = sval_t(instruction.Op2.value);
    result.pushes_return = true;
    return true;
  }
  if ( instruction.itype == NN_add && instruction.Op1.type == o_reg
    && instruction.Op1.reg == 4 && instruction.Op2.type == o_imm
    && sval_t(instruction.Op2.value) > 0 )
  {
    result.discards_return = true;
    return true;
  }
  return false;
}

bool analyze_get_pc_gadget(ea_t address, int depth, GadgetInfo &result)
{
  result = GadgetInfo{};
  insn_t instruction;
  if ( decode_insn(&instruction, address) <= 0
    || !classify_gadget_entry(instruction, result) )
  {
    return false;
  }

  const int tracked_reg = result.reg;
  ea_t scan = address + instruction.size;
  bool saw_push = result.pushes_return;
  for ( int index = 0; index < depth; ++index )
  {
    if ( decode_insn(&instruction, scan) <= 0 )
      break;
    if ( is_ret_insn(instruction) )
    {
      result.return_ea = scan;
      result.pushes_return = saw_push;
      result.has_return = !saw_push;
      break;
    }
    const uint32_t features = instruction.get_canon_feature(PH);
    if ( (features & CF_CALL) != 0 )
      break;
    if ( (features & CF_STOP) != 0 )
    {
      result.has_jump = true;
      break;
    }
    if ( instruction.itype == NN_push && instruction.Op1.type == o_reg
      && instruction.Op1.reg == tracked_reg )
    {
      saw_push = true;
      scan += instruction.size;
      continue;
    }
    if ( instruction.Op1.type == o_reg
      && instruction.Op1.reg == tracked_reg )
    {
      track_register_delta(result.delta, instruction, tracked_reg);
    }
    scan += instruction.size;
  }
  return true;
}

bool is_redundant_rep_prefix(ea_t address)
{
  if ( !is_loaded(address) || !is_loaded(address + 1) )
    return false;
  const uint8_t prefix = get_byte(address);
  if ( prefix != 0xF2 && prefix != 0xF3 )
    return false;
  const uint8_t opcode = get_byte(address + 1);
  if ( opcode == 0x0F || (prefix == 0xF3 && opcode == 0x90) )
    return false;
  if ( prefix == 0xF3
    && (opcode == 0xC2 || opcode == 0xC3
     || opcode == 0xCA || opcode == 0xCB) )
  {
    return false;
  }
  return !((opcode >= 0xA4 && opcode <= 0xA7)
        || (opcode >= 0xAA && opcode <= 0xAF)
        || (opcode >= 0x6C && opcode <= 0x6F));
}

constexpr std::array<std::array<uint16_t, 2>, 8> kX86Opposites = {{
  {{ NN_jz,  NN_jnz  }}, {{ NN_jo,  NN_jno  }},
  {{ NN_js,  NN_jns  }}, {{ NN_jp,  NN_jnp  }},
  {{ NN_jb,  NN_jnb  }}, {{ NN_jbe, NN_ja   }},
  {{ NN_jl,  NN_jnl  }}, {{ NN_jle, NN_jnle }},
}};

uint16_t opposite_x86_condition(uint16_t type)
{
  for ( const auto &pair : kX86Opposites )
  {
    if ( type == pair[0] ) return pair[1];
    if ( type == pair[1] ) return pair[0];
  }
  return 0;
}

bool instruction_modifies_x86_flags(uint16_t type)
{
  static constexpr std::array<uint16_t, 18> preserving = {{
    NN_mov, NN_lea, NN_nop, NN_push, NN_pop, NN_pusha, NN_popa,
    NN_pushf, NN_pushfd, NN_pushfq, NN_xchg, NN_bswap,
    NN_jmp, NN_jmpni, NN_jmpfi, NN_jcxz, NN_jecxz, NN_jrcxz,
  }};
  return std::find(preserving.begin(), preserving.end(), type)
             == preserving.end()
      && opposite_x86_condition(type) == 0;
}

bool same_register_operands(const insn_t &instruction)
{
  return instruction.Op1.type == o_reg && instruction.Op2.type == o_reg
      && instruction.Op1.reg == instruction.Op2.reg;
}

FlagEffects x86_flag_effects(const insn_t &instruction)
{
  FlagEffects result;
  switch ( instruction.itype )
  {
    case NN_stc:
      result.carry = FlagEffect::Set;
      break;
    case NN_clc:
      result.carry = FlagEffect::Clear;
      break;
    case NN_cmc:
      result.carry = FlagEffect::Flip;
      break;
    case NN_and:
    case NN_or:
    case NN_test:
      result.carry = FlagEffect::Clear;
      break;
    case NN_xor:
      result.carry = FlagEffect::Clear;
      if ( same_register_operands(instruction) )
        result.zero = FlagEffect::Set;
      break;
    case NN_sub:
      if ( same_register_operands(instruction) )
        result.zero = FlagEffect::Set;
      break;
    case NN_cmp:
      if ( same_register_operands(instruction) )
      {
        result.carry = FlagEffect::Clear;
        result.zero = FlagEffect::Set;
      }
      break;
    default:
      break;
  }
  return result;
}

template <typename Effect>
FlagValue scan_x86_flag(ea_t from, int depth, Effect effect)
{
  ea_t scan = from;
  for ( int count = 0; count < depth; )
  {
    const ea_t previous = prev_head(scan, 0);
    if ( previous == BADADDR )
      break;
    if ( !is_code(get_flags(previous)) )
    {
      scan = previous;
      continue;
    }
    if ( has_xref(get_flags(scan))
      && flow_xref_exists(scan, false, previous) )
    {
      break;
    }
    insn_t instruction;
    if ( decode_insn(&instruction, previous) <= 0 )
      break;
    ++count;
    const FlagEffect current = effect(x86_flag_effects(instruction));
    if ( current == FlagEffect::Set ) return FlagValue::Set;
    if ( current == FlagEffect::Clear ) return FlagValue::Clear;
    if ( current == FlagEffect::Flip
      || instruction_modifies_x86_flags(instruction.itype) )
    {
      const bool get_pc_call = instruction.itype == NN_call
          && flow_xref_exists(instruction.ea, true, BADADDR, fl_JN);
      if ( !get_pc_call )
        break;
    }
    scan = previous;
  }
  return FlagValue::Unknown;
}

BranchDecision decision_for_x86_flag(uint16_t type, bool carry,
                                     FlagValue value)
{
  if ( value == FlagValue::Unknown )
    return BranchDecision::Unknown;
  const bool set = value == FlagValue::Set;
  if ( carry )
  {
    if ( type == NN_jb ) return set ? BranchDecision::Taken
                                    : BranchDecision::NotTaken;
    if ( type == NN_jnb ) return set ? BranchDecision::NotTaken
                                     : BranchDecision::Taken;
    if ( type == NN_jbe && set ) return BranchDecision::Taken;
    if ( type == NN_ja && set ) return BranchDecision::NotTaken;
  }
  else
  {
    if ( type == NN_jz ) return set ? BranchDecision::Taken
                                    : BranchDecision::NotTaken;
    if ( type == NN_jnz ) return set ? BranchDecision::NotTaken
                                     : BranchDecision::Taken;
    if ( (type == NN_jbe || type == NN_jle) && set )
      return BranchDecision::Taken;
    if ( (type == NN_ja || type == NN_jnle) && set )
      return BranchDecision::NotTaken;
  }
  return BranchDecision::Unknown;
}

bool zero_register_operand(const op_t &operand)
{
  if ( operand.type != o_reg )
    return false;
  size_t width = get_dtype_size(operand.dtype);
  if ( width == 0 )
    width = inf_is_64bit() ? 8 : 4;
  qstring name;
  return get_reg_name(&name, operand.reg, width) > 0
      && (name == "XZR" || name == "WZR");
}

std::string normalized_mnemonic(ea_t address)
{
  qstring raw;
  if ( !print_insn_mnem(&raw, address) )
    return {};
  std::string result;
  for ( char value : std::string(raw.c_str()) )
  {
    const unsigned char byte = static_cast<unsigned char>(value);
    if ( std::isalnum(byte) )
      result.push_back(char(std::tolower(byte)));
  }
  return result;
}

bool opposite_arm_branch(const insn_t &left, const insn_t &right)
{
  if ( (left.itype == ARM_cbz && right.itype == ARM_cbnz)
    || (left.itype == ARM_cbnz && right.itype == ARM_cbz) )
  {
    return left.Op1.reg == right.Op1.reg;
  }
  if ( (left.itype == ARM_tbz && right.itype == ARM_tbnz)
    || (left.itype == ARM_tbnz && right.itype == ARM_tbz) )
  {
    return left.Op1.reg == right.Op1.reg
        && left.Op2.value == right.Op2.value;
  }
  if ( left.itype != ARM_b || right.itype != ARM_b )
    return false;
  static const std::map<std::string, std::string> opposites = {
    {"beq", "bne"}, {"bne", "beq"}, {"bcs", "bcc"},
    {"bcc", "bcs"}, {"bhs", "blo"}, {"blo", "bhs"},
    {"bmi", "bpl"}, {"bpl", "bmi"}, {"bvs", "bvc"},
    {"bvc", "bvs"}, {"bhi", "bls"}, {"bls", "bhi"},
    {"bge", "blt"}, {"blt", "bge"}, {"bgt", "ble"},
    {"ble", "bgt"},
  };
  const std::string first = normalized_mnemonic(left.ea);
  const std::string second = normalized_mnemonic(right.ea);
  const auto found = opposites.find(first);
  return found != opposites.end() && found->second == second;
}

bool direct_transfer(const insn_t &instruction)
{
  for ( int index = 0; index < UA_MAXOP; ++index )
  {
    const optype_t type = instruction.ops[index].type;
    if ( type == o_void )
      break;
    if ( type == o_near || type == o_far )
      return true;
  }
  return false;
}

bool writes_global_memory(const insn_t &instruction)
{
  const uint32_t features = instruction.get_canon_feature(PH);
  for ( int index = 0; index < UA_MAXOP; ++index )
  {
    const op_t &operand = instruction.ops[index];
    if ( operand.type == o_void )
      break;
    if ( operand.type == o_mem && has_cf_chg(features, index) )
      return true;
  }
  return false;
}

bool name_contains_hikari_wrapper(ea_t address)
{
  qstring name;
  return get_short_name(&name, address) > 0
      && name.find("HikariFunctionWrapper") != qstring::npos;
}

bool wrapper_shape(const func_t *function, const NativeAnalysisConfig &config)
{
  if ( function == nullptr )
    return false;
  const uint32_t excluded = FUNC_LIB | FUNC_THUNK | FUNC_HIDDEN | FUNC_OUTLINE;
  if ( (function->flags & excluded) != 0 || function->tailqty > 0
    || function->start_ea < inf_get_min_ea()
    || function->end_ea >= inf_get_max_ea() )
  {
    return false;
  }

  int instruction_count = 0;
  int calls = 0;
  int returns = 0;
  int other_terminators = 0;
  ea_t call_target = BADADDR;
  for ( ea_t address = function->start_ea; address < function->end_ea; )
  {
    insn_t instruction;
    if ( decode_insn(&instruction, address) <= 0
      || ++instruction_count > config.wrapper_max_instructions )
    {
      return false;
    }
    if ( writes_global_memory(instruction) )
      return false;
    const bool call = is_call_insn(instruction);
    const bool ret = is_ret_insn(instruction);
    if ( call )
    {
      if ( !direct_transfer(instruction) )
        return false;
      call_target = branch_target(instruction);
      ++calls;
    }
    if ( ret )
      ++returns;
    if ( !call && !ret && is_basic_block_end(instruction, false) )
      ++other_terminators;
    address += instruction.size;
  }
  if ( calls != 1 || other_terminators != 0 )
    return false;
  if ( returns == 0 )
  {
    const func_t *callee = get_func(call_target);
    if ( callee == nullptr || callee->does_return() )
      return false;
  }

  int callers = 0;
  xrefblk_t xref;
  for ( bool ok = xref.first_to(function->start_ea, XREF_CODE);
        ok; ok = xref.next_to() )
  {
    if ( xref.iscode && (xref.type == fl_CN || xref.type == fl_CF) )
      ++callers;
  }
  return config.wrapper_max_callers == 0
      || callers <= config.wrapper_max_callers;
}

ea_t bounded_function_end(ea_t start, int maximum_instructions)
{
  ea_t address = start;
  for ( int index = 0; index < maximum_instructions; ++index )
  {
    if ( !is_code(get_flags(address)) )
      return BADADDR;
    const func_t *owner = get_func(address);
    if ( address != start && owner != nullptr && owner->start_ea == address )
      return BADADDR;
    insn_t instruction;
    if ( decode_insn(&instruction, address) <= 0 )
      return BADADDR;
    if ( is_ret_insn(instruction) )
      return address + instruction.size;
    if ( (instruction.get_canon_feature(PH) & CF_STOP) != 0
      && !is_call_insn(instruction) )
    {
      return BADADDR;
    }
    address += instruction.size;
  }
  return BADADDR;
}

} // namespace

struct NativeAnalysisEngine::Impl final : event_listener_t
{
  NativeAnalysisConfig config = load_native_analysis_config();
  NativeAnalysisStats statistics;
  Architecture architecture = Architecture::Unsupported;
  bool hooked = false;
  bool post_analysis_running = false;
  bool post_metadata_scanned = false;
  rangeset_t emulated;
  rangeset_t prefix_seen;
  std::set<std::pair<int, ea_t>> findings_seen;
  std::vector<std::pair<ea_t, ea_t>> pending_cfg_edges;
  size_t reported_orphan_functions = 0;
  size_t reported_outlined_wrappers = 0;

  Impl()
  {
    if ( PH.id == PLFM_386 )
      architecture = Architecture::X86;
    else if ( PH.id == PLFM_ARM )
      architecture = Architecture::Arm;
    if ( config.enabled && architecture != Architecture::Unsupported )
      hooked = hook_event_listener(HT_IDP, this, this);
    if ( config.enabled )
    {
      msg("[chernobog][ida-analysis] native engine %s (%s)\n",
          hooked ? "enabled" : "unavailable",
          architecture == Architecture::X86 ? "x86"
        : architecture == Architecture::Arm ? "ARM" : "unsupported");
    }
  }

  ~Impl() override
  {
    if ( hooked )
      unhook_event_listener(HT_IDP, this);
  }

  void reset()
  {
    post_analysis_running = false;
    emulated.clear();
    prefix_seen.clear();
    findings_seen.clear();
    pending_cfg_edges.clear();
    statistics = NativeAnalysisStats{};
    post_metadata_scanned = false;
    reported_orphan_functions = 0;
    reported_outlined_wrappers = 0;
  }

  bool mark_once(int category, ea_t address)
  {
    return findings_seen.insert({ category, address }).second;
  }

  ssize_t handle_analysis(insn_t &instruction)
  {
    if ( architecture != Architecture::X86 || !config.redundant_prefixes
      || !is_redundant_rep_prefix(instruction.ea) )
    {
      return 0;
    }
    if ( !prefix_seen.contains(instruction.ea) )
    {
      prefix_seen.add(instruction.ea, instruction.ea + 1);
      ++statistics.redundant_prefixes;
    }
    instruction.size = 1;
    instruction.itype = NN_nop;
    return 1;
  }

  ssize_t handle_output_mnemonic(outctx_t &context)
  {
    if ( architecture != Architecture::X86 || !config.redundant_prefixes
      || !is_redundant_rep_prefix(context.insn.ea) )
    {
      return 0;
    }
    context.out_custom_mnem(get_byte(context.insn.ea) == 0xF2
                          ? "repne" : "rep");
    return 1;
  }

  bool handle_call_pop(const insn_t &instruction, bool revisiting)
  {
    if ( architecture != Architecture::X86 || !config.call_pop_get_pc
      || instruction.itype != NN_call || instruction.Op1.type != o_near )
    {
      return false;
    }
    const ea_t target = instruction.Op1.addr;
    const ea_t call_end = instruction.ea + instruction.size;
    if ( target == call_end || has_other_callers(target, instruction.ea) )
      return false;
    if ( target > call_end
      && uint64_t(target - call_end) > config.maximum_gap )
    {
      return false;
    }
    GadgetInfo gadget;
    if ( !analyze_get_pc_gadget(target, config.pop_ret_depth, gadget)
      || gadget.has_jump
      || (!gadget.pops_return && !gadget.pushes_return
       && !gadget.has_return && !gadget.discards_return)
      || (!gadget.pops_return && gadget.has_return
       && !gadget.pushes_return) )
    {
      return false;
    }

    add_user_cref(instruction.ea, target, fl_JN);
    set_notproc(target);
    statistics.gaps_retyped += retype_gap_as_bytes(
        call_end, target, config.maximum_gap, revisiting);
    add_user_stkpnt(target, -inf_get_effective_addrsize());

    if ( gadget.discards_return )
    {
      append_analysis_comment(instruction.ea,
                              "call+discard get-PC idiom");
    }
    else if ( gadget.pushes_return )
    {
      const ea_t resumed = ea_t(sval_t(call_end) + gadget.delta);
      if ( target_is_executable(resumed) )
      {
        add_user_cref(instruction.ea, resumed, fl_F);
        if ( !revisiting && resumed >= call_end && resumed < target
          && is_unknown(get_flags(resumed)) )
        {
          create_insn(resumed);
        }
        func_t *owner = get_func(instruction.ea);
        if ( owner != nullptr && get_func(resumed) == nullptr )
          append_func_tail(owner, resumed, BADADDR);
        if ( gadget.return_ea != BADADDR )
        {
          const auto edge = std::make_pair(gadget.return_ea, resumed);
          if ( std::find(pending_cfg_edges.begin(), pending_cfg_edges.end(), edge)
            == pending_cfg_edges.end() )
          {
            pending_cfg_edges.push_back(edge);
          }
        }
      }
      append_analysis_comment(instruction.ea, "call+pop get-PC idiom");
    }
    else
    {
      append_analysis_comment(instruction.ea, "call+pop get-PC idiom");
    }
    if ( mark_once(1, instruction.ea) )
      ++statistics.get_pc_gadgets;
    return true;
  }

  bool handle_push_return(const insn_t &instruction)
  {
    if ( architecture != Architecture::X86 || !config.push_return
      || instruction.itype != NN_push || instruction.Op1.type != o_imm )
    {
      return false;
    }
    insn_t ret;
    if ( decode_insn(&ret, instruction.ea + instruction.size) <= 0
      || !is_ret_insn(ret) )
    {
      return false;
    }
    ea_t target = ea_t(instruction.Op1.value);
    if ( inf_is_64bit() )
      target = ea_t(int64_t(int32_t(instruction.Op1.value)));
    if ( !target_is_executable(target) )
      return false;
    add_user_cref(ret.ea, target, fl_JN);
    if ( is_unknown(get_flags(target)) )
    {
      auto_make_code(target);
      plan_ea(target);
    }
    append_analysis_comment(ret.ea, "constant push/return target");
    if ( mark_once(2, ret.ea) )
      ++statistics.push_return_targets;
    return true;
  }

  bool handle_zero_register(const insn_t &instruction)
  {
    if ( architecture != Architecture::Arm || !config.zero_register_branches )
      return false;
    BranchDecision decision = BranchDecision::Unknown;
    switch ( instruction.itype )
    {
      case ARM_cbz:
      case ARM_tbz:
        if ( zero_register_operand(instruction.Op1) )
          decision = BranchDecision::Taken;
        break;
      case ARM_cbnz:
      case ARM_tbnz:
        if ( zero_register_operand(instruction.Op1) )
          decision = BranchDecision::NotTaken;
        break;
      default:
        break;
    }
    if ( decision == BranchDecision::Unknown )
      return false;
    const ea_t target = branch_target(instruction);
    if ( target == BADADDR )
      return false;
    if ( decision == BranchDecision::Taken )
      add_user_cref(instruction.ea, target, fl_JN);
    else
      add_user_cref(instruction.ea, instruction.ea + instruction.size, fl_F);
    append_analysis_comment(
        instruction.ea, decision == BranchDecision::Taken
                      ? "always taken (architectural zero register)"
                      : "never taken (architectural zero register)");
    if ( mark_once(3, instruction.ea) )
      ++statistics.zero_register_branches;
    return true;
  }

  bool handle_opposite_pair(const insn_t &instruction, bool revisiting)
  {
    if ( !config.opposite_branches )
      return false;
    insn_t next;
    if ( decode_insn(&next, instruction.ea + instruction.size) <= 0 )
      return false;
    const ea_t target = branch_target(instruction);
    if ( target == BADADDR || branch_target(next) != target )
      return false;
    bool opposite = false;
    if ( architecture == Architecture::X86 )
      opposite = opposite_x86_condition(instruction.itype) == next.itype;
    else if ( architecture == Architecture::Arm )
      opposite = opposite_arm_branch(instruction, next);
    if ( !opposite )
      return false;

    add_user_cref(instruction.ea, target, fl_JN);
    add_user_cref(instruction.ea, instruction.ea + instruction.size, fl_F);
    add_user_cref(next.ea, target, fl_JN);
    statistics.gaps_retyped += retype_gap_as_bytes(
        next.ea + next.size, target, config.maximum_gap, revisiting);
    append_analysis_comment(instruction.ea,
                            "adjacent opposite predicates cover both outcomes");
    if ( mark_once(4, instruction.ea) )
      ++statistics.opposite_branch_pairs;
    return true;
  }

  bool handle_entry_predicate(const insn_t &instruction)
  {
    if ( architecture != Architecture::X86 || !config.entry_predicates
      || opposite_x86_condition(instruction.itype) == 0 )
    {
      return false;
    }
    const func_t *function = get_func(instruction.ea);
    if ( function == nullptr || instruction.ea < function->start_ea
      || uint64_t(instruction.ea - function->start_ea)
           > config.entry_predicate_window )
    {
      return false;
    }
    for ( ea_t scan = function->start_ea; scan < instruction.ea; )
    {
      insn_t prior;
      if ( decode_insn(&prior, scan) <= 0 )
        return false;
      if ( instruction_modifies_x86_flags(prior.itype) )
        return false;
      scan += prior.size;
    }
    if ( append_analysis_comment(
            instruction.ea,
            "entry predicate consumes ABI-unspecified flags")
      && mark_once(5, instruction.ea) )
    {
      ++statistics.entry_predicates;
    }
    return true;
  }

  bool handle_known_x86_flag(const insn_t &instruction, bool revisiting)
  {
    if ( architecture != Architecture::X86 || !config.known_x86_flags )
      return false;
    if ( instruction.itype != NN_jb && instruction.itype != NN_jnb
      && instruction.itype != NN_jbe && instruction.itype != NN_ja
      && instruction.itype != NN_jz && instruction.itype != NN_jnz
      && instruction.itype != NN_jle && instruction.itype != NN_jnle )
    {
      return false;
    }
    BranchDecision decision = BranchDecision::Unknown;
    const FlagValue carry = scan_x86_flag(
        instruction.ea, config.flag_scan_depth,
        [](const FlagEffects &effects) { return effects.carry; });
    decision = decision_for_x86_flag(instruction.itype, true, carry);
    const char *flag_name = "CF";
    if ( decision == BranchDecision::Unknown )
    {
      const FlagValue zero = scan_x86_flag(
          instruction.ea, config.flag_scan_depth,
          [](const FlagEffects &effects) { return effects.zero; });
      decision = decision_for_x86_flag(instruction.itype, false, zero);
      flag_name = "ZF";
    }
    if ( decision == BranchDecision::Unknown )
      return false;
    const ea_t target = branch_target(instruction);
    if ( target == BADADDR )
      return false;
    const ea_t fallthrough = instruction.ea + instruction.size;
    if ( decision == BranchDecision::Taken )
    {
      add_user_cref(instruction.ea, target, fl_JN);
      statistics.gaps_retyped += retype_gap_as_bytes(
          fallthrough, target, config.maximum_gap, revisiting);
    }
    else
    {
      add_user_cref(instruction.ea, fallthrough, fl_F);
    }
    qstring comment;
    comment.sprnt("%s (locally known %s)",
                  decision == BranchDecision::Taken
                    ? "always taken" : "never taken",
                  flag_name);
    append_analysis_comment(instruction.ea, comment.c_str());
    if ( mark_once(6, instruction.ea) )
      ++statistics.known_flag_branches;
    return true;
  }

  bool handle_indirect_branch(const insn_t &instruction)
  {
    if ( !config.indirect_branches )
      return false;
    const bool call = is_call_insn(instruction);
    const bool jump = is_indirect_jump_insn(instruction);
    if ( (!call && !jump) || is_ret_insn(instruction) )
      return false;
    const uint32_t features = instruction.get_canon_feature(PH);
    int reg = -1;
    for ( int index = 0; index < UA_MAXOP; ++index )
    {
      const op_t &operand = instruction.ops[index];
      if ( operand.type == o_void )
        break;
      if ( operand.type != o_reg )
        continue;
      if ( has_cf_chg(features, index) && !has_cf_use(features, index) )
        continue;
      reg = operand.reg;
      break;
    }
    if ( reg < 0 )
      return false;
    reg_value_info_t value;
    ea_t target = BADADDR;
    if ( !find_reg_value_info(
            &value, instruction.ea, reg, config.register_scan_depth)
      || !value.get_addr(&target) || !target_is_executable(target) )
    {
      return false;
    }
    const cref_t type = call ? fl_CN : fl_JN;
    if ( flow_xref_exists(instruction.ea, true, BADADDR, type) )
      return false;
    add_user_cref(instruction.ea, target, type);
    qstring comment;
    comment.sprnt("resolved to %a (IDA register tracker)", target);
    append_analysis_comment(instruction.ea, comment.c_str());
    if ( mark_once(7, instruction.ea) )
      ++statistics.indirect_targets;
    return true;
  }

  bool handle_jump_gap(const insn_t &instruction, bool revisiting)
  {
    if ( architecture != Architecture::X86 || !config.jump_gaps
      || instruction.itype != NN_jmp || instruction.Op1.type == o_far )
    {
      return false;
    }
    const ea_t target = branch_target(instruction);
    const ea_t fallthrough = instruction.ea + instruction.size;
    if ( target == BADADDR || target <= fallthrough )
      return false;
    const size_t changed = retype_gap_as_bytes(
        fallthrough, target, config.maximum_gap, revisiting);
    statistics.gaps_retyped += changed;
    return changed != 0;
  }

  ssize_t handle_emulation(const insn_t &instruction)
  {
    const bool revisiting = emulated.contains(instruction.ea);
    if ( !revisiting )
      emulated.add(instruction.ea, instruction.ea + instruction.size);
    ssize_t handled = 0;
    handled |= handle_call_pop(instruction, revisiting) ? 1 : 0;
    handled |= handle_push_return(instruction) ? 1 : 0;
    handled |= handle_zero_register(instruction) ? 1 : 0;
    handled |= handle_opposite_pair(instruction, revisiting) ? 1 : 0;
    handled |= handle_entry_predicate(instruction) ? 1 : 0;
    handled |= handle_known_x86_flag(instruction, revisiting) ? 1 : 0;
    handled |= handle_indirect_branch(instruction) ? 1 : 0;
    handled |= handle_jump_gap(instruction, revisiting) ? 1 : 0;
    return handled;
  }

  ssize_t idaapi on_event(ssize_t code, va_list arguments) override
  {
    if ( !config.enabled )
      return 0;
    if ( code == processor_t::ev_ana_insn )
      return handle_analysis(*va_arg(arguments, insn_t *));
    if ( code == processor_t::ev_emu_insn )
      return handle_emulation(*va_arg(arguments, const insn_t *));
    if ( code == processor_t::ev_out_mnem )
      return handle_output_mnemonic(*va_arg(arguments, outctx_t *));
    return 0;
  }

  void fix_pending_cfg_edges()
  {
    for ( const auto &edge : pending_cfg_edges )
    {
      if ( is_code(get_flags(edge.first))
        && get_item_end(edge.first) == edge.second )
      {
        add_user_cref(edge.first, edge.second, fl_F);
      }
    }
    pending_cfg_edges.clear();
  }

  void recover_orphan_functions()
  {
    if ( !config.orphan_functions )
      return;
    std::set<ea_t> candidates;
    size_t scanned_heads = 0;
    bool limit_hit = false;
    const int segment_count = get_segm_qty();
    for ( int segment_index = 0;
          segment_index < segment_count && !limit_hit;
          ++segment_index )
    {
      const segment_t *segment = getnseg(segment_index);
      if ( segment == nullptr || (segment->perm & SEGPERM_EXEC) == 0 )
        continue;
      ea_t address = segment->start_ea;
      while ( address != BADADDR && address < segment->end_ea )
      {
        if ( scanned_heads >= config.maximum_post_scan_heads )
        {
          limit_hit = true;
          break;
        }
        ++scanned_heads;
        if ( is_code(get_flags(address)) && is_head(get_flags(address)) )
        {
          insn_t instruction;
          if ( decode_insn(&instruction, address) > 0
            && is_call_insn(instruction) && direct_transfer(instruction) )
          {
            const ea_t target = branch_target(instruction);
            func_t *owner = target != BADADDR ? get_func(target) : nullptr;
            if ( target_is_executable(target)
              && (owner == nullptr || owner->start_ea != target) )
            {
              // Never split an existing function. Interior-call evidence is
              // retained by its cref/comment but not promoted automatically.
              if ( owner == nullptr )
                candidates.insert(target);
            }
          }
        }
        const ea_t next = next_head(address, segment->end_ea);
        if ( next == BADADDR || next <= address )
          break;
        address = next;
      }
    }
    statistics.post_scan_heads += scanned_heads;
    statistics.post_scan_truncated |= limit_hit;

    size_t promoted = 0;
    for ( ea_t target : candidates )
    {
      if ( get_func(target) != nullptr || !target_is_executable(target) )
        continue;
      if ( is_unknown(get_flags(target)) )
      {
        insn_t decoded;
        if ( decode_insn(&decoded, target) <= 0 || create_insn(target) <= 0 )
          continue;
      }
      if ( add_func(target) )
      {
        ++promoted;
        continue;
      }
      const ea_t end = bounded_function_end(
          target, config.orphan_scan_instructions);
      if ( end != BADADDR && get_func(target) == nullptr
        && add_func(target, end) )
      {
        ++promoted;
      }
    }
    statistics.orphan_functions += promoted;
  }

  void outline_wrapper_functions()
  {
    if ( !config.outline_wrappers )
      return;
    size_t marked = 0;
    const size_t count = get_func_qty();
    const size_t scan_count = qmin(
        count, config.maximum_post_scan_functions);
    for ( size_t index = 0; index < scan_count; ++index )
    {
      func_t *function = getn_func(index);
      if ( function == nullptr || (function->flags & FUNC_OUTLINE) != 0 )
        continue;
      if ( !name_contains_hikari_wrapper(function->start_ea)
        && !wrapper_shape(function, config) )
      {
        continue;
      }
      const uint32_t old_flags = function->flags;
      function->flags |= FUNC_OUTLINE;
      if ( update_func(function) )
        ++marked;
      else
        function->flags = old_flags;
    }
    statistics.post_scan_functions += scan_count;
    statistics.post_scan_truncated |= scan_count < count;
    statistics.outlined_wrappers += marked;
  }

  void on_autoanalysis_complete()
  {
    if ( !config.enabled || post_analysis_running )
      return;
    post_analysis_running = true;
    fix_pending_cfg_edges();
    if ( !post_metadata_scanned )
    {
      // This is a bounded IDA decoder/xref metadata pass, not emulation.
      // Run it once between per-database resets; later autoanalysis events
      // only commit deferred native fallthrough edges.
      post_metadata_scanned = true;
      recover_orphan_functions();
      outline_wrapper_functions();
      if ( statistics.post_scan_truncated )
      {
        msg("[chernobog][ida-analysis] post-analysis scan reached its "
            "configured bound (%zu heads, %zu functions)\n",
            statistics.post_scan_heads, statistics.post_scan_functions);
      }
    }
    if ( statistics.orphan_functions != reported_orphan_functions
      || statistics.outlined_wrappers != reported_outlined_wrappers )
    {
      msg("[chernobog][ida-analysis] post-analysis: %zu orphan functions, "
          "%zu outlined wrappers\n",
          statistics.orphan_functions, statistics.outlined_wrappers);
      reported_orphan_functions = statistics.orphan_functions;
      reported_outlined_wrappers = statistics.outlined_wrappers;
    }
    post_analysis_running = false;
  }
};

NativeAnalysisEngine::NativeAnalysisEngine()
  : impl_(new Impl)
{
}

NativeAnalysisEngine::~NativeAnalysisEngine() = default;

bool NativeAnalysisEngine::enabled() const
{
  return impl_ != nullptr && impl_->config.enabled && impl_->hooked;
}

void NativeAnalysisEngine::reset()
{
  if ( impl_ != nullptr )
    impl_->reset();
}

void NativeAnalysisEngine::on_autoanalysis_complete()
{
  if ( impl_ != nullptr )
    impl_->on_autoanalysis_complete();
}

const NativeAnalysisStats &NativeAnalysisEngine::stats() const
{
  static const NativeAnalysisStats empty;
  return impl_ != nullptr ? impl_->statistics : empty;
}

} // namespace chernobog::ida_analysis
