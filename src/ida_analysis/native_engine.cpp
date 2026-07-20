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
#include "get_pc_ida.hpp"
#include "ida_sdk_compat.hpp"

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

bool target_is_mapped_executable(ea_t target)
{
  const segment_t *segment = getseg(target);
  return target != BADADDR && is_mapped(target) && segment != nullptr
      && (segment->perm == 0 || (segment->perm & SEGPERM_EXEC) != 0);
}

// Packers commonly place executable instructions in a PE section whose
// loader permissions are RW.  For an already-proven control transfer, accept
// such a target only when IDA can decode it and either IDA has classified the
// segment/item as code or the transfer remains within the source segment.
// This deliberately does not make arbitrary non-executable data branchable.
bool target_is_proven_code_candidate(ea_t from, ea_t target)
{
  if ( target_is_mapped_executable(target) )
    return true;
  if ( from == BADADDR || target == BADADDR || !is_mapped(target) )
    return false;
  const segment_t *source_segment = getseg(from);
  const segment_t *target_segment = getseg(target);
  if ( source_segment == nullptr || target_segment == nullptr )
    return false;
  const flags64_t flags = get_flags(target);
  if ( source_segment != target_segment
    && target_segment->type != SEG_CODE && !is_code(flags) )
  {
    return false;
  }
  insn_t decoded;
  return decode_insn(&decoded, target) > 0;
}

bool add_user_cref(
    ea_t from,
    ea_t to,
    cref_t type,
    bool persistent = true,
    bool require_code_target = true)
{
  if ( from == BADADDR
    || (require_code_target
      ? !target_is_executable(to) : !target_is_mapped_executable(to))
    || !is_code(get_flags(from)) || !is_head(get_flags(from)) )
  {
    return false;
  }
  xrefblk_t xref;
  for ( bool ok = xref.first_from(from, XREF_CODE);
        ok; ok = xref.next_from() )
  {
    if ( xref.to != to )
      continue;
    if ( (int(xref.type) & XREF_MASK) == int(type) )
      return false;
    // Preserve a user-selected edge type. IDA-generated call edges are safe
    // to replace after the get-PC gadget has been proven.
    if ( xref.user )
      return false;
    del_cref(from, to, false);
    break;
  }
  // A call/pop classification must replace IDA's initial fl_CN edge with
  // fl_JN. fl_F cannot carry XREF_USER and is handled as ordinary flow.
  const cref_t stored_type = type == fl_F || !persistent
                           ? type
                           : cref_t(int(type) | XREF_USER);
  return add_cref(from, to, stored_type);
}

struct desired_code_edge_t
{
  ea_t target = BADADDR;
  cref_t type = fl_U;
  bool persistent = true;
};

bool edge_matches(
    ea_t target,
    int type,
    const desired_code_edge_t &desired)
{
  return target == desired.target
      && (int(type) & XREF_MASK) == (int(desired.type) & XREF_MASK);
}

bool exact_code_edge_exists(
    ea_t from,
    const desired_code_edge_t &desired)
{
  xrefblk_t xref;
  for ( bool ok = xref.first_from(from, XREF_CODE); ok; ok = xref.next_from() )
  {
    if ( edge_matches(xref.to, xref.type, desired) )
      return true;
  }
  return false;
}

struct existing_code_edge_t
{
  ea_t target = BADADDR;
  cref_t type = fl_U;
  bool user = false;
};

std::vector<existing_code_edge_t> collect_code_edges(ea_t from)
{
  std::vector<existing_code_edge_t> result;
  xrefblk_t xref;
  for ( bool ok = xref.first_from(from, XREF_CODE); ok; ok = xref.next_from() )
  {
    result.push_back(existing_code_edge_t{
      xref.to, cref_t(int(xref.type) & XREF_MASK), xref.user,
    });
  }
  return result;
}

bool desired_edge_set_is_exact(
    ea_t from,
    const std::vector<desired_code_edge_t> &desired)
{
  const std::vector<existing_code_edge_t> current = collect_code_edges(from);
  if ( current.size() != desired.size() )
    return false;
  for ( const existing_code_edge_t &edge : current )
  {
    const auto found = std::find_if(
        desired.begin(), desired.end(),
        [&](const desired_code_edge_t &candidate) {
          return edge_matches(edge.target, edge.type, candidate);
        });
    if ( found == desired.end() )
      return false;
    if ( found->persistent && found->type != fl_F && !edge.user )
      return false;
  }
  return true;
}

void remove_generated_code_edges(ea_t from)
{
  std::vector<ea_t> targets;
  for ( const existing_code_edge_t &edge : collect_code_edges(from) )
  {
    if ( !edge.user )
      targets.push_back(edge.target);
  }
  std::sort(targets.begin(), targets.end());
  targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
  for ( ea_t target : targets )
    del_cref(from, target, false);
}

// Replace only IDA-generated edges. A conflicting user edge is an explicit
// boundary and makes an exclusive branch proof inapplicable.
bool replace_generated_code_edges(
    ea_t from,
    const std::vector<desired_code_edge_t> &desired)
{
  qstring trace_value;
  const bool trace = qgetenv(
      "CHERNOBOG_IDA_GET_PC_TRACE", &trace_value)
      && !trace_value.empty() && trace_value[0] != '0';
  if ( trace )
    msg("[chernobog][ida-analysis][edge-trace] enter from=%a desired=%zu\n",
        from, desired.size());
  if ( from == BADADDR || desired.empty() )
  {
    if ( trace )
      msg("[chernobog][ida-analysis][edge-trace] reject invalid source/set\n");
    return false;
  }
  for ( const desired_code_edge_t &edge : desired )
  {
    if ( edge.target == BADADDR
      || !target_is_proven_code_candidate(from, edge.target) )
    {
      if ( trace )
      {
        const segment_t *segment = getseg(edge.target);
        msg("[chernobog][ida-analysis][edge-trace] reject target=%a "
            "mapped=%d segment=%p perm=%d\n",
            edge.target, is_mapped(edge.target) ? 1 : 0, segment,
            segment != nullptr ? segment->perm : -1);
      }
      return false;
    }
  }
  for ( size_t index = 0; index < desired.size(); ++index )
  {
    for ( size_t other = index + 1; other < desired.size(); ++other )
    {
      if ( desired[index].target == desired[other].target )
      {
        if ( trace )
          msg("[chernobog][ida-analysis][edge-trace] reject duplicate=%a\n",
              desired[index].target);
        return false;
      }
    }
  }

  const std::vector<existing_code_edge_t> original = collect_code_edges(from);
  if ( trace )
  {
    msg("[chernobog][ida-analysis][edge-trace] from=%a original=%zu "
        "desired=%zu\n", from, original.size(), desired.size());
    for ( const existing_code_edge_t &edge : original )
      msg("[chernobog][ida-analysis][edge-trace]   old to=%a type=%d "
          "user=%d\n", edge.target, int(edge.type), edge.user ? 1 : 0);
  }
  for ( const existing_code_edge_t &edge : original )
  {
    if ( edge.user && std::none_of(
          desired.begin(), desired.end(),
          [&](const desired_code_edge_t &candidate) {
            return edge_matches(edge.target, edge.type, candidate);
          }) )
    {
      if ( trace )
        msg("[chernobog][ida-analysis][edge-trace] reject conflicting "
            "user edge to=%a type=%d\n", edge.target, int(edge.type));
      return false;
    }
  }
  if ( desired_edge_set_is_exact(from, desired) )
    return true;

  // Rebuild the generated portion as a transaction. User edges that agree
  // with the proof remain untouched; every generated edge can be restored
  // exactly if an insertion fails.
  remove_generated_code_edges(from);
  bool success = true;
  std::vector<ea_t> inserted_targets;
  for ( const desired_code_edge_t &edge : desired )
  {
    if ( exact_code_edge_exists(from, edge) )
      continue;
    const cref_t stored_type = edge.type == fl_F || !edge.persistent
                            ? edge.type
                            : cref_t(int(edge.type) | XREF_USER);
    const bool inserted = add_cref(from, edge.target, stored_type);
    if ( trace )
      msg("[chernobog][ida-analysis][edge-trace]   add to=%a type=%d "
          "inserted=%d exact=%d\n", edge.target, int(stored_type),
          inserted ? 1 : 0,
          exact_code_edge_exists(from, edge) ? 1 : 0);
    if ( inserted || exact_code_edge_exists(from, edge) )
      inserted_targets.push_back(edge.target);
    if ( !inserted && !exact_code_edge_exists(from, edge) )
    {
      success = false;
      break;
    }
  }
  success = success && desired_edge_set_is_exact(from, desired);
  if ( trace )
  {
    const std::vector<existing_code_edge_t> current = collect_code_edges(from);
    msg("[chernobog][ida-analysis][edge-trace] final success=%d count=%zu\n",
        success ? 1 : 0, current.size());
    for ( const existing_code_edge_t &edge : current )
      msg("[chernobog][ida-analysis][edge-trace]   now to=%a type=%d "
          "user=%d\n", edge.target, int(edge.type), edge.user ? 1 : 0);
  }
  if ( success )
    return true;

  for ( ea_t target : inserted_targets )
    del_cref(from, target, false);
  remove_generated_code_edges(from);
  for ( const existing_code_edge_t &edge : original )
  {
    if ( edge.user )
      continue;
    add_cref(from, edge.target, edge.type);
  }
  return false;
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
      && (required_type == cref_t(-1)
       || (int(xref.type) & XREF_MASK) == int(required_type)) )
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

bool has_inbound_reference(
    ea_t address,
    ea_t allowed_source = BADADDR)
{
  xrefblk_t xref;
  for ( bool ok = xref.first_to(address, XREF_ALL);
        ok; ok = xref.next_to() )
  {
    // A proven always-transfer instruction can leave an IDA-generated
    // fallthrough into the skipped bytes from an earlier analysis wave. That
    // edge is precisely the stale state being repaired. User-selected edges
    // and every reference from another source remain a hard barrier.
    if ( xref.from != allowed_source || xref.user )
      return true;
  }
  return false;
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

bool safe_gap_candidate(
    ea_t start,
    ea_t end,
    uint64_t maximum_gap,
    ea_t allowed_source)
{
  if ( start >= end || uint64_t(end - start) > maximum_gap )
    return false;
  const func_t *owner = get_func(start);
  for ( ea_t address = start; address < end; ++address )
  {
    const flags64_t flags = get_flags(address);
    if ( !is_mapped(address) || !is_loaded(address)
      || has_protected_metadata(address, flags)
      || has_inbound_reference(address, allowed_source) )
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

size_t retype_gap_as_bytes(
    ea_t start,
    ea_t end,
    uint64_t maximum_gap,
    ea_t allowed_source)
{
  // The operation is idempotent: existing one-byte data items are retained.
  // Re-run the safety proof even on a revisited instruction because a plugin
  // loaded during an active autoanalysis wave can first observe the source
  // after IDA has already decoded the skipped byte as overlapping code.
  if ( !safe_gap_candidate(start, end, maximum_gap, allowed_source) )
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

bool operands_equivalent(const op_t &left, const op_t &right)
{
  if ( left.type != right.type || left.dtype != right.dtype
    || left.flags != right.flags )
  {
    return false;
  }
  if ( left.type == o_void )
    return true;
  return left.reg == right.reg && left.value == right.value
      && left.addr == right.addr && left.specval == right.specval
      && left.specflag1 == right.specflag1
      && left.specflag2 == right.specflag2
      && left.specflag3 == right.specflag3
      && left.specflag4 == right.specflag4;
}

bool instructions_equivalent_without_prefix(
    const insn_t &prefixed,
    const insn_t &plain)
{
  if ( prefixed.itype != plain.itype || prefixed.size != plain.size + 1
    || prefixed.get_canon_feature(PH) != plain.get_canon_feature(PH) )
  {
    return false;
  }
  for ( int index = 0; index < UA_MAXOP; ++index )
  {
    if ( !operands_equivalent(prefixed.ops[index], plain.ops[index]) )
      return false;
    if ( prefixed.ops[index].type == o_void )
      break;
  }
  return true;
}

bool prefix_candidate_is_semantically_eligible(
    ea_t address,
    const insn_t &prefixed)
{
  if ( !is_loaded(address) || !is_loaded(address + 1) )
    return false;
  const uint8_t prefix = get_byte(address);
  if ( prefix != 0xF2 && prefix != 0xF3 )
    return false;
  const uint8_t opcode = get_byte(address + 1);
  // Any second prefix byte makes this a prefix train. Conservatively retain
  // it; the following byte, not this one, determines REP semantics.
  if ( opcode == 0x0F || opcode == 0x26 || opcode == 0x2E
    || opcode == 0x36 || opcode == 0x3E || opcode == 0x64
    || opcode == 0x65 || opcode == 0x66 || opcode == 0x67
    || opcode == 0xF0 || opcode == 0xF2 || opcode == 0xF3
    || (inf_is_64bit() && opcode >= 0x40 && opcode <= 0x4F)
    || (prefix == 0xF3 && opcode == 0x90) )
  {
    return false;
  }
  if ( prefix == 0xF3
    && (opcode == 0xC2 || opcode == 0xC3
     || opcode == 0xCA || opcode == 0xCB) )
  {
    return false;
  }
  if ( (opcode >= 0xA4 && opcode <= 0xA7)
    || (opcode >= 0xAA && opcode <= 0xAF)
    || (opcode >= 0x6C && opcode <= 0x6F)
    || is_call_insn(prefixed) || is_basic_block_end(prefixed, false) )
  {
    return false;
  }
  return true;
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
      // A CALL transfers through code that may change arithmetic flags. Even a
      // proved get-PC gadget can contain INC/DEC/ADD/SUB, so flags never cross
      // the call boundary without a separate complete effect summary.
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

bool exact_register_operand(const op_t &left, const op_t &right)
{
  if ( left.type != o_reg || right.type != o_reg
    || left.dtype != right.dtype )
  {
    return false;
  }
  const size_t width = get_dtype_size(left.dtype);
  if ( width == 0 || width != get_dtype_size(right.dtype) )
    return false;
  qstring left_name;
  qstring right_name;
  if ( get_reg_name(&left_name, left.reg, width) <= 0
    || get_reg_name(&right_name, right.reg, width) <= 0 )
  {
    return false;
  }
  bitrange_t left_range;
  bitrange_t right_range;
  const char *left_main = PH.get_reg_info(left_name.c_str(), &left_range);
  const char *right_main = PH.get_reg_info(right_name.c_str(), &right_range);
  if ( left_main == nullptr || right_main == nullptr
    || str2reg(left_main) != str2reg(right_main) )
  {
    return false;
  }
  const size_t left_offset = left_range.empty() ? 0 : left_range.bitoff();
  const size_t right_offset = right_range.empty() ? 0 : right_range.bitoff();
  const size_t left_bits = left_range.empty() ? width * 8
                                              : left_range.bitsize();
  const size_t right_bits = right_range.empty() ? width * 8
                                                : right_range.bitsize();
  return left_offset == right_offset && left_bits == right_bits;
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
    return exact_register_operand(left.Op1, right.Op1);
  }
  if ( (left.itype == ARM_tbz && right.itype == ARM_tbnz)
    || (left.itype == ARM_tbnz && right.itype == ARM_tbz) )
  {
    if ( !exact_register_operand(left.Op1, right.Op1)
      || left.Op2.type != o_imm || right.Op2.type != o_imm
      || left.Op2.value != right.Op2.value )
    {
      return false;
    }
    const size_t width = get_dtype_size(left.Op1.dtype);
    return width != 0 && left.Op2.value < width * 8;
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
  bool final_instruction_is_return = false;
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
    const ea_t next = address + instruction.size;
    final_instruction_is_return = ret && next == function->end_ea;
    address = next;
  }
  if ( calls != 1 || other_terminators != 0
    || call_target == BADADDR || call_target == function->start_ea
    || !target_is_mapped_executable(call_target) )
    return false;
  const func_t *callee = get_func(call_target);
  const bool callee_returns = callee == nullptr || callee->does_return();
  if ( callee_returns )
  {
    if ( returns != 1 || !final_instruction_is_return )
      return false;
  }
  else if ( returns != 0 )
  {
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
    // This is deliberately a linear item-boundary scan, matching IDA's
    // orphan-callee recovery heuristic. A legitimate function may contain
    // direct jumps before its natural return; CF_STOP is therefore not a
    // rejection criterion here. Existing function entries still terminate
    // the scan above, and the configured instruction bound prevents runaway.
    address += instruction.size;
  }
  return BADADDR;
}

} // namespace

struct NativeAnalysisEngine::Impl final : event_listener_t
{
  const ssize_t owner_database = get_dbctx_id();
  NativeAnalysisConfig config = load_native_analysis_config();
  NativeAnalysisStats statistics;
  Architecture architecture = Architecture::Unsupported;
  bool hooked = false;
  bool post_analysis_running = false;
  bool post_metadata_scanned = false;
  bool prefix_decode_probe = false;
  rangeset_t emulated;
  rangeset_t prefix_seen;
  std::set<std::pair<int, ea_t>> findings_seen;
  std::set<ea_t> get_pc_function_roots;
  std::set<ea_t> observed_direct_call_targets;
  std::vector<std::pair<ea_t, ea_t>> pending_cfg_edges;
  size_t reported_orphan_functions = 0;
  size_t reported_outlined_wrappers = 0;
  size_t reported_get_pc_tail_extensions = 0;

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
    prefix_decode_probe = false;
    emulated.clear();
    prefix_seen.clear();
    findings_seen.clear();
    get_pc_function_roots.clear();
    observed_direct_call_targets.clear();
    pending_cfg_edges.clear();
    statistics = NativeAnalysisStats{};
    post_metadata_scanned = false;
    reported_orphan_functions = 0;
    reported_outlined_wrappers = 0;
    reported_get_pc_tail_extensions = 0;
  }

  bool mark_once(int category, ea_t address)
  {
    return findings_seen.insert({ category, address }).second;
  }

  void remember_direct_call_target(ea_t target, ea_t fallthrough)
  {
    if ( target == BADADDR || target == fallthrough
      || observed_direct_call_targets.count(target) != 0 )
    {
      return;
    }
    if ( observed_direct_call_targets.size()
         >= config.maximum_post_scan_heads )
    {
      statistics.post_scan_truncated = true;
      return;
    }
    observed_direct_call_targets.insert(target);
  }

  bool redundant_rep_prefix(ea_t address)
  {
    if ( prefix_decode_probe || !is_loaded(address)
      || !is_loaded(address + 1) )
    {
      return false;
    }
    struct probe_scope_t
    {
      bool &active;
      explicit probe_scope_t(bool &value) : active(value) { active = true; }
      ~probe_scope_t() { active = false; }
    } probe(prefix_decode_probe);

    insn_t prefixed;
    insn_t plain;
    return decode_insn(&prefixed, address) > 0
        && prefix_candidate_is_semantically_eligible(address, prefixed)
        && decode_insn(&plain, address + 1) > 0
        && instructions_equivalent_without_prefix(prefixed, plain);
  }

  ssize_t handle_analysis(insn_t &instruction)
  {
    if ( prefix_decode_probe || architecture != Architecture::X86
      || !config.redundant_prefixes
      || !redundant_rep_prefix(instruction.ea) )
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
      || !redundant_rep_prefix(context.insn.ea) )
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
    if ( target > call_end
      && uint64_t(target - call_end) > config.maximum_gap )
    {
      return false;
    }
    const auto gadget = classify_ida_get_pc_call(
        instruction, size_t(config.pop_ret_depth), true);
    if ( !gadget )
      return false;
    qstring trace;
    if ( qgetenv("CHERNOBOG_IDA_GET_PC_TRACE", &trace)
      && !trace.empty() && trace[0] != '0' )
    {
      msg("[chernobog][ida-analysis][get-pc-trace] native accepted call=%a "
          "target=%a owner=%p revisiting=%d\n",
          instruction.ea, target, get_func(instruction.ea),
          revisiting ? 1 : 0);
    }

    // This handler owns processor emulation for the reclassified CALL. Install
    // the one exact outgoing transfer and remove stale IDA-generated call and
    // fallthrough edges. Conflicting user edges make the proof inapplicable.
    if ( !replace_generated_code_edges(
            instruction.ea,
            { desired_code_edge_t{target, fl_JN, true} }) )
      return false;
    set_notproc(target);
    if ( is_unknown(get_flags(target)) )
      create_insn(target);
    auto_make_code(target);
    plan_ea(target);
    // Every accepted get-PC form is an intra-function transfer. In
    // particular, add-sp/discard gadgets continue in the target body and have
    // no later return edge that could otherwise pull that range into the
    // caller. Admit the proven gadget target before queuing it so nested
    // get-PC chains are traversed rather than truncated at an auto-created
    // tail boundary.
    func_t *call_owner = get_func(instruction.ea);
    if ( call_owner != nullptr )
      get_pc_function_roots.insert(call_owner->start_ea);
    if ( call_owner != nullptr && !func_contains(call_owner, target) )
    {
      const bool appended = append_func_tail_ea(
          call_owner->start_ea, target, BADADDR);
      if ( !trace.empty() && trace[0] != '0' )
        msg("[chernobog][ida-analysis][get-pc-trace] target-tail owner=%a "
            "target=%a appended=%d\n", call_owner->start_ea, target,
            appended ? 1 : 0);
    }
    statistics.gaps_retyped += retype_gap_as_bytes(
        call_end, target, config.maximum_gap, instruction.ea);
    add_user_stkpnt(target, -effective_address_size_compat());

    append_analysis_comment(
        instruction.ea,
        gadget->mode == classifier::get_pc_mode_t::discard_return_address
          ? "call+discard get-PC idiom" : "call+pop get-PC idiom");
    if ( gadget->resumed_at.has_value() )
    {
      const ea_t resumed = ea_t(*gadget->resumed_at);
      if ( target_is_proven_code_candidate(instruction.ea, resumed) )
      {
        if ( !revisiting && resumed >= call_end && resumed < target
          && is_unknown(get_flags(resumed)) )
        {
          create_insn(resumed);
        }
        if ( is_unknown(get_flags(resumed)) )
          create_insn(resumed);
        auto_make_code(resumed);
        plan_ea(resumed);
        func_t *owner = get_func(instruction.ea);
        // The effective return can already belong to a small auto-created
        // function or range while still being outside the caller.  The
        // generic deobfuscator tests containment in the caller, not merely
        // whether some function owns the address; that distinction is what
        // lets chained gadgets become one traversable CFG.
        if ( owner != nullptr && !func_contains(owner, resumed) )
        {
          const bool appended = append_func_tail_ea(
              owner->start_ea, resumed, BADADDR);
          if ( !trace.empty() && trace[0] != '0' )
            msg("[chernobog][ida-analysis][get-pc-trace] resumed-tail owner=%a "
                "resumed=%a appended=%d\n", owner->start_ea, resumed,
                appended ? 1 : 0);
        }
        if ( gadget->return_instruction != classifier::k_bad_address )
        {
          // Queue the newly-proven continuation immediately. IDA may remove
          // this fallthrough while its first autoanalysis wave is still
          // classifying the return, so retain the deferred copy below too.
          // The deferred HS_FUNC_DONE-equivalent repair is authoritative.
          const ea_t return_ea = ea_t(gadget->return_instruction);
          if ( is_code(get_flags(return_ea))
            && get_item_end(return_ea) == resumed )
          {
            add_user_cref(return_ea, resumed, fl_F);
            auto_make_code(resumed);
            plan_ea(return_ea);
            plan_ea(resumed);
          }
          const auto edge = std::make_pair(return_ea, resumed);
          if ( std::find(pending_cfg_edges.begin(), pending_cfg_edges.end(), edge)
            == pending_cfg_edges.end() )
          {
            pending_cfg_edges.push_back(edge);
          }
        }
      }
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
    const ea_t selected = decision == BranchDecision::Taken
                        ? target : instruction.ea + instruction.size;
    const cref_t selected_type = decision == BranchDecision::Taken
                               ? fl_JN : fl_F;
    if ( !replace_generated_code_edges(
            instruction.ea,
            { desired_code_edge_t{
                selected, selected_type, selected_type != fl_F} }) )
    {
      return false;
    }
    auto_make_code(selected);
    plan_ea(selected);
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

    statistics.gaps_retyped += retype_gap_as_bytes(
        next.ea + next.size, target, config.maximum_gap, next.ea);
    if ( is_unknown(get_flags(target)) )
      create_insn(target);
    add_user_cref(instruction.ea, target, fl_JN, true, false);
    add_user_cref(instruction.ea, instruction.ea + instruction.size, fl_F);
    add_user_cref(next.ea, target, fl_JN, false, false);
    // Reinstall the first predicate's adjacent fallthrough after the processor
    // has finalized its own branch xrefs. fl_F cannot be made user-persistent,
    // and the paired-branch reclassification can otherwise leave the second
    // predicate as an orphan block.
    const auto fallthrough_edge = std::make_pair(
        instruction.ea, instruction.ea + instruction.size);
    if ( std::find(
            pending_cfg_edges.begin(), pending_cfg_edges.end(),
            fallthrough_edge) == pending_cfg_edges.end() )
    {
      pending_cfg_edges.push_back(fallthrough_edge);
    }
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
    const ea_t selected = decision == BranchDecision::Taken
                        ? target : fallthrough;
    const cref_t selected_type = decision == BranchDecision::Taken
                               ? fl_JN : fl_F;
    if ( !replace_generated_code_edges(
            instruction.ea,
            { desired_code_edge_t{
                selected, selected_type, selected_type != fl_F} }) )
    {
      return false;
    }
    if ( decision == BranchDecision::Taken )
    {
      statistics.gaps_retyped += retype_gap_as_bytes(
          fallthrough, target, config.maximum_gap, instruction.ea);
      if ( is_unknown(get_flags(target)) )
        create_insn(target);
    }
    else
      auto_make_code(fallthrough);
    plan_ea(selected);
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
      || !reg_value_address_compat(value, &target)
      || !target_is_executable(target) )
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
        fallthrough, target, config.maximum_gap, instruction.ea);
    if ( changed > 0 && is_unknown(get_flags(target)) )
      create_insn(target);
    statistics.gaps_retyped += changed;
    return changed != 0;
  }

  ssize_t handle_emulation(const insn_t &instruction)
  {
    const bool revisiting = emulated.contains(instruction.ea);
    if ( !revisiting )
      emulated.add(instruction.ea, instruction.ea + instruction.size);
    const bool call_pop = handle_call_pop(instruction, revisiting);
    if ( !call_pop && config.orphan_functions && is_call_insn(instruction)
      && direct_transfer(instruction) )
    {
      const ea_t target = branch_target(instruction);
      remember_direct_call_target(
          target, instruction.ea + instruction.size);
    }
    // Additive mutations must not claim ev_emu_insn: returning 1 suppresses
    // the processor module's normal emulation. Only handlers that installed a
    // complete exclusive edge set own the event.
    (void)handle_push_return(instruction);
    const bool zero_register = handle_zero_register(instruction);
    (void)handle_opposite_pair(instruction, revisiting);
    (void)handle_entry_predicate(instruction);
    const bool known_flag = handle_known_x86_flag(instruction, revisiting);
    (void)handle_indirect_branch(instruction);
    (void)handle_jump_gap(instruction, revisiting);
    return call_pop || zero_register || known_flag ? 1 : 0;
  }

  ssize_t idaapi on_event(ssize_t code, va_list arguments) override
  {
    if ( get_dbctx_id() != owner_database || !config.enabled )
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
        // The edge is installed from auto_empty_finally, after the original
        // traversal stopped at the return. Explicitly queue its continuation
        // so chained call/pop gadgets are discovered in the next bounded
        // autoanalysis wave instead of remaining unreachable until a manual
        // reanalysis.
        if ( is_unknown(get_flags(edge.second)) )
          create_insn(edge.second);
        auto_make_code(edge.second);
        plan_ea(edge.first);
        plan_ea(edge.second);
      }
    }
    pending_cfg_edges.clear();
  }

  size_t expand_get_pc_function_tails()
  {
    size_t appended_count = 0;
    size_t inspected = 0;
    bool limit_hit = false;
    std::set<ea_t> completed_roots;
    for ( ea_t root : get_pc_function_roots )
    {
      func_t *function = get_func(root);
      if ( function == nullptr || function->start_ea != root )
      {
        completed_roots.insert(root);
        continue;
      }

      std::vector<std::pair<ea_t, ea_t>> worklist;
      std::set<ea_t> queued;
      auto queue_noncall_successors = [&](ea_t source) {
        xrefblk_t xref;
        for ( bool ok = xref.first_from(source, XREF_CODE);
              ok; ok = xref.next_from() )
        {
          const int type = int(xref.type) & XREF_MASK;
          if ( type != fl_F && type != fl_JF && type != fl_JN )
            continue;
          if ( queued.insert(xref.to).second )
            worklist.emplace_back(source, xref.to);
        }
      };

      function_item_iterator_t item(root);
      for ( bool ok = item.first(); ok; ok = item.next_code() )
      {
        if ( ++inspected > config.maximum_post_scan_heads )
        {
          limit_hit = true;
          completed_roots.insert(root);
          break;
        }
        queue_noncall_successors(item.current());
      }
      if ( limit_hit )
        break;

      for ( size_t cursor = 0; cursor < worklist.size(); ++cursor )
      {
        if ( ++inspected > config.maximum_post_scan_heads )
        {
          limit_hit = true;
          completed_roots.insert(root);
          break;
        }
        const ea_t source = worklist[cursor].first;
        const ea_t target = worklist[cursor].second;
        func_t *owner = get_func(target);
        if ( owner != nullptr )
        {
          if ( owner->start_ea == root )
            queue_noncall_successors(target);
          continue;
        }
        const flags64_t flags = get_flags(target);
        if ( !is_code(flags) || !is_head(flags) || has_user_name(flags)
          || !target_is_proven_code_candidate(source, target) )
        {
          continue;
        }
        const ea_t end = get_item_end(target);
        if ( end == BADADDR || end <= target
          || !append_func_tail_ea(root, target, end) )
        {
          continue;
        }
        ++appended_count;
        queue_noncall_successors(target);
      }
      if ( limit_hit )
        break;
      completed_roots.insert(root);
    }
    for ( ea_t root : completed_roots )
      get_pc_function_roots.erase(root);
    statistics.post_scan_truncated |= limit_hit;
    statistics.get_pc_tail_extensions += appended_count;
    return appended_count;
  }

  size_t recover_orphan_functions(bool discover_database_targets)
  {
    if ( !config.orphan_functions )
      return 0;
    size_t scanned_heads = 0;
    bool limit_hit = false;
    if ( discover_database_targets )
    {
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
              remember_direct_call_target(
                  target, instruction.ea + instruction.size);
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
    }

    size_t promoted = 0;
    for ( auto iterator = observed_direct_call_targets.begin();
          iterator != observed_direct_call_targets.end(); )
    {
      const ea_t target = *iterator;
      func_t *owner = get_func(target);
      if ( owner != nullptr )
      {
        // A proper entry is resolved and can leave the candidate set. Retain
        // interior targets so a later IDA function-boundary correction can
        // make them eligible without another whole-database scan; do not split
        // the current owner automatically.
        if ( owner->start_ea == target )
          iterator = observed_direct_call_targets.erase(iterator);
        else
          ++iterator;
        continue;
      }
      if ( !target_is_executable(target) )
      {
        ++iterator;
        continue;
      }
      if ( is_unknown(get_flags(target)) )
      {
        insn_t decoded;
        if ( decode_insn(&decoded, target) <= 0 || create_insn(target) <= 0 )
        {
          ++iterator;
          continue;
        }
      }
      bool created = false;
      if ( add_func(target) )
      {
        created = true;
      }
      else
      {
        const ea_t end = bounded_function_end(
            target, config.orphan_scan_instructions);
        if ( end != BADADDR && get_func(target) == nullptr
          && add_func(target, end) )
        {
          created = true;
        }
      }
      if ( !created )
      {
        ++iterator;
        continue;
      }
      ++promoted;
      iterator = observed_direct_call_targets.erase(iterator);
    }
    statistics.orphan_functions += promoted;
    return promoted;
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
      // FUNC_OUTLINE changes decompiler structure. Require both independent
      // signals: an explicit Hikari wrapper name and the complete bounded
      // one-call forwarding shape. Neither a name nor a ubiquitous short
      // one-call function is sufficient alone.
      if ( !name_contains_hikari_wrapper(function->start_ea)
        || !wrapper_shape(function, config) )
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
    if ( get_dbctx_id() != owner_database
      || !config.enabled || post_analysis_running )
      return;
    post_analysis_running = true;
    fix_pending_cfg_edges();
    (void)expand_get_pc_function_tails();
    const bool initial_metadata_scan = !post_metadata_scanned;
    size_t promoted = 0;
    if ( !post_metadata_scanned )
    {
      // This is a bounded IDA decoder/xref metadata pass, not emulation.
      // Discover the baseline direct-call set once between per-database
      // resets. ev_emu_insn adds later call targets incrementally, so future
      // autoanalysis completions need not rescan the whole database.
      post_metadata_scanned = true;
      promoted = recover_orphan_functions(true);
    }
    else if ( !observed_direct_call_targets.empty() )
    {
      promoted = recover_orphan_functions(false);
    }
    if ( initial_metadata_scan || promoted > 0 )
    {
      outline_wrapper_functions();
      if ( statistics.post_scan_truncated )
      {
        msg("[chernobog][ida-analysis] post-analysis scan reached its "
            "configured bound (%zu heads, %zu functions)\n",
            statistics.post_scan_heads, statistics.post_scan_functions);
      }
    }
    if ( statistics.orphan_functions != reported_orphan_functions
      || statistics.outlined_wrappers != reported_outlined_wrappers
      || statistics.get_pc_tail_extensions
           != reported_get_pc_tail_extensions )
    {
      msg("[chernobog][ida-analysis] post-analysis: %zu get-PC tail "
          "extensions, %zu orphan functions, %zu outlined wrappers\n",
          statistics.get_pc_tail_extensions,
          statistics.orphan_functions, statistics.outlined_wrappers);
      reported_get_pc_tail_extensions = statistics.get_pc_tail_extensions;
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
