#include "early_hexrays.hpp"

#include "analysis_config.hpp"
#include "ida_sdk_compat.hpp"

#include "../common/warn_off.h"
#include <allins.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <hexrays.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <nalt.hpp>
#include <regfinder.hpp>
#include <segment.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include "../common/warn_on.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <utility>

namespace chernobog::ida_analysis {
namespace {

struct GadgetInfo
{
  int reg = -1;
  sval_t delta = 0;
  ea_t return_ea = BADADDR;
  bool pops_return = false;
  bool pushes_return = false;
  bool discards_return = false;
  bool has_return = false;
  bool has_control_transfer = false;
};

bool is_x86_database()
{
  return PH.id == PLFM_386;
}

bool is_return_instruction(const insn_t &instruction)
{
  return instruction.itype == NN_retn || instruction.itype == NN_retf;
}

bool executable_code(ea_t address)
{
  const segment_t *segment = getseg(address);
  return address != BADADDR && segment != nullptr
      // Older/packed inputs can leave segment permissions unspecified (0).
      && (segment->perm == 0 || (segment->perm & SEGPERM_EXEC) != 0)
      && is_mapped(address) && is_code(get_flags(address));
}

bool stack_pointer_deref(const op_t &operand)
{
  // IDA's x86 register enumeration uses id 4 for SP/ESP/RSP.
  return operand.reg == 4
      && (operand.type == o_phrase
       || (operand.type == o_displ && operand.addr == 0));
}

void update_register_delta(
    sval_t &delta,
    const insn_t &instruction,
    int tracked_register)
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
      if ( instruction.Op2.type == o_displ
        && instruction.Op2.reg == tracked_register )
      {
        delta += sval_t(instruction.Op2.addr);
      }
      break;
    default:
      break;
  }
}

bool classify_gadget_entry(
    const insn_t &instruction,
    GadgetInfo &result)
{
  if ( instruction.itype == NN_pop && instruction.Op1.type == o_reg )
  {
    result.reg = instruction.Op1.reg;
    result.pops_return = true;
    return true;
  }
  if ( instruction.itype == NN_mov && instruction.Op1.type == o_reg
    && stack_pointer_deref(instruction.Op2) )
  {
    result.reg = instruction.Op1.reg;
    return true;
  }
  if ( instruction.itype == NN_add
    && stack_pointer_deref(instruction.Op1)
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

bool analyze_get_pc_gadget(
    ea_t entry,
    int depth,
    GadgetInfo &result)
{
  result = GadgetInfo{};
  insn_t instruction;
  if ( decode_insn(&instruction, entry) <= 0
    || !classify_gadget_entry(instruction, result) )
  {
    return false;
  }

  const int tracked_register = result.reg;
  ea_t cursor = entry + instruction.size;
  bool saw_push = result.pushes_return;
  for ( int index = 0; index < depth; ++index )
  {
    if ( decode_insn(&instruction, cursor) <= 0 )
      break;
    if ( is_return_instruction(instruction) )
    {
      result.return_ea = cursor;
      result.pushes_return = saw_push;
      result.has_return = !saw_push;
      break;
    }

    const uint32 features = instruction.get_canon_feature(PH);
    if ( (features & CF_CALL) != 0 )
    {
      result.has_control_transfer = true;
      break;
    }
    if ( (features & CF_STOP) != 0 )
    {
      result.has_control_transfer = instruction.itype != NN_jmp;
      break;
    }
    if ( instruction.itype == NN_push && instruction.Op1.type == o_reg
      && instruction.Op1.reg == tracked_register )
    {
      saw_push = true;
      cursor += instruction.size;
      continue;
    }
    if ( instruction.Op1.type == o_reg
      && instruction.Op1.reg == tracked_register )
    {
      update_register_delta(result.delta, instruction, tracked_register);
    }
    cursor += instruction.size;
  }
  return true;
}

bool add_signed_delta(ea_t base, sval_t delta, ea_t &result)
{
  if ( delta >= 0 )
  {
    const uint64 amount = uint64(delta);
    if ( uint64(base) > uint64(BADADDR) - amount )
      return false;
    result = ea_t(uint64(base) + amount);
  }
  else
  {
    const uint64 amount = uint64(-(delta + 1)) + 1;
    if ( uint64(base) < amount )
      return false;
    result = ea_t(uint64(base) - amount);
  }
  return result != BADADDR;
}

bool is_marked_get_pc_call(ea_t address)
{
  insn_t instruction;
  if ( decode_insn(&instruction, address) <= 0
    || instruction.itype != NN_call || instruction.Op1.type != o_near )
  {
    return false;
  }
  xrefblk_t xref;
  for ( bool ok = xref.first_from(address, XREF_FLOW);
        ok; ok = xref.next_from() )
  {
    if ( (int(xref.type) & XREF_MASK) == fl_JN )
      return true;
  }
  return false;
}

// Resolve a push/return get-PC gadget only when all marked callers imply one
// target. Ambiguous shared gadgets remain indirect instead of inheriting an
// arbitrary xref iteration order.
ea_t resolve_gadget_return(ea_t return_ea, int scan_depth)
{
  if ( !is_x86_database() || !executable_code(return_ea) )
    return BADADDR;

  const segment_t *segment = getseg(return_ea);
  const func_t *function = get_func(return_ea);
  const ea_t lower_bound = function != nullptr
                         ? function->start_ea
                         : (segment != nullptr ? segment->start_ea : 0);
  ea_t cursor = return_ea;
  for ( int index = 0; index < scan_depth; ++index )
  {
    const ea_t previous = prev_head(cursor, lower_bound);
    if ( previous == BADADDR || previous >= cursor )
      break;
    cursor = previous;

    GadgetInfo gadget;
    if ( !analyze_get_pc_gadget(previous, scan_depth, gadget)
      || !gadget.pushes_return || gadget.has_control_transfer
      || gadget.return_ea != return_ea )
    {
      continue;
    }

    ea_t consensus = BADADDR;
    bool found = false;
    xrefblk_t xref;
    for ( bool ok = xref.first_to(previous, XREF_FLOW);
          ok; ok = xref.next_to() )
    {
      if ( (int(xref.type) & XREF_MASK) != fl_JN )
        continue;
      insn_t call;
      if ( decode_insn(&call, xref.from) <= 0
        || call.itype != NN_call || call.Op1.type != o_near
        || call.Op1.addr != previous )
      {
        continue;
      }
      ea_t target = BADADDR;
      if ( !add_signed_delta(call.ea + call.size, gadget.delta, target)
        || !executable_code(target) )
      {
        continue;
      }
      if ( found && target != consensus )
        return BADADDR;
      consensus = target;
      found = true;
    }
    if ( found )
      return consensus;
  }
  return BADADDR;
}

template <class Flowchart>
std::map<ea_t, int> index_blocks_by_start(const Flowchart &flowchart)
{
  std::map<ea_t, int> result;
  for ( size_t index = 0; index < flowchart.blocks.size(); ++index )
    result.emplace(flowchart.blocks[index].start_ea, int(index));
  return result;
}

template <class Flowchart>
int block_containing(
    const Flowchart &flowchart,
    const std::map<ea_t, int> &blocks_by_start,
    ea_t address)
{
  auto found = blocks_by_start.upper_bound(address);
  if ( found == blocks_by_start.begin() )
    return -1;
  --found;
  const qbasic_block_t &block = flowchart.blocks[found->second];
  if ( block.start_ea <= address && address < block.end_ea )
    return found->second;
  return -1;
}

bool contains_index(const intvec_t &indices, int value)
{
  return std::find(indices.begin(), indices.end(), value) != indices.end();
}

template <class Flowchart>
void propagate_reachability(const Flowchart &flowchart, bitset_t &reachable)
{
  qvector<int> worklist;
  for ( size_t index = 0; index < flowchart.blocks.size(); ++index )
  {
    if ( reachable.has(int(index)) )
      worklist.push_back(int(index));
  }
  for ( size_t cursor = 0; cursor < worklist.size(); ++cursor )
  {
    const int index = worklist[cursor];
    for ( int successor : flowchart.blocks[index].succ )
    {
      if ( successor >= 0
        && successor < int(flowchart.blocks.size())
        && !reachable.has(successor) )
      {
        reachable.add(successor);
        worklist.push_back(successor);
      }
    }
  }
}

template <class Flowchart>
int repair_flowchart(
    Flowchart &flowchart,
    bitset_t *reachable,
    const EarlyHexRaysConfig &config,
    bool &bounded)
{
  bounded = false;
  if ( !is_x86_database()
    || flowchart.blocks.size() > config.maximum_blocks )
  {
    bounded = flowchart.blocks.size() > config.maximum_blocks;
    return 0;
  }

  size_t scanned = 0;
  int changes = 0;
  const std::map<ea_t, int> blocks_by_start =
      index_blocks_by_start(flowchart);
  for ( size_t index = 0; index < flowchart.blocks.size(); ++index )
  {
    qbasic_block_t &block = flowchart.blocks[index];
    for ( ea_t address = block.start_ea;
          address != BADADDR && address < block.end_ea; )
    {
      if ( ++scanned > config.maximum_instructions )
      {
        bounded = true;
        if ( changes > 0 && reachable != nullptr )
          propagate_reachability(flowchart, *reachable);
        return changes;
      }

      insn_t call;
      if ( is_marked_get_pc_call(address)
        && decode_insn(&call, address) > 0 )
      {
        GadgetInfo gadget;
        if ( analyze_get_pc_gadget(
                call.Op1.addr, config.gadget_scan_depth, gadget)
          && gadget.pushes_return && !gadget.has_control_transfer )
        {
          ea_t target = BADADDR;
          if ( add_signed_delta(call.ea + call.size, gadget.delta, target) )
          {
            const int target_block = block_containing(
                flowchart, blocks_by_start, target);
            if ( target_block >= 0 && target_block != int(index)
              && !contains_index(block.succ, target_block) )
            {
              block.succ.push_back(target_block);
              qbasic_block_t &destination = flowchart.blocks[target_block];
              if ( !contains_index(destination.pred, int(index)) )
                destination.pred.push_back(int(index));
              if ( reachable != nullptr )
                reachable->add(target_block);
              ++changes;
            }
          }
        }
      }

      const ea_t next = next_head(address, block.end_ea);
      if ( next == BADADDR || next <= address )
        break;
      address = next;
    }
  }

  if ( changes > 0 && reachable != nullptr )
    propagate_reachability(flowchart, *reachable);
  return changes;
}

bool mba_within_bounds(
    const mba_t &mba,
    const EarlyHexRaysConfig &config)
{
  if ( mba.qty < 0 || size_t(mba.qty) > config.maximum_blocks )
    return false;
  size_t count = 0;
  for ( int index = 0; index < mba.qty; ++index )
  {
    const mblock_t *block = mba.get_mblock(index);
    for ( const minsn_t *instruction = block->head;
          instruction != nullptr; instruction = instruction->next )
    {
      if ( ++count > config.maximum_instructions )
        return false;
    }
  }
  return true;
}

void erase_predecessor(intvec_t &predecessors, int serial)
{
  for ( auto iterator = predecessors.begin();
        iterator != predecessors.end(); )
  {
    if ( *iterator == serial )
      iterator = predecessors.erase(iterator);
    else
      ++iterator;
  }
}

int convert_resolved_returns(
    mba_t &mba,
    const EarlyHexRaysConfig &config)
{
  if ( !is_x86_database() || !mba_within_bounds(mba, config) )
    return 0;

  std::map<ea_t, int> blocks_by_start;
  for ( int index = 0; index < mba.qty; ++index )
    blocks_by_start.emplace(mba.get_mblock(index)->start, index);

  int changes = 0;
  for ( int index = 0; index < mba.qty; ++index )
  {
    mblock_t *block = mba.get_mblock(index);
    if ( block->tail == nullptr
      || (block->tail->opcode != m_ijmp
       && block->tail->opcode != m_ret) )
    {
      continue;
    }
    const ea_t target = resolve_gadget_return(
        block->tail->ea, config.gadget_scan_depth);
    if ( target == BADADDR )
      continue;

    auto found = blocks_by_start.upper_bound(target);
    if ( found == blocks_by_start.begin() )
      continue;
    --found;
    const int target_block = found->second;
    const mblock_t *target_range = mba.get_mblock(target_block);
    if ( target < target_range->start || target >= target_range->end
      || target_block == index )
    {
      continue;
    }

    const intvec_t old_successors(block->succset);
    for ( int successor : old_successors )
    {
      if ( successor >= 0 && successor < mba.qty )
        erase_predecessor(mba.get_mblock(successor)->predset, index);
    }

    block->tail->opcode = m_goto;
    block->tail->l.make_blkref(target_block);
    block->tail->r.erase();
    block->tail->d.erase();
    block->succset.clear();
    block->succset.push_back(target_block);

    mblock_t *destination = mba.get_mblock(target_block);
    if ( !contains_index(destination->predset, index) )
      destination->predset.push_back(index);
    block->mark_lists_dirty();
    destination->mark_lists_dirty();
    ++changes;
  }
  if ( changes > 0 )
    mba.mark_chains_dirty();
  return changes;
}

} // namespace

namespace {

uint64 truncate_to_size(uint64 value, int size);

struct CharacterCandidate
{
  ea_t target = BADADDR;
  uint8 value = 0;
  ea_t operand_ea = BADADDR;
  int operand_number = -1;
};

ea_t instruction_write_target(ea_t instruction_ea)
{
  ea_t result = BADADDR;
  xrefblk_t xref;
  for ( bool ok = xref.first_from(instruction_ea, XREF_DATA);
        ok; ok = xref.next_from() )
  {
    if ( (int(xref.type) & XREF_MASK) != dr_W )
      continue;
    if ( result != BADADDR && result != xref.to )
      return BADADDR;
    result = xref.to;
  }
  if ( result != BADADDR )
    return result;

  insn_t native;
  if ( decode_insn(&native, instruction_ea) <= 0 )
    return BADADDR;
  const uint32 features = native.get_canon_feature(PH);
  for ( int index = 0; index < UA_MAXOP; ++index )
  {
    const op_t &operand = native.ops[index];
    if ( operand.type == o_void )
      break;
    if ( operand.type != o_displ && operand.type != o_phrase )
      continue;
    if ( (features & (CF_CHG1 << index)) == 0 )
      continue;

    qstring register_name;
    if ( get_reg_name(
            &register_name, operand.reg, inf_is_64bit() ? 8 : 4) <= 0 )
    {
      continue;
    }
    reg_value_info_t register_value;
    if ( !find_register_value_info_compat(
            &register_value, instruction_ea,
            register_name.c_str(), operand.reg, -1) )
    {
      continue;
    }
    ea_t base = BADADDR;
    if ( !reg_value_address_compat(register_value, &base) )
      continue;
    ea_t target = BADADDR;
    if ( !add_signed_delta(base, sval_t(operand.addr), target)
      || !is_mapped(target) )
    {
      return BADADDR;
    }
    return target;
  }
  return BADADDR;
}

const minsn_t *find_constant_register_definition(
    const minsn_t &before,
    mreg_t reg)
{
  for ( const minsn_t *instruction = before.prev;
        instruction != nullptr; instruction = instruction->prev )
  {
    if ( instruction->d.t != mop_r || instruction->d.r != reg )
      continue;
    if ( (instruction->opcode == m_ldc || instruction->opcode == m_mov)
      && instruction->l.t == mop_n && instruction->l.nnn != nullptr )
    {
      return instruction;
    }
    return nullptr;
  }
  return nullptr;
}

bool fold_store_source_with_regfinder(minsn_t &instruction)
{
  if ( instruction.l.t != mop_r || instruction.is_fpinsn() )
    return false;
  qstring register_name;
  if ( get_mreg_name(
          &register_name, instruction.l.r, instruction.l.size) <= 0 )
  {
    return false;
  }
  reg_value_info_t register_value;
  if ( !find_register_value_info_compat(
          &register_value, instruction.ea,
          register_name.c_str(), -1, -1) || !register_value.is_num() )
  {
    return false;
  }
  uint64 value = 0;
  if ( !register_value.get_num(&value) )
    return false;
  instruction.l.make_number(
      truncate_to_size(value, instruction.l.size),
      instruction.l.size, instruction.ea);
  return true;
}

const mnumber_t *resolve_store_source(
    minsn_t &instruction,
    bool &mutated)
{
  mutated = false;
  if ( instruction.l.t == mop_n )
    return instruction.l.nnn;
  if ( instruction.l.t != mop_r )
    return nullptr;
  const minsn_t *definition = find_constant_register_definition(
      instruction, instruction.l.r);
  if ( definition != nullptr )
    return definition->l.nnn;
  if ( fold_store_source_with_regfinder(instruction) )
  {
    mutated = true;
    return instruction.l.nnn;
  }
  return nullptr;
}

bool character_byte(uint8 value)
{
  return value == 0 || (value >= 0x20 && value <= 0x7E);
}

uint8 stored_byte(uint64 value, int size, int offset)
{
  const int scalar_index = inf_is_be() ? size - offset - 1 : offset;
  return uint8(value >> (8 * scalar_index));
}

bool safe_character_target(ea_t base, int size)
{
  ea_t last = BADADDR;
  if ( !add_signed_delta(base, size - 1, last)
    || !is_mapped(base) || !is_mapped(last) )
  {
    return false;
  }
  const segment_t *segment = getseg(base);
  if ( segment == nullptr || getseg(last) != segment )
    return false;
  for ( int offset = 0; offset < size; ++offset )
  {
    const ea_t address = base + offset;
    if ( !is_loaded(address) )
      return false;
    const flags64_t flags = get_flags(address);
    if ( is_strlit(flags) || has_user_name(flags) )
      return false;
  }
  return true;
}

bool collect_character_store(
    qvector<CharacterCandidate> &candidates,
    minsn_t &instruction)
{
  const int size = instruction.l.size;
  if ( instruction.opcode != m_stx
    || (size != 1 && size != 2 && size != 4 && size != 8) )
  {
    return false;
  }

  bool mutated = false;
  const mnumber_t *number = resolve_store_source(instruction, mutated);
  if ( number == nullptr )
    return mutated;
  const uint64 value = number->value;
  for ( int offset = 0; offset < size; ++offset )
  {
    if ( !character_byte(stored_byte(value, size, offset)) )
      return mutated;
  }

  const ea_t base = instruction_write_target(instruction.ea);
  if ( base == BADADDR || !safe_character_target(base, size) )
    return mutated;
  for ( int offset = 0; offset < size; ++offset )
  {
    CharacterCandidate candidate;
    candidate.target = base + offset;
    candidate.value = stored_byte(value, size, offset);
    candidate.operand_ea = number->ea;
    candidate.operand_number = number->opnum;
    candidates.push_back(candidate);
  }
  return mutated;
}

int mark_character_runs(
    mba_t &mba,
    qvector<CharacterCandidate> &candidates)
{
  if ( candidates.empty() )
    return 0;
  std::sort(
      candidates.begin(), candidates.end(),
      [](const CharacterCandidate &lhs, const CharacterCandidate &rhs)
      {
        if ( lhs.target != rhs.target )
          return lhs.target < rhs.target;
        if ( lhs.value != rhs.value )
          return lhs.value < rhs.value;
        if ( lhs.operand_ea != rhs.operand_ea )
          return lhs.operand_ea < rhs.operand_ea;
        return lhs.operand_number < rhs.operand_number;
      });

  // Reject addresses assigned conflicting bytes. Retain one representative
  // for repeated identical stores so branch duplication does not fragment a
  // contiguous run.
  qvector<CharacterCandidate> unique;
  std::map<ea_t, std::set<std::pair<ea_t, int>>> operand_keys;
  for ( size_t index = 0; index < candidates.size(); )
  {
    size_t end = index + 1;
    bool conflict = false;
    while ( end < candidates.size()
      && candidates[end].target == candidates[index].target )
    {
      if ( candidates[end].value != candidates[index].value )
        conflict = true;
      ++end;
    }
    if ( !conflict )
    {
      unique.push_back(candidates[index]);
      auto &keys = operand_keys[candidates[index].target];
      for ( size_t candidate = index; candidate < end; ++candidate )
      {
        if ( candidates[candidate].operand_ea != BADADDR
          && candidates[candidate].operand_number >= 0 )
        {
          keys.emplace(
              candidates[candidate].operand_ea,
              candidates[candidate].operand_number);
        }
      }
    }
    index = end;
  }
  if ( unique.empty() )
    return 0;

  user_numforms_t *formats = restore_user_numforms(mba.entry_ea);
  if ( formats == nullptr )
    formats = user_numforms_new();
  if ( formats == nullptr )
    return 0;

  int marked = 0;
  size_t begin = 0;
  while ( begin < unique.size() )
  {
    size_t end = begin;
    while ( end + 1 < unique.size()
      && unique[end + 1].target == unique[end].target + 1 )
    {
      ++end;
    }
    const size_t length = end - begin + 1;
    const bool nul_terminated = unique[end].value == 0;
    bool interior_nul = false;
    for ( size_t index = begin; index < end; ++index )
      interior_nul |= unique[index].value == 0;
    if ( !interior_nul
      && (length >= 4 || (nul_terminated && length >= 2)) )
    {
      std::set<std::pair<ea_t, int>> seen_operands;
      for ( size_t index = begin; index <= end; ++index )
      {
        const auto found_keys = operand_keys.find(unique[index].target);
        if ( found_keys == operand_keys.end() )
          continue;
        for ( const auto &key_pair : found_keys->second )
        {
          if ( !seen_operands.insert(key_pair).second )
            continue;
          const operand_locator_t key(key_pair.first, key_pair.second);
          if ( user_numforms_find(formats, key)
            != user_numforms_end(formats) )
          {
            continue; // preserve an existing user-selected representation
          }
          number_format_t format(key_pair.second);
          format.flags = char_flag();
          format.props = NF_FIXED;
#if IDA_SDK_VERSION >= 940
          mba.set_numform(key, format);
#endif
          user_numforms_insert(formats, key, format);
          ++marked;
        }
      }
    }
    begin = end + 1;
  }

  if ( marked > 0 )
    save_user_numforms(mba.entry_ea, formats);
  user_numforms_free(formats);
  return marked;
}

int force_character_strings(
    mba_t &mba,
    const EarlyHexRaysConfig &config)
{
  if ( !mba_within_bounds(mba, config) )
    return -1;
  qvector<CharacterCandidate> candidates;
  for ( int index = 0; index < mba.qty; ++index )
  {
    mblock_t *block = mba.get_mblock(index);
    bool dirty = false;
    for ( minsn_t *instruction = block->head;
          instruction != nullptr; instruction = instruction->next )
    {
      dirty = collect_character_store(candidates, *instruction) || dirty;
    }
    if ( dirty )
      block->mark_lists_dirty();
  }
  return mark_character_runs(mba, candidates);
}

} // namespace

namespace {

using SlotKey = std::pair<mreg_t, sval_t>;
using SlotMap = std::map<SlotKey, uint64>;

struct FoldContext
{
  const SlotMap &slots;
};

ea_t resolved_data_read(ea_t instruction_ea)
{
  ea_t result = BADADDR;
  xrefblk_t xref;
  for ( bool ok = xref.first_from(instruction_ea, XREF_DATA);
        ok; ok = xref.next_from() )
  {
    if ( (int(xref.type) & XREF_MASK) != dr_R )
      continue;
    if ( result != BADADDR && result != xref.to )
      return BADADDR;
    result = xref.to;
  }
  return result;
}

bool read_constant_memory(ea_t address, int size, uint64 &value)
{
  if ( size != 1 && size != 2 && size != 4 && size != 8 )
    return false;
  ea_t last = BADADDR;
  if ( !add_signed_delta(address, size - 1, last)
    || !is_mapped(address) || !is_mapped(last) )
  {
    return false;
  }
  const segment_t *first_segment = getseg(address);
  if ( first_segment == nullptr || getseg(last) != first_segment )
    return false;

  for ( int offset = 0; offset < size; ++offset )
  {
    const ea_t current = address + offset;
    if ( !is_loaded(current) )
      return false;
    xrefblk_t xref;
    for ( bool ok = xref.first_to(current, XREF_DATA);
          ok; ok = xref.next_to() )
    {
      if ( !xref.iscode && (int(xref.type) & XREF_MASK) == dr_W )
        return false;
    }
  }

  switch ( size )
  {
    case 1:
      value = get_byte(address);
      return true;
    case 2:
      value = get_word(address);
      return true;
    case 4:
      value = get_dword(address);
      return true;
    case 8:
      value = get_qword(address);
      return true;
    default:
      return false;
  }
}

bool evaluate_binary(mcode_t opcode, uint64 lhs, uint64 rhs, uint64 &value)
{
  switch ( opcode )
  {
    case m_xor:
      value = lhs ^ rhs;
      return true;
    case m_or:
      value = lhs | rhs;
      return true;
    case m_and:
      value = lhs & rhs;
      return true;
    case m_add:
      value = lhs + rhs;
      return true;
    case m_sub:
      value = lhs - rhs;
      return true;
    case m_mul:
      value = lhs * rhs;
      return true;
    default:
      return false;
  }
}

const minsn_t *find_local_definition(
    const minsn_t *before,
    mreg_t reg)
{
  for ( const minsn_t *instruction = before->prev;
        instruction != nullptr; instruction = instruction->prev )
  {
    if ( instruction->d.t == mop_r && instruction->d.r == reg )
      return instruction;
  }
  return nullptr;
}

bool stable_frame_base(mreg_t reg)
{
  static constexpr const char *names[] =
  {
    "rsp", "rbp", "esp", "ebp", "SP", "X29",
  };
  for ( const char *name : names )
  {
    const int processor_reg = str2reg(name);
    if ( processor_reg >= 0 && reg2mreg(processor_reg) == reg )
      return true;
  }
  return false;
}

bool extract_slot_key(const mop_t &memory, SlotKey &key)
{
  if ( memory.t == mop_r )
  {
    key = { memory.r, 0 };
    return true;
  }
  if ( memory.t != mop_d || memory.d == nullptr )
    return false;
  const minsn_t &inner = *memory.d;
  if ( inner.opcode != m_add && inner.opcode != m_sub )
    return false;

  uint64 immediate = 0;
  if ( inner.l.t == mop_r && inner.r.is_constant(&immediate, false) )
  {
    key = {
      inner.l.r,
      inner.opcode == m_sub ? -sval_t(immediate) : sval_t(immediate),
    };
    return true;
  }
  if ( inner.opcode == m_add
    && inner.l.is_constant(&immediate, false) && inner.r.t == mop_r )
  {
    key = { inner.r.r, sval_t(immediate) };
    return true;
  }
  return false;
}

uint64 truncate_to_size(uint64 value, int size)
{
  if ( size <= 0 || size >= 8 )
    return value;
  return value & ((uint64(1) << (size * 8)) - 1);
}

bool resolve_instruction_result(
    const FoldContext &context,
    const minsn_t *instruction,
    uint64 &value,
    int depth);

bool resolve_constant_operand(
    const FoldContext &context,
    const minsn_t *current,
    const mop_t &operand,
    uint64 &value,
    int depth)
{
  if ( depth > 64 )
    return false;
  if ( operand.is_constant(&value, false) )
    return true;
  if ( operand.t == mop_r )
  {
    const minsn_t *definition = find_local_definition(current, operand.r);
    return definition != nullptr
        && resolve_instruction_result(
            context, definition, value, depth + 1);
  }
  if ( operand.t == mop_d && operand.d != nullptr )
  {
    return resolve_instruction_result(
        context, operand.d, value, depth + 1);
  }
  return false;
}

uint64 sign_extend_value(uint64 value, int source_bits)
{
  if ( source_bits <= 0 || source_bits >= 64 )
    return value;
  const uint64 sign = uint64(1) << (source_bits - 1);
  const uint64 mask = (uint64(1) << source_bits) - 1;
  value &= mask;
  return (value ^ sign) - sign;
}

bool evaluate_unary(
    mcode_t opcode,
    uint64 operand,
    int source_bits,
    uint64 &value)
{
  switch ( opcode )
  {
    case m_ldc:
    case m_mov:
    case m_xdu:
    case m_low:
      value = operand;
      return true;
    case m_xds:
      value = sign_extend_value(operand, source_bits);
      return true;
    case m_bnot:
      value = ~operand;
      return true;
    case m_neg:
      value = uint64(0) - operand;
      return true;
    case m_lnot:
      value = operand == 0 ? 1 : 0;
      return true;
    default:
      return false;
  }
}

bool resolve_load_result(
    const FoldContext &context,
    const minsn_t *instruction,
    uint64 &value,
    int depth)
{
  const int size = instruction->d.size;
  const ea_t xref_address = resolved_data_read(instruction->ea);
  if ( xref_address != BADADDR )
    return read_constant_memory(xref_address, size, value);

  SlotKey key;
  if ( extract_slot_key(instruction->r, key) )
  {
    if ( stable_frame_base(key.first) )
    {
      const auto found = context.slots.find(key);
      if ( found != context.slots.end() )
      {
        value = found->second;
        return true;
      }
    }

    const minsn_t *definition = find_local_definition(
        instruction, key.first);
    uint64 base = 0;
    ea_t address = BADADDR;
    if ( definition != nullptr
      && resolve_instruction_result(
          context, definition, base, depth + 1)
      && add_signed_delta(ea_t(base), key.second, address) )
    {
      return read_constant_memory(address, size, value);
    }
  }

  uint64 address = 0;
  if ( !resolve_constant_operand(
          context, instruction, instruction->r, address, depth + 1) )
  {
    return false;
  }
  return read_constant_memory(ea_t(address), size, value);
}

bool resolve_instruction_result(
    const FoldContext &context,
    const minsn_t *instruction,
    uint64 &value,
    int depth)
{
  if ( instruction == nullptr || depth > 64 )
    return false;
  if ( instruction->opcode == m_ldx )
    return resolve_load_result(context, instruction, value, depth + 1);

  uint64 lhs = 0;
  if ( !resolve_constant_operand(
          context, instruction, instruction->l, lhs, depth + 1) )
  {
    return false;
  }
  if ( evaluate_unary(
          instruction->opcode, lhs, 8 * instruction->l.size, value) )
  {
    value = truncate_to_size(value, instruction->d.size);
    return true;
  }

  uint64 rhs = 0;
  if ( !resolve_constant_operand(
          context, instruction, instruction->r, rhs, depth + 1)
    || !evaluate_binary(instruction->opcode, lhs, rhs, value) )
  {
    return false;
  }
  value = truncate_to_size(value, instruction->d.size);
  return true;
}

void build_stable_slot_map(mba_t &mba, SlotMap &slots)
{
  static const SlotMap empty_slots;
  const FoldContext bootstrap{ empty_slots };
  std::set<SlotKey> invalid;
  if ( mba.qty <= 0 )
    return;

  // Admit a stack/frame slot only after a constant store in the entry block.
  // That store dominates every reachable successor; loads preceding it in the
  // entry block invalidate the slot. A same-valued later store is harmless,
  // while an unresolved or differing store invalidates the candidate. This is
  // stricter than a function-wide "all observed constants agree" map, which
  // can incorrectly fold a load on a path that bypasses the first store.
  const mblock_t *entry = mba.get_mblock(0);
  for ( const minsn_t *instruction = entry->head;
        instruction != nullptr; instruction = instruction->next )
  {
    SlotKey key;
    if ( instruction->opcode == m_ldx
      && extract_slot_key(instruction->r, key)
      && stable_frame_base(key.first) && slots.count(key) == 0 )
    {
      invalid.insert(key);
      continue;
    }
    if ( instruction->opcode != m_stx
      || !extract_slot_key(instruction->d, key)
      || !stable_frame_base(key.first) )
    {
      continue;
    }
    uint64 value = 0;
    if ( !resolve_constant_operand(
            bootstrap, instruction, instruction->l, value, 0) )
    {
      slots.erase(key);
      invalid.insert(key);
      continue;
    }
    value = truncate_to_size(value, instruction->l.size);
    const auto found = slots.find(key);
    if ( invalid.count(key) != 0 )
      continue;
    if ( found == slots.end() )
      slots.emplace(key, value);
    else if ( found->second != value )
    {
      slots.erase(found);
      invalid.insert(key);
    }
  }

  for ( int index = 1; index < mba.qty; ++index )
  {
    const mblock_t *block = mba.get_mblock(index);
    for ( const minsn_t *instruction = block->head;
          instruction != nullptr; instruction = instruction->next )
    {
      if ( instruction->opcode != m_stx )
        continue;
      SlotKey key;
      if ( !extract_slot_key(instruction->d, key)
        || !stable_frame_base(key.first) )
      {
        continue;
      }
      uint64 value = 0;
      if ( !resolve_constant_operand(
              bootstrap, instruction, instruction->l, value, 0) )
      {
        slots.erase(key);
        invalid.insert(key);
        continue;
      }
      value = truncate_to_size(value, instruction->l.size);
      const auto found = slots.find(key);
      if ( found == slots.end() || found->second != value )
      {
        if ( found != slots.end() )
          slots.erase(found);
        invalid.insert(key);
      }
    }
  }
  for ( const SlotKey &key : invalid )
    slots.erase(key);
}

bool flatten_operand(
    const FoldContext &context,
    minsn_t *current,
    mop_t &operand)
{
  if ( operand.t == mop_n )
    return false;
  uint64 value = 0;
  if ( operand.size > 0 && operand.size <= 8
    && resolve_constant_operand(context, current, operand, value, 0) )
  {
    if ( is_mcode_shift(current->opcode) && &operand == &current->r )
    {
      if ( current->l.size <= 0 )
        return false;
      const uint64 maximum = uint64(8 * current->l.size - 1);
      if ( value > maximum )
        return false;
    }
    operand.make_number(
        truncate_to_size(value, operand.size), operand.size, current->ea);
    return true;
  }
  if ( operand.t != mop_d || operand.d == nullptr )
    return false;
  minsn_t *inner = operand.d;
  bool changed = flatten_operand(context, inner, inner->l);
  if ( inner->r.t != mop_z )
    changed = flatten_operand(context, inner, inner->r) || changed;
  return changed;
}

bool fold_instruction(
    const FoldContext &context,
    minsn_t *instruction)
{
  const int size = instruction->d.size;
  if ( (size != 1 && size != 2 && size != 4 && size != 8)
    || instruction->opcode == m_mov || instruction->opcode == m_ldc )
  {
    return false;
  }
  uint64 value = 0;
  if ( !resolve_instruction_result(context, instruction, value, 0) )
    return false;
  instruction->opcode = m_mov;
  instruction->l.make_number(
      truncate_to_size(value, size), size, instruction->ea);
  instruction->r.erase();
  return true;
}

int fold_constants(mba_t &mba, const EarlyHexRaysConfig &config)
{
  if ( !mba_within_bounds(mba, config) )
    return -1;
  SlotMap slots;
  build_stable_slot_map(mba, slots);
  const FoldContext context{ slots };
  int changes = 0;
  for ( int index = 0; index < mba.qty; ++index )
  {
    mblock_t *block = mba.get_mblock(index);
    bool dirty = false;
    for ( minsn_t *instruction = block->head;
          instruction != nullptr; instruction = instruction->next )
    {
      bool changed = flatten_operand(
          context, instruction, instruction->l);
      if ( instruction->r.t != mop_z )
      {
        changed = flatten_operand(
            context, instruction, instruction->r) || changed;
      }
      changed = fold_instruction(context, instruction) || changed;
      if ( changed )
      {
        ++changes;
        dirty = true;
      }
    }
    if ( dirty )
      block->mark_lists_dirty();
  }
  return changes;
}

} // namespace

struct EarlyHexRaysAnalysis::Impl final : microcode_filter_t
{
  EarlyHexRaysConfig config = load_early_hexrays_config();
  EarlyHexRaysStats statistics;
  bool installed = false;

  bool match(codegen_t &codegen) override
  {
    return config.enabled && config.call_pop_codegen
        && is_x86_database()
        && is_return_instruction(codegen.insn)
        && resolve_gadget_return(
            codegen.insn.ea, config.gadget_scan_depth) != BADADDR;
  }

  merror_t apply(codegen_t &codegen) override
  {
    const ea_t target = resolve_gadget_return(
        codegen.insn.ea, config.gadget_scan_depth);
    if ( target == BADADDR )
      return MERR_INSN;

    // Re-present the native return as a direct jump to Hex-Rays' standard
    // microcode generator. This happens before an MBA exists.
    codegen.insn.itype = NN_jmp;
    codegen.insn.Op1.type = o_near;
    codegen.insn.Op1.addr = target;
    codegen.insn.Op1.dtype = dt_code;
    for ( int index = 1; index < UA_MAXOP; ++index )
      codegen.insn.ops[index].type = o_void;
    ++statistics.codegen_returns;
    return MERR_INSN;
  }

  bool install_filter()
  {
    if ( installed || !config.enabled || !config.call_pop_codegen )
      return true;
    installed = install_microcode_filter(this, true);
    return installed;
  }

  void uninstall_filter(bool dispatcher_available)
  {
    if ( !installed )
      return;
    if ( dispatcher_available && get_hexdsp() != nullptr )
      install_microcode_filter(this, false);
    installed = false;
  }

  template <class Flowchart>
  int flowchart(const Flowchart *input, bitset_t *reachable)
  {
    if ( !config.enabled || !config.call_pop_flowchart || input == nullptr )
      return 0;
    bool bounded = false;
    Flowchart *mutable_flowchart = const_cast<Flowchart *>(input);
    const int changes = repair_flowchart(
        *mutable_flowchart, reachable, config, bounded);
    statistics.flowchart_edges += size_t(changes);
    if ( bounded )
      ++statistics.bounded_skips;
    return changes;
  }

  int microcode(mba_t *mba)
  {
    if ( !config.enabled || !config.generated_gotos || mba == nullptr )
      return 0;
    if ( !mba_within_bounds(*mba, config) )
    {
      ++statistics.bounded_skips;
      return 0;
    }
    const int changes = convert_resolved_returns(*mba, config);
    statistics.generated_gotos += size_t(changes);
    return changes;
  }

  int preoptimized(mba_t *mba)
  {
    if ( !config.enabled || mba == nullptr )
      return 0;
    if ( !mba_within_bounds(*mba, config) )
    {
      ++statistics.bounded_skips;
      return 0;
    }

    int total = 0;
    if ( config.constant_folding )
    {
      const int changes = fold_constants(*mba, config);
      if ( changes > 0 )
      {
        statistics.folded_instructions += size_t(changes);
        total += changes;
      }
    }
    if ( config.force_char_strings )
    {
      const int changes = force_character_strings(*mba, config);
      if ( changes > 0 )
      {
        statistics.character_operands += size_t(changes);
        total += changes;
      }
    }
    return total;
  }
};

EarlyHexRaysAnalysis::EarlyHexRaysAnalysis()
  : impl_(new Impl)
{
}

EarlyHexRaysAnalysis::~EarlyHexRaysAnalysis()
{
  uninstall(get_hexdsp() != nullptr);
}

bool EarlyHexRaysAnalysis::install()
{
  return impl_ != nullptr && impl_->install_filter();
}

void EarlyHexRaysAnalysis::uninstall(bool dispatcher_available)
{
  if ( impl_ != nullptr )
    impl_->uninstall_filter(dispatcher_available);
}

bool EarlyHexRaysAnalysis::enabled() const
{
  return impl_ != nullptr && impl_->config.enabled;
}

void EarlyHexRaysAnalysis::reset()
{
  if ( impl_ != nullptr )
    impl_->statistics = EarlyHexRaysStats{};
}

int EarlyHexRaysAnalysis::on_flowchart(
    const qflow_chart_t *flowchart,
    bitset_t *reachable)
{
  return impl_ != nullptr ? impl_->flowchart(flowchart, reachable) : 0;
}

#if IDA_SDK_VERSION >= 940
int EarlyHexRaysAnalysis::on_flowchart(
    const qflow_chart_ea_t *flowchart,
    bitset_t *reachable)
{
  return impl_ != nullptr ? impl_->flowchart(flowchart, reachable) : 0;
}
#endif

int EarlyHexRaysAnalysis::on_microcode(mba_t *mba)
{
  return impl_ != nullptr ? impl_->microcode(mba) : 0;
}

int EarlyHexRaysAnalysis::on_preoptimized(mba_t *mba)
{
  return impl_ != nullptr ? impl_->preoptimized(mba) : 0;
}

const EarlyHexRaysStats &EarlyHexRaysAnalysis::stats() const
{
  static const EarlyHexRaysStats empty;
  return impl_ != nullptr ? impl_->statistics : empty;
}

} // namespace chernobog::ida_analysis
