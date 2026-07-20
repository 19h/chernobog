#include "early_hexrays.hpp"

#include "analysis_config.hpp"
#include "get_pc_ida.hpp"
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
#include <segment.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include "../common/warn_on.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <utility>

namespace chernobog::ida_analysis {
namespace {

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
      const auto candidate = classify_ida_get_pc_call(
          call, size_t(scan_depth), false);
      if ( !candidate || !candidate->resumed_at.has_value()
        || candidate->return_instruction != uint64_t(return_ea) )
      {
        continue;
      }
      const ea_t target = ea_t(*candidate->resumed_at);
      if ( !executable_code(target) )
        continue;
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
        const auto gadget = classify_ida_get_pc_call(
            call, size_t(config.gadget_scan_depth), false);
        if ( gadget && gadget->resumed_at.has_value()
          && gadget->return_instruction != classifier::k_bad_address )
        {
          const ea_t target = ea_t(*gadget->resumed_at);
          const auto exact_target = blocks_by_start.find(target);
          const int return_block = block_containing(
              flowchart, blocks_by_start, ea_t(gadget->return_instruction));
          if ( exact_target != blocks_by_start.end() && return_block >= 0 )
          {
            const int target_block = exact_target->second;
            qbasic_block_t &source = flowchart.blocks[return_block];
            if ( target_block != return_block
              && !contains_index(source.succ, target_block) )
            {
              source.succ.push_back(target_block);
              qbasic_block_t &destination = flowchart.blocks[target_block];
              if ( !contains_index(destination.pred, return_block) )
                destination.pred.push_back(return_block);
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

struct RegisterKey
{
  mreg_t start = mr_none;
  int size = 0;

  bool operator<(const RegisterKey &other) const
  {
    return start < other.start
        || (start == other.start && size < other.size);
  }
};

struct SlotAddress
{
  mreg_t base = mr_none;
  sval_t offset = 0;
};

struct SlotKey
{
  mreg_t base = mr_none;
  sval_t offset = 0;
  int size = 0;

  bool operator<(const SlotKey &other) const
  {
    if ( base != other.base )
      return base < other.base;
    if ( offset != other.offset )
      return offset < other.offset;
    return size < other.size;
  }
};

struct ConstantValue
{
  uint64 value = 0;
  ea_t operand_ea = BADADDR;
  int operand_number = -1;
};

struct ForwardState
{
  std::map<RegisterKey, ConstantValue> registers;
  std::map<SlotKey, ConstantValue> slots;
  std::optional<mreg_t> slot_base;
};

constexpr size_t maximum_forward_register_constants = 256;

struct ForwardEffect
{
  mlist_t definitions;
  std::optional<RegisterKey> result_register;
  std::optional<ConstantValue> result;
  std::optional<SlotKey> stored_slot;
  std::optional<ConstantValue> stored_value;
  bool call = false;
  bool writes_memory = false;
};

bool evaluate_forward_operand(
    const ForwardState &state,
    const minsn_t *current,
    const mop_t &operand,
    ConstantValue &value,
    int depth = 0);

ForwardEffect analyze_forward_effect(
    const mblock_t &block,
    const minsn_t &instruction,
    const ForwardState &state);

void apply_forward_effect(
    ForwardState &state,
    const ForwardEffect &effect);

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
  return result;
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

void collect_character_store(
    qvector<CharacterCandidate> &candidates,
    const minsn_t &instruction,
    const ForwardState &state)
{
  const int size = instruction.l.size;
  if ( instruction.opcode != m_stx
    || (size != 1 && size != 2 && size != 4 && size != 8) )
  {
    return;
  }

  ConstantValue source;
  if ( !evaluate_forward_operand(
          state, &instruction, instruction.l, source)
    || source.operand_ea == BADADDR || source.operand_number < 0 )
  {
    return;
  }
  const uint64 value = truncate_to_size(source.value, size);
  for ( int offset = 0; offset < size; ++offset )
  {
    if ( !character_byte(stored_byte(value, size, offset)) )
      return;
  }

  const ea_t base = instruction_write_target(instruction.ea);
  if ( base == BADADDR || !safe_character_target(base, size) )
    return;
  for ( int offset = 0; offset < size; ++offset )
  {
    CharacterCandidate candidate;
    candidate.target = base + offset;
    candidate.value = stored_byte(value, size, offset);
    candidate.operand_ea = source.operand_ea;
    candidate.operand_number = source.operand_number;
    candidates.push_back(candidate);
  }
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
    ForwardState state;
    for ( minsn_t *instruction = block->head;
          instruction != nullptr; instruction = instruction->next )
    {
      collect_character_store(candidates, *instruction, state);
      const ForwardEffect effect = analyze_forward_effect(
          *block, *instruction, state);
      apply_forward_effect(state, effect);
    }
  }
  return mark_character_runs(mba, candidates);
}

} // namespace

namespace {

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
  if ( first_segment == nullptr || getseg(last) != first_segment
    || first_segment->type == SEG_XTRN )
  {
    return false;
  }

  for ( int offset = 0; offset < size; ++offset )
  {
    const ea_t current = address + offset;
    if ( !is_loaded(current) )
      return false;
    xrefblk_t xref;
    for ( bool ok = xref.first_to(current, XREF_DATA);
          ok; ok = xref.next_to() )
    {
      if ( (int(xref.type) & XREF_MASK) == dr_W )
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
    case m_shl:
      if ( rhs >= 64 )
        return false;
      value = lhs << rhs;
      return true;
    case m_shr:
      if ( rhs >= 64 )
        return false;
      value = lhs >> rhs;
      return true;
    default:
      return false;
  }
}

bool valid_scalar_size(int size)
{
  return size == 1 || size == 2 || size == 4 || size == 8;
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

bool extract_slot_address(const mop_t &memory, SlotAddress &address)
{
  if ( memory.t == mop_r )
  {
    address = { memory.r, 0 };
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
    address = {
      inner.l.r,
      inner.opcode == m_sub ? -sval_t(immediate) : sval_t(immediate),
    };
    return true;
  }
  if ( inner.opcode == m_add
    && inner.l.is_constant(&immediate, false) && inner.r.t == mop_r )
  {
    address = { inner.r.r, sval_t(immediate) };
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

bool register_ranges_overlap(const RegisterKey &left, const RegisterKey &right)
{
  if ( left.size <= 0 || right.size <= 0 )
    return true;
  const int64 left_start = int64(left.start);
  const int64 right_start = int64(right.start);
  return left_start < right_start + int64(right.size)
      && right_start < left_start + int64(left.size);
}

bool register_list_overlaps(const rlist_t &list, const RegisterKey &key)
{
  if ( key.start == mr_none || key.size <= 0 )
    return true;
  for ( int offset = 0; offset < key.size; ++offset )
  {
    if ( list.has(key.start + offset) )
      return true;
  }
  return false;
}

bool slot_ranges_overlap(const SlotKey &left, const SlotKey &right)
{
  if ( left.base != right.base )
    return false;
  if ( left.size <= 0 || right.size <= 0 )
    return true;
  const sval_t maximum = std::numeric_limits<sval_t>::max();
  if ( left.offset > maximum - (left.size - 1)
    || right.offset > maximum - (right.size - 1) )
  {
    return true;
  }
  const sval_t left_last = left.offset + left.size - 1;
  const sval_t right_last = right.offset + right.size - 1;
  return left.offset <= right_last && right.offset <= left_last;
}

bool slot_base_is_defined(const rlist_t &definitions, mreg_t base)
{
  const int pointer_size = inf_is_64bit() ? 8 : 4;
  return register_list_overlaps(
      definitions, RegisterKey{ base, pointer_size });
}

void erase_register_range(
    std::map<RegisterKey, ConstantValue> &registers,
    const RegisterKey &range)
{
  auto iterator = registers.lower_bound(RegisterKey{ range.start, 0 });
  if ( iterator != registers.begin() )
  {
    auto previous = iterator;
    --previous;
    if ( register_ranges_overlap(previous->first, range) )
      registers.erase(previous);
  }
  const int64 end = int64(range.start) + int64(std::max(range.size, 1));
  while ( iterator != registers.end()
    && int64(iterator->first.start) < end )
  {
    if ( register_ranges_overlap(iterator->first, range) )
      iterator = registers.erase(iterator);
    else
      ++iterator;
  }
}

void erase_overlapping_slots(
    std::map<SlotKey, ConstantValue> &slots,
    const SlotKey &range)
{
  auto iterator = slots.lower_bound(
      SlotKey{ range.base, range.offset, 0 });
  if ( iterator != slots.begin() )
  {
    auto previous = iterator;
    --previous;
    if ( slot_ranges_overlap(previous->first, range) )
      slots.erase(previous);
  }
  const sval_t maximum = std::numeric_limits<sval_t>::max();
  const sval_t last = range.offset > maximum - (range.size - 1)
                    ? maximum : range.offset + range.size - 1;
  while ( iterator != slots.end()
    && iterator->first.base == range.base
    && iterator->first.offset <= last )
  {
    if ( slot_ranges_overlap(iterator->first, range) )
      iterator = slots.erase(iterator);
    else
      ++iterator;
  }
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

bool evaluate_forward_instruction(
    const ForwardState &state,
    const minsn_t *instruction,
    ConstantValue &value,
    int depth)
{
  if ( instruction == nullptr || depth > 16 || instruction->is_fpinsn() )
    return false;

  if ( instruction->opcode != m_ldx )
  {
    ConstantValue lhs;
    if ( !evaluate_forward_operand(
            state, instruction, instruction->l, lhs, depth + 1) )
    {
      return false;
    }
    uint64 result = 0;
    if ( evaluate_unary(
            instruction->opcode, lhs.value,
            8 * instruction->l.size, result) )
    {
      value.value = truncate_to_size(result, instruction->d.size);
      if ( instruction->opcode == m_ldc || instruction->opcode == m_mov )
      {
        value.operand_ea = lhs.operand_ea;
        value.operand_number = lhs.operand_number;
      }
      return true;
    }

    ConstantValue rhs;
    if ( !evaluate_forward_operand(
            state, instruction, instruction->r, rhs, depth + 1)
      || !evaluate_binary(
            instruction->opcode, lhs.value, rhs.value, result) )
    {
      return false;
    }
    if ( is_mcode_shift(instruction->opcode) )
    {
      if ( instruction->l.size <= 0
        || rhs.value > uint64(8 * instruction->l.size - 1) )
      {
        return false;
      }
    }
    value.value = truncate_to_size(result, instruction->d.size);
    return true;
  }

  const int size = instruction->d.size;
  if ( !valid_scalar_size(size) )
    return false;

  const ea_t xref_address = resolved_data_read(instruction->ea);
  if ( xref_address != BADADDR )
    return read_constant_memory(xref_address, size, value.value);

  SlotAddress slot_address;
  if ( extract_slot_address(instruction->r, slot_address)
    && stable_frame_base(slot_address.base) )
  {
    const SlotKey key{ slot_address.base, slot_address.offset, size };
    const auto found = state.slots.find(key);
    if ( found != state.slots.end() )
    {
      value = found->second;
      value.value = truncate_to_size(value.value, size);
      return true;
    }
  }

  ConstantValue address_value;
  if ( !evaluate_forward_operand(
          state, instruction, instruction->r,
          address_value, depth + 1) )
  {
    return false;
  }
  return read_constant_memory(ea_t(address_value.value), size, value.value);
}

bool evaluate_forward_operand(
    const ForwardState &state,
    const minsn_t *current,
    const mop_t &operand,
    ConstantValue &value,
    int depth)
{
  if ( current == nullptr || depth > 16 )
    return false;
  if ( operand.t == mop_n && operand.nnn != nullptr )
  {
    value.value = truncate_to_size(operand.nnn->value, operand.size);
    value.operand_ea = operand.nnn->ea;
    value.operand_number = operand.nnn->opnum;
    return true;
  }
  if ( operand.t == mop_r && operand.size > 0 )
  {
    const auto found = state.registers.find(
        RegisterKey{ operand.r, operand.size });
    if ( found == state.registers.end() )
      return false;
    value = found->second;
    value.value = truncate_to_size(value.value, operand.size);
    return true;
  }
  if ( operand.t == mop_d && operand.d != nullptr )
  {
    return evaluate_forward_instruction(
        state, operand.d, value, depth + 1);
  }
  return false;
}

ForwardEffect analyze_forward_effect(
    const mblock_t &block,
    const minsn_t &instruction,
    const ForwardState &state)
{
  ForwardEffect effect;
  effect.call = is_mcode_call(instruction.opcode);
  effect.definitions = block.build_def_list(
      instruction,
      MAY_ACCESS | INCLUDE_SPOILED_REGS | INCLUDE_DEAD_RETREGS);
  effect.writes_memory = !effect.definitions.mem.empty();

  if ( instruction.modifies_d()
    && instruction.d.t == mop_r && instruction.d.size > 0 )
  {
    effect.result_register = RegisterKey{
      instruction.d.r, instruction.d.size,
    };
    ConstantValue result;
    if ( valid_scalar_size(instruction.d.size)
      && evaluate_forward_instruction(state, &instruction, result, 0) )
    {
      effect.result = result;
    }
  }

  if ( instruction.opcode == m_stx
    && valid_scalar_size(instruction.l.size) )
  {
    SlotAddress address;
    if ( extract_slot_address(instruction.d, address)
      && stable_frame_base(address.base) )
    {
      effect.stored_slot = SlotKey{
        address.base, address.offset, instruction.l.size,
      };
      ConstantValue stored;
      if ( evaluate_forward_operand(
              state, &instruction, instruction.l, stored) )
      {
        stored.value = truncate_to_size(stored.value, instruction.l.size);
        effect.stored_value = stored;
      }
    }
  }
  return effect;
}

void apply_forward_effect(
    ForwardState &state,
    const ForwardEffect &effect)
{
  // Unknown and ordinary calls are hard barriers. This deliberately does not
  // borrow regfinder facts from after a call: an incomplete prototype or call
  // model must reduce optimization, never manufacture a constant.
  if ( effect.call )
  {
    state.registers.clear();
    state.slots.clear();
    state.slot_base.reset();
    return;
  }

  // Keep the abstract domain explicitly bounded. Scanning at most 256 exact
  // byte ranges per instruction is O(I) with a fixed constant and avoids the
  // previous unbounded backward searches.
  for ( auto iterator = state.registers.begin();
        iterator != state.registers.end(); )
  {
    if ( register_list_overlaps(effect.definitions.reg, iterator->first) )
      iterator = state.registers.erase(iterator);
    else
      ++iterator;
  }
  if ( effect.result_register )
    erase_register_range(state.registers, *effect.result_register);

  if ( state.slot_base
    && slot_base_is_defined(effect.definitions.reg, *state.slot_base) )
  {
    state.slots.clear();
    state.slot_base.reset();
  }

  if ( effect.writes_memory )
  {
    if ( !effect.stored_slot )
    {
      state.slots.clear();
      state.slot_base.reset();
    }
    else
    {
      if ( state.slot_base && *state.slot_base != effect.stored_slot->base )
      {
        state.slots.clear();
        state.slot_base.reset();
      }
      erase_overlapping_slots(state.slots, *effect.stored_slot);
    }
  }

  if ( effect.stored_slot && effect.stored_value )
  {
    state.slot_base = effect.stored_slot->base;
    state.slots[*effect.stored_slot] = *effect.stored_value;
  }
  if ( effect.result_register && effect.result )
  {
    state.registers[*effect.result_register] = *effect.result;
    if ( state.registers.size() > maximum_forward_register_constants )
      state.registers.clear();
  }
}

bool flatten_forward_operand(
    const ForwardState &state,
    minsn_t *current,
    mop_t &operand)
{
  if ( operand.t == mop_n )
    return false;
  ConstantValue value;
  if ( operand.size > 0 && operand.size <= 8
    && evaluate_forward_operand(state, current, operand, value, 0) )
  {
    if ( is_mcode_shift(current->opcode) && &operand == &current->r )
    {
      if ( current->l.size <= 0 )
        return false;
      const uint64 maximum = uint64(8 * current->l.size - 1);
      if ( value.value > maximum )
        return false;
    }
    operand.make_number(
        truncate_to_size(value.value, operand.size),
        operand.size, current->ea);
    return true;
  }
  if ( operand.t != mop_d || operand.d == nullptr )
    return false;
  minsn_t *inner = operand.d;
  bool changed = flatten_forward_operand(state, inner, inner->l);
  if ( inner->r.t != mop_z )
    changed = flatten_forward_operand(state, inner, inner->r) || changed;
  return changed;
}

bool fold_instruction(
    minsn_t *instruction,
    const ForwardEffect &effect)
{
  const int size = instruction->d.size;
  if ( !valid_scalar_size(size) || !effect.result
    || !effect.result_register || instruction->d.t != mop_r
    || instruction->is_fpinsn()
    || instruction->opcode == m_mov || instruction->opcode == m_ldc )
  {
    return false;
  }
  instruction->opcode = m_mov;
  instruction->clr_fpinsn();
  instruction->clr_assert();
  instruction->l.make_number(
      truncate_to_size(effect.result->value, size), size, instruction->ea);
  instruction->r.erase();
  return true;
}

int fold_constants(mba_t &mba, const EarlyHexRaysConfig &config)
{
  if ( !mba_within_bounds(mba, config) )
    return -1;
  int changes = 0;
  for ( int index = 0; index < mba.qty; ++index )
  {
    mblock_t *block = mba.get_mblock(index);
    ForwardState state;
    bool dirty = false;
    for ( minsn_t *instruction = block->head;
          instruction != nullptr; instruction = instruction->next )
    {
      const ForwardEffect effect = analyze_forward_effect(
          *block, *instruction, state);
      bool changed = false;
      if ( !effect.call && !instruction->is_fpinsn() )
      {
        changed = flatten_forward_operand(
            state, instruction, instruction->l);
        if ( instruction->r.t != mop_z )
        {
          changed = flatten_forward_operand(
              state, instruction, instruction->r) || changed;
        }
        changed = fold_instruction(instruction, effect) || changed;
      }
      apply_forward_effect(state, effect);
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
  const ssize_t owner_database = get_dbctx_id();
  EarlyHexRaysConfig config = load_early_hexrays_config();
  EarlyHexRaysStats statistics;
  bool installed = false;

  bool match(codegen_t &codegen) override
  {
    return get_dbctx_id() == owner_database
        && config.enabled && config.call_pop_codegen
        && is_x86_database()
        && is_return_instruction(codegen.insn)
        && resolve_gadget_return(
            codegen.insn.ea, config.gadget_scan_depth) != BADADDR;
  }

  merror_t apply(codegen_t &codegen) override
  {
    if ( get_dbctx_id() != owner_database )
      return MERR_INSN;
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
    if ( get_dbctx_id() != owner_database || !config.enabled
      || !config.call_pop_flowchart || input == nullptr )
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
    if ( get_dbctx_id() != owner_database || !config.enabled
      || !config.generated_gotos || mba == nullptr )
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
    if ( get_dbctx_id() != owner_database || !config.enabled || mba == nullptr )
      return 0;
    if ( !mba_within_bounds(*mba, config) )
    {
      ++statistics.bounded_skips;
      return 0;
    }

    int total = 0;
    // Fold first so a proven store expression has one in-flight numeric
    // operand that can carry the character numform. Source bytes in writable
    // segments are admitted only by read_constant_memory() when loaded and
    // free of every statically known write reference.
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
