#include "static_analysis.hpp"

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <segregs.hpp>
#include <kernwin.hpp>

#include <algorithm>

namespace chernobog::hybrid {
namespace {

constexpr size_t kMaximumInstructionBytes = 16;

bool encoded_direct_operand(const insn_t &instruction)
{
  for ( int index = 0; index < UA_MAXOP; ++index )
  {
    const op_t &operand = instruction.ops[index];
    if ( operand.type == o_void )
      break;
    if ( operand.type == o_near || operand.type == o_far )
      return true;
  }
  return false;
}

DecoderInstruction project_ida(ea_t address, const insn_t &instruction)
{
  DecoderInstruction result;
  result.valid = instruction.size != 0;
  result.size = instruction.size;

  bool flow = false;
  std::vector<uint64_t> nonflow_targets;
  xrefblk_t xref;
  for ( bool ok = xref.first_from(address, XREF_CODE); ok; ok = xref.next_from() )
  {
    if ( xref.type == fl_F )
      flow = true;
    else
      nonflow_targets.push_back(uint64_t(xref.to));
  }
  std::sort(nonflow_targets.begin(), nonflow_targets.end());
  nonflow_targets.erase(
      std::unique(nonflow_targets.begin(), nonflow_targets.end()),
      nonflow_targets.end());

  const bool direct = encoded_direct_operand(instruction);
  const bool call = is_call_insn(instruction);
  const bool ret = is_ret_insn(instruction);
  const uint32_t features = instruction.get_canon_feature(PH);
  const bool control = call || ret
                    || (features & (CF_CALL | CF_JUMP | CF_STOP)) != 0;

  if ( call )
    result.flow = direct ? RAX_FLOW_CALL : RAX_FLOW_INDIRECT_CALL;
  else if ( ret )
    result.flow = RAX_FLOW_RETURN;
  else if ( control )
    result.flow = direct
        ? (flow ? RAX_FLOW_COND_BRANCH : RAX_FLOW_BRANCH)
        : RAX_FLOW_INDIRECT_JUMP;
  else
    result.flow = RAX_FLOW_FALLTHROUGH;

  result.indirect = result.flow == RAX_FLOW_INDIRECT_CALL
                 || result.flow == RAX_FLOW_INDIRECT_JUMP;
  if ( direct && nonflow_targets.size() == 1 )
  {
    result.has_target = true;
    result.target = nonflow_targets.front();
  }
  if ( result.flow == RAX_FLOW_COND_BRANCH )
  {
    result.has_fallthrough = true;
    result.fallthrough = uint64_t(address) + uint64_t(instruction.size);
  }
  return result;
}

DecoderArmState arm_state_at(const DecoderArchitecture &architecture,
                             int t_register, ea_t address)
{
  if ( !architecture.per_instruction_thumb )
    return DecoderArmState::Arm;
  const sel_t state = t_register >= 0 ? get_sreg(address, t_register) : BADSEL;
  if ( state == BADSEL )
    return DecoderArmState::Unknown;
  return state == 0 ? DecoderArmState::Arm : DecoderArmState::Thumb;
}

size_t copy_instruction_window(const ProgramImage &image, uint64_t address,
                               size_t maximum, uint8_t *output)
{
  const SegImage *segment = image.segment_at(address);
  if ( segment == nullptr || address >= segment->end )
    return 0;
  const size_t available = size_t(std::min<uint64_t>(maximum, segment->end - address));
  size_t copied = 0;
  for ( ; copied < available; ++copied )
  {
    const uint64_t current = address + uint64_t(copied);
    if ( !segment->byte_loaded(current) )
      break;
    output[copied] = segment->bytes[size_t(current - segment->start)];
  }
  return copied;
}

} // namespace

StaticAnalysisResult hybrid_analyze_current_function(
    const RaxApi *api, const ProgramImage &image, const FuncRange &function,
    const HybridConfig &config)
{
  StaticAnalysisResult result;
  result.function_start = function.start;
  if ( api == nullptr || (!config.want_static && !config.want_smir) )
    return result;

  const DecoderArchitecture architecture =
      hybrid_decoder_architecture(image.arch, image.big_endian);
  if ( !architecture.valid )
    return result;
  const int t_register = architecture.per_instruction_thumb ? str2reg("T") : -1;

  size_t remaining = config.max_static_instructions;
  for ( const FuncChunk &chunk : function.chunks )
  {
    ea_t address = ea_t(chunk.start);
    const ea_t end = ea_t(chunk.end);
    while ( address != BADADDR && address < end )
    {
      if ( (result.stats.instruction_heads & 0xFFu) == 0 && user_cancelled() )
      {
        result.stats.truncated = true;
        break;
      }
      if ( remaining == 0 )
      {
        result.stats.truncated = true;
        break;
      }
      --remaining;
      const flags64_t flags = get_flags(address);
      if ( is_code(flags) && is_head(flags) )
      {
        insn_t instruction;
        if ( decode_insn(&instruction, address) > 0 )
        {
          StaticInstructionEvidence item;
          item.address = uint64_t(address);
          item.ida = project_ida(address, instruction);
          ++result.stats.instruction_heads;

          const DecoderArmState state = arm_state_at(
              architecture, t_register, address);
          const size_t offered = hybrid_decoder_window_size(
              uint64_t(address), chunk.end, kMaximumInstructionBytes);
          uint8_t bytes[kMaximumInstructionBytes] = {};
          const size_t copied = copy_instruction_window(
              image, uint64_t(address), offered, bytes);
          if ( copied != 0
            && hybrid_decoder_mode(architecture, state, item.mode) )
          {
            if ( config.want_static )
            {
              item.rax = hybrid_decode_one(
                  api->decode, architecture.rax_arch, item.mode,
                  uint64_t(address), bytes, copied);
              if ( item.rax.status == DecoderDecodeStatus::Valid )
              {
                ++result.stats.rax_decoded;
                item.comparison = hybrid_compare_decoders(
                    item.ida, item.rax.instruction);
                if ( item.comparison.size_disagreement )
                  ++result.stats.size_disagreements;
                if ( item.comparison.flow_disagreement )
                  ++result.stats.flow_disagreements;
                if ( item.comparison.target_disagreement )
                  ++result.stats.target_disagreements;
                if ( item.comparison.fallthrough_disagreement )
                  ++result.stats.fallthrough_disagreements;
              }
              else
              {
                ++result.stats.rax_decode_failures;
              }
            }
            if ( config.want_smir )
            {
              item.smir = hybrid_analyze_instruction_effects(
                  api, image, uint64_t(address), item.mode, offered);
              if ( item.smir.valid() )
              {
                ++result.stats.smir_analyzed;
                if ( (item.smir.summary.flags & RAX_ANALYSIS_COMPLETE) != 0 )
                  ++result.stats.smir_complete;
                if ( (item.smir.summary.flags & RAX_ANALYSIS_PARTIAL) != 0 )
                  ++result.stats.smir_partial;
              }
            }
          }
          result.instructions.push_back(std::move(item));
        }
      }

      const ea_t next = next_head(address, end);
      if ( next == BADADDR || next <= address )
        break;
      address = next;
    }
    if ( result.stats.truncated )
      break;
  }
  std::sort(result.instructions.begin(), result.instructions.end(),
            [](const StaticInstructionEvidence &left,
               const StaticInstructionEvidence &right)
            { return left.address < right.address; });
  return result;
}

} // namespace chernobog::hybrid
