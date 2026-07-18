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
  const bool control = call || ret || (direct && !nonflow_targets.empty())
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
      const flags64_t flags = get_flags(address);
      if ( is_code(flags) && is_head(flags) )
      {
        insn_t instruction;
        if ( decode_insn(&instruction, address) > 0 )
        {
          ++result.stats.instruction_heads;
          const DecoderInstruction ida_projection = project_ida(address, instruction);
          size_t component_offset = 0;
          size_t component_index = 0;
          bool macro_counted = false;
          while ( component_offset < instruction.size )
          {
            if ( remaining == 0 )
            {
              result.stats.truncated = true;
              break;
            }
            --remaining;
            const uint64_t component_address = uint64_t(address) + component_offset;
            StaticInstructionEvidence item;
            item.address = component_address;
            item.ida_head = uint64_t(address);
            item.ida_projection_present = component_index == 0;
            if ( item.ida_projection_present )
              item.ida = ida_projection;

            const DecoderArmState state = arm_state_at(
                architecture, t_register, ea_t(component_address));
            const size_t offered = hybrid_decoder_window_size(
                component_address, chunk.end, kMaximumInstructionBytes);
            uint8_t bytes[kMaximumInstructionBytes] = {};
            const size_t copied = copy_instruction_window(
                image, component_address, offered, bytes);
            if ( copied != 0
              && hybrid_decoder_mode(architecture, state, item.mode) )
            {
              // Decode is required for canonical traversal even when only SMIR
              // output was requested.
              item.rax = hybrid_decode_one(
                    api->decode, architecture.rax_arch, item.mode,
                    component_address, bytes, copied);
              if ( item.rax.status == DecoderDecodeStatus::Valid )
              {
                ++result.stats.rax_decoded;
                const bool arm64_macro = image.arch == HybridArch::ARM64
                    && instruction.size > item.rax.instruction.size
                    && item.rax.instruction.size == 4
                    && instruction.size % 4 == 0;
                item.ida_macro_component = arm64_macro;
                if ( arm64_macro )
                {
                  if ( !macro_counted )
                  {
                    ++result.stats.ida_macro_heads;
                    macro_counted = true;
                  }
                  ++result.stats.ida_macro_components;
                }
                else if ( config.want_static && item.ida_projection_present )
                {
                  item.comparison = hybrid_compare_decoders(
                      item.ida, item.rax.instruction);
                  ++result.stats.decoder_comparisons;
                  const bool mismatch = item.comparison.size_disagreement
                                     || item.comparison.flow_disagreement
                                     || item.comparison.target_disagreement
                                     || item.comparison.fallthrough_disagreement;
                  if ( mismatch )
                    ++result.stats.mismatched_instructions;
                  if ( item.comparison.size_disagreement )
                    ++result.stats.size_disagreements;
                  if ( item.comparison.flow_disagreement )
                    ++result.stats.flow_disagreements;
                  if ( item.comparison.target_disagreement )
                    ++result.stats.target_disagreements;
                  if ( item.comparison.fallthrough_disagreement )
                    ++result.stats.fallthrough_disagreements;
                }
              }
              else
              {
                ++result.stats.rax_decode_failures;
              }
              if ( config.want_smir )
              {
                item.smir = hybrid_analyze_instruction_effects(
                    api, image, component_address, item.mode, offered);
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
            const size_t step = item.rax.status == DecoderDecodeStatus::Valid
                              ? size_t(item.rax.instruction.size)
                              : size_t(instruction.size) - component_offset;
            ++result.stats.canonical_instructions;
            result.instructions.push_back(std::move(item));
            if ( step == 0 || step > size_t(instruction.size) - component_offset )
              break;
            component_offset += step;
            ++component_index;
          }
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
