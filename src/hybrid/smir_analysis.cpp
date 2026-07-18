#include "smir_analysis.hpp"

#include "decoder_core.hpp"

#include <algorithm>

namespace chernobog::hybrid {
namespace {

constexpr size_t kMaximumInstructionBytes = 16;
constexpr size_t kInlineEffects = 32;
constexpr size_t kMaximumEffects = 4096;

bool effect_abi_valid(const rax_analysis_effect &effect)
{
  return effect.struct_size == sizeof(rax_analysis_effect)
      && effect.abi_version == RAX_ANALYSIS_ABI_VERSION;
}

bool summary_abi_valid(const rax_analysis &summary, size_t required)
{
  return summary.struct_size == sizeof(rax_analysis)
      && summary.abi_version == RAX_ANALYSIS_ABI_VERSION
      && size_t(summary.required_effect_count) == required;
}

} // namespace

SmirInstructionAnalysis hybrid_analyze_instruction_effects(
    const RaxApi *api, const ProgramImage &image, uint64_t instruction,
    uint32_t mode, size_t maximum_bytes)
{
  SmirInstructionAnalysis result;
  result.instruction = instruction;
  result.mode = mode;
  if ( api == nullptr || api->analyze == nullptr )
    return result;

  const DecoderArchitecture architecture =
      hybrid_decoder_architecture(image.arch, image.big_endian);
  if ( !architecture.valid )
  {
    result.status = SmirStatus::BACKEND_ERROR;
    return result;
  }
  result.arch = architecture.rax_arch;

  const SegImage *segment = image.segment_at(instruction);
  if ( segment == nullptr || instruction >= segment->end || maximum_bytes == 0 )
  {
    result.status = SmirStatus::UNMAPPED;
    return result;
  }
  const size_t available = size_t(std::min<uint64_t>(
      std::min<size_t>(kMaximumInstructionBytes, maximum_bytes),
      segment->end - instruction));
  std::vector<uint8_t> bytes;
  bytes.reserve(available);
  for ( size_t offset = 0; offset < available; ++offset )
  {
    const uint64_t address = instruction + uint64_t(offset);
    if ( !segment->byte_loaded(address) )
      break;
    bytes.push_back(segment->bytes[size_t(address - segment->start)]);
  }
  if ( bytes.empty() )
  {
    result.status = SmirStatus::UNMAPPED;
    return result;
  }

  result.effects.resize(kInlineEffects);
  size_t required = 0;
  rax_status status = api->analyze(
      result.arch, result.mode, instruction, bytes.data(), bytes.size(),
      &result.summary, result.effects.data(), result.effects.size(), &required);
  if ( required > kMaximumEffects )
  {
    result.effects.clear();
    result.status = SmirStatus::EFFECT_LIMIT;
    return result;
  }
  if ( !summary_abi_valid(result.summary, required) )
  {
    result.effects.clear();
    result.status = SmirStatus::INVALID_ABI;
    return result;
  }

  if ( status == RAX_ERR_BOUNDS )
  {
    if ( required <= result.effects.size()
      || size_t(result.summary.effect_count) != result.effects.size()
      || (result.summary.flags & RAX_ANALYSIS_TRUNCATED) == 0 )
    {
      result.effects.clear();
      result.status = SmirStatus::INVALID_ABI;
      return result;
    }
    result.effects.resize(required);
    size_t retry_required = 0;
    status = api->analyze(
        result.arch, result.mode, instruction, bytes.data(), bytes.size(),
        &result.summary, result.effects.data(), result.effects.size(),
        &retry_required);
    if ( retry_required != required
      || !summary_abi_valid(result.summary, required) )
    {
      result.effects.clear();
      result.status = SmirStatus::INVALID_ABI;
      return result;
    }
  }

  if ( status != RAX_OK || size_t(result.summary.effect_count) != required
    || (result.summary.flags & RAX_ANALYSIS_TRUNCATED) != 0 )
  {
    result.effects.clear();
    result.status = SmirStatus::BACKEND_ERROR;
    return result;
  }
  result.effects.resize(required);
  if ( !std::all_of(result.effects.begin(), result.effects.end(), effect_abi_valid) )
  {
    result.effects.clear();
    result.status = SmirStatus::INVALID_ABI;
    return result;
  }
  result.status = SmirStatus::VALID;
  return result;
}

} // namespace chernobog::hybrid
