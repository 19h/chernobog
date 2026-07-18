#include "decoder_core.hpp"

#include <algorithm>
#include <limits>

namespace chernobog::hybrid {
namespace {

bool known_flow(int32_t flow)
{
  return flow >= RAX_FLOW_FALLTHROUGH && flow <= RAX_FLOW_UNKNOWN;
}

bool direct_flow(int32_t flow)
{
  return flow == RAX_FLOW_CALL
      || flow == RAX_FLOW_BRANCH
      || flow == RAX_FLOW_COND_BRANCH;
}

bool indirect_flow(int32_t flow)
{
  return flow == RAX_FLOW_INDIRECT_CALL
      || flow == RAX_FLOW_INDIRECT_JUMP;
}

} // namespace

DecoderArchitecture hybrid_decoder_architecture(HybridArch arch, bool big_endian)
{
  const uint32_t endian = big_endian ? RAX_MODE_BIG_ENDIAN
                                     : RAX_MODE_LITTLE_ENDIAN;
  switch ( arch )
  {
    case HybridArch::X86_16:
      return { true, RAX_ARCH_X86, RAX_MODE_16, false };
    case HybridArch::X86_32:
      return { true, RAX_ARCH_X86, RAX_MODE_32, false };
    case HybridArch::X86_64:
      return { true, RAX_ARCH_X86, RAX_MODE_64, false };
    case HybridArch::ARM32:
      return { true, RAX_ARCH_ARM, endian, true };
    case HybridArch::ARM64:
      return { true, RAX_ARCH_ARM64, endian, false };
    case HybridArch::RISCV64:
      return { true, RAX_ARCH_RISCV64, endian, false };
    case HybridArch::CORTEX_M:
      return { true, RAX_ARCH_CORTEXM,
               uint32_t(endian | RAX_MODE_THUMB), false };
    case HybridArch::HEXAGON:
      return { true, RAX_ARCH_HEXAGON, endian, false };
    default:
      return {};
  }
}

bool hybrid_decoder_mode(const DecoderArchitecture &architecture,
                      DecoderArmState arm_state, uint32_t &mode)
{
  mode = 0;
  if ( !architecture.valid )
    return false;
  if ( !architecture.per_instruction_thumb )
  {
    mode = architecture.base_mode;
    return true;
  }
  if ( arm_state == DecoderArmState::Unknown )
    return false;
  mode = architecture.base_mode
       | (arm_state == DecoderArmState::Thumb ? RAX_MODE_THUMB : RAX_MODE_ARM);
  return true;
}

size_t hybrid_decoder_window_size(uint64_t pc, uint64_t chunk_end,
                               size_t maximum_bytes)
{
  if ( maximum_bytes == 0 || pc >= chunk_end )
    return 0;
  const uint64_t remaining = chunk_end - pc;
  const uint64_t size_limit = uint64_t(std::numeric_limits<size_t>::max());
  const size_t bounded_remaining = remaining > size_limit
                                 ? std::numeric_limits<size_t>::max()
                                 : size_t(remaining);
  return std::min(maximum_bytes, bounded_remaining);
}

DecoderDirectTarget hybrid_decoder_direct_target(
    const DecoderInstruction &instruction)
{
  DecoderDirectTarget result;
  if ( !instruction.valid || instruction.size == 0 || instruction.indirect
    || !instruction.has_target )
    return result;
  if ( instruction.flow == RAX_FLOW_CALL )
    result.kind = DecoderTargetKind::Call;
  else if ( instruction.flow == RAX_FLOW_BRANCH
         || instruction.flow == RAX_FLOW_COND_BRANCH )
    result.kind = DecoderTargetKind::Jump;
  else
    return result;
  result.valid = true;
  result.address = instruction.target;
  return result;
}

DecoderDecodeResult hybrid_accept_rax_decoded(const rax_decoded &decoded,
                                           size_t offered_bytes)
{
  DecoderDecodeResult result;
  result.status = DecoderDecodeStatus::InvalidEncoding;
  if ( offered_bytes == 0 || decoded.valid == 0 )
    return result;

  if ( decoded.valid != 1 || decoded.is_indirect > 1 || decoded.has_target > 1
    || decoded.size == 0 || size_t(decoded.size) > offered_bytes
    || !known_flow(decoded.flow) )
  {
    result.status = DecoderDecodeStatus::MalformedResult;
    return result;
  }

  const bool direct = direct_flow(decoded.flow);
  const bool indirect = indirect_flow(decoded.flow);
  if ( (direct && (decoded.has_target == 0 || decoded.is_indirect != 0))
    || (indirect && (decoded.has_target != 0 || decoded.is_indirect == 0))
    || (!direct && !indirect && (decoded.has_target != 0
                              || decoded.is_indirect != 0)) )
  {
    result.status = DecoderDecodeStatus::MalformedResult;
    return result;
  }

  result.status = DecoderDecodeStatus::Valid;
  result.instruction.valid = true;
  result.instruction.size = decoded.size;
  result.instruction.flow = decoded.flow;
  result.instruction.indirect = decoded.is_indirect != 0;
  result.instruction.has_target = decoded.has_target != 0;
  result.instruction.target = decoded.target;
  result.instruction.has_fallthrough =
      decoded.flow == RAX_FLOW_COND_BRANCH;
  result.instruction.fallthrough = decoded.fallthrough;
  return result;
}

DecoderDecodeResult hybrid_decode_one(decltype(&rax_decode) decode,
                                   int arch, uint32_t mode, uint64_t pc,
                                   const uint8_t *bytes, size_t byte_count)
{
  DecoderDecodeResult result;
  if ( decode == nullptr )
  {
    result.status = DecoderDecodeStatus::Unavailable;
    return result;
  }
  if ( bytes == nullptr || byte_count == 0 )
  {
    result.status = DecoderDecodeStatus::InvalidInput;
    return result;
  }
  rax_decoded decoded{};
  if ( decode(arch, mode, pc, bytes, byte_count, &decoded) != RAX_OK )
  {
    result.status = DecoderDecodeStatus::BackendError;
    return result;
  }
  return hybrid_accept_rax_decoded(decoded, byte_count);
}

DecoderComparison hybrid_compare_decoders(const DecoderInstruction &left,
                                       const DecoderInstruction &right)
{
  DecoderComparison comparison;
  comparison.left_target = hybrid_decoder_direct_target(left);
  comparison.right_target = hybrid_decoder_direct_target(right);
  if ( !left.valid || !right.valid || left.size == 0 || right.size == 0 )
    return comparison;

  comparison.comparable = true;
  comparison.size_disagreement = left.size != right.size;
  comparison.flow_disagreement = left.flow != right.flow;
  comparison.targets_comparable = comparison.left_target.valid
                               || comparison.right_target.valid;
  if ( comparison.targets_comparable )
  {
    comparison.target_disagreement =
        comparison.left_target.valid != comparison.right_target.valid
     || (comparison.left_target.valid && comparison.right_target.valid
      && (comparison.left_target.kind != comparison.right_target.kind
       || comparison.left_target.address != comparison.right_target.address));
  }
  comparison.fallthroughs_comparable = left.has_fallthrough
                                    || right.has_fallthrough;
  if ( comparison.fallthroughs_comparable )
  {
    comparison.fallthrough_disagreement =
        left.has_fallthrough != right.has_fallthrough
     || (left.has_fallthrough && right.has_fallthrough
      && left.fallthrough != right.fallthrough);
  }
  return comparison;
}

const char *hybrid_decoder_flow_name(int32_t flow)
{
  switch ( flow )
  {
    case RAX_FLOW_FALLTHROUGH:   return "fallthrough";
    case RAX_FLOW_BRANCH:        return "branch";
    case RAX_FLOW_COND_BRANCH:   return "conditional-branch";
    case RAX_FLOW_INDIRECT_JUMP: return "indirect-jump";
    case RAX_FLOW_CALL:          return "call";
    case RAX_FLOW_INDIRECT_CALL: return "indirect-call";
    case RAX_FLOW_RETURN:        return "return";
    case RAX_FLOW_TRAP:          return "trap";
    case RAX_FLOW_SYSCALL:       return "syscall";
    case RAX_FLOW_UNKNOWN:       return "unknown";
    default:                     return "invalid";
  }
}

} // namespace chernobog::hybrid
