/*
 * decoder_core.hpp -- IDA-free static-decoder policy.
 *
 * Both decoder_audit.cpp and static_decoder.cpp use this layer for architecture
 * selection, instruction-boundary-safe decode windows, validation of the rax C
 * ABI result, direct-target classification, and decoder comparison.  Keeping
 * these decisions out of the IDA adapters makes the safety-critical policy
 * independently testable and prevents the two plugin passes from drifting.
 */
#pragma once

#include <cstddef>
#include <cstdint>

#include <rax.h>

#include "program_model.hpp"

namespace chernobog::hybrid {

struct DecoderArchitecture
{
  bool valid = false;
  int rax_arch = 0;
  uint32_t base_mode = 0;
  bool per_instruction_thumb = false;
};

// State of AArch32's T bit at one instruction.  Unknown is deliberately not
// guessed as ARM: callers must have authoritative state before decoding an
// architecture that can interwork between ARM and Thumb.
enum class DecoderArmState : uint8_t
{
  Unknown = 0,
  Arm,
  Thumb,
};

DecoderArchitecture hybrid_decoder_architecture(HybridArch arch, bool big_endian);

// Resolve the complete rax mode. Returns false only when the architecture is
// unsupported or an AArch32 instruction requires a known ARM/Thumb state.
bool hybrid_decoder_mode(const DecoderArchitecture &architecture,
                      DecoderArmState arm_state, uint32_t &mode);

// Maximum bytes that may be offered to a one-instruction decoder without
// crossing the current function chunk. Safe at UINT64_MAX and for pc >= end.
size_t hybrid_decoder_window_size(uint64_t pc, uint64_t chunk_end,
                               size_t maximum_bytes);

enum class DecoderTargetKind : uint8_t
{
  None = 0,
  Call,
  Jump,
};

// Producer-neutral instruction projection. `valid` means all invariants needed
// by the comparison/target policy have already been checked.
struct DecoderInstruction
{
  bool valid = false;
  uint32_t size = 0;
  int32_t flow = RAX_FLOW_UNKNOWN;
  bool indirect = false;
  bool has_target = false;
  uint64_t target = 0;
  bool has_fallthrough = false;
  uint64_t fallthrough = 0;
};

struct DecoderDirectTarget
{
  bool valid = false;
  DecoderTargetKind kind = DecoderTargetKind::None;
  uint64_t address = 0;
};

DecoderDirectTarget hybrid_decoder_direct_target(
    const DecoderInstruction &instruction);

enum class DecoderDecodeStatus : uint8_t
{
  Valid = 0,
  Unavailable,
  InvalidInput,
  BackendError,
  InvalidEncoding,
  MalformedResult,
};

struct DecoderDecodeResult
{
  DecoderDecodeStatus status = DecoderDecodeStatus::InvalidInput;
  DecoderInstruction instruction;
};

// Validate and project an already-produced rax result (including the decoded
// member embedded in rax_analysis). `offered_bytes` is the chunk-limited byte
// count; a decoder claiming a larger instruction is rejected as truncated.
DecoderDecodeResult hybrid_accept_rax_decoded(const rax_decoded &decoded,
                                           size_t offered_bytes);

// Invoke the stateless rax decoder and apply the identical validation policy.
DecoderDecodeResult hybrid_decode_one(decltype(&rax_decode) decode,
                                   int arch, uint32_t mode, uint64_t pc,
                                   const uint8_t *bytes, size_t byte_count);

struct DecoderComparison
{
  bool comparable = false;
  bool size_disagreement = false;
  bool flow_disagreement = false;
  bool targets_comparable = false;
  bool target_disagreement = false;
  bool fallthroughs_comparable = false;
  bool fallthrough_disagreement = false;
  DecoderDirectTarget left_target;
  DecoderDirectTarget right_target;
};

DecoderComparison hybrid_compare_decoders(const DecoderInstruction &left,
                                       const DecoderInstruction &right);

const char *hybrid_decoder_flow_name(int32_t flow);

} // namespace chernobog::hybrid
