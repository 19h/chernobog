/* IDA-free negotiation of rax 1.3 stateless SMIR instruction effects. */
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "program_model.hpp"
#include "rax_loader.hpp"

namespace chernobog::hybrid {

enum class SmirStatus : uint8_t
{
  VALID = 0,
  UNAVAILABLE,
  UNMAPPED,
  INVALID_ABI,
  BACKEND_ERROR,
  EFFECT_LIMIT,
};

struct SmirInstructionAnalysis
{
  SmirStatus status = SmirStatus::UNAVAILABLE;
  uint64_t instruction = 0;
  int arch = 0;
  uint32_t mode = 0;
  rax_analysis summary{};
  std::vector<rax_analysis_effect> effects;

  bool valid() const { return status == SmirStatus::VALID; }
};

// `maximum_bytes` must already be bounded to the current function chunk.
SmirInstructionAnalysis hybrid_analyze_instruction_effects(
    const RaxApi *api, const ProgramImage &image, uint64_t instruction,
    uint32_t mode, size_t maximum_bytes);

} // namespace chernobog::hybrid
