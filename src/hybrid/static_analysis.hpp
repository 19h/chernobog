/* Main-thread, current-function comparison of IDA and rax decode/SMIR facts. */
#pragma once

#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <vector>

#include "decoder_core.hpp"
#include "hybrid_config.hpp"
#include "program_model.hpp"
#include "rax_loader.hpp"
#include "smir_analysis.hpp"

namespace chernobog::hybrid {

struct StaticInstructionEvidence
{
  uint64_t address = 0;
  uint32_t mode = 0;
  DecoderInstruction ida;
  DecoderDecodeResult rax;
  DecoderComparison comparison;
  SmirInstructionAnalysis smir;
};

struct StaticAnalysisStats
{
  size_t instruction_heads = 0;
  size_t rax_decoded = 0;
  size_t rax_decode_failures = 0;
  size_t smir_analyzed = 0;
  size_t smir_complete = 0;
  size_t smir_partial = 0;
  size_t size_disagreements = 0;
  size_t flow_disagreements = 0;
  size_t target_disagreements = 0;
  size_t fallthrough_disagreements = 0;
  bool truncated = false;
};

struct StaticAnalysisResult
{
  uint64_t function_start = 0;
  StaticAnalysisStats stats;
  std::vector<StaticInstructionEvidence> instructions;

  const StaticInstructionEvidence *find(uint64_t address) const
  {
    const auto found = std::lower_bound(
        instructions.begin(), instructions.end(), address,
        [](const StaticInstructionEvidence &item, uint64_t value)
        { return item.address < value; });
    return found != instructions.end() && found->address == address
         ? &*found : nullptr;
  }
};

// Reads IDA instruction boundaries/xrefs and segment-register state. Main
// thread only; all rax calls here are stateless.
StaticAnalysisResult hybrid_analyze_current_function(
    const RaxApi *api, const ProgramImage &image, const FuncRange &function,
    const HybridConfig &config);

} // namespace chernobog::hybrid
