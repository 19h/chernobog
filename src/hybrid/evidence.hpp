/* Typed, function-generation-bound observations from static and concrete rax. */
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "emulation_workers.hpp"
#include "static_analysis.hpp"

namespace chernobog::hybrid {

enum class EvidenceProducer : uint8_t
{
  IDA_STATIC = 0,
  RAX_DECODE,
  RAX_SMIR,
  RAX_CONCRETE,
  Z3_MODEL_REPLAY,
};

enum class ProofCharacter : uint8_t
{
  STATIC_FACT = 0,
  CONCRETE_WITNESS,
  CROSS_CHECK,
};

struct EvidenceProvenance
{
  EvidenceProducer producer = EvidenceProducer::RAX_CONCRETE;
  ProofCharacter proof = ProofCharacter::CONCRETE_WITNESS;
  uint64_t function_start = 0;
  uint64_t function_hash = 0;
  uint64_t image_hash = 0;
  uint64_t generation = 0;
  uint64_t focus_address = 0;
  uint64_t ticket = 0;
  uint32_t run_id = 0;
  uint64_t seed = 0;
};

enum class InputOrigin : uint8_t
{
  DETERMINISTIC_SEED = 0,
  CALLSITE_TRACKER,
  Z3_MODEL,
};

struct ConcreteInput
{
  InputOrigin origin = InputOrigin::DETERMINISTIC_SEED;
  EmuInput input;
  std::string label;
};

enum class BranchDisposition : uint8_t
{
  TAKEN = 0,
  FALLTHROUGH,
  OTHER_SUCCESSOR,
};

struct BranchObservation
{
  uint64_t instruction = 0;
  uint64_t encoded_target = 0;
  uint64_t fallthrough = 0;
  uint64_t observed_successor = 0;
  BranchDisposition disposition = BranchDisposition::OTHER_SUCCESSOR;
  uint64_t sequence = 0;
  bool consumed_context_complete = false;
  EvidenceProvenance provenance;
};

struct IndirectTargetObservation
{
  uint64_t instruction = 0;
  uint64_t target = 0;
  ExecEdge::Kind kind = ExecEdge::Kind::Unknown;
  EvidenceProvenance provenance;
};

struct RunObservation
{
  bool ran = false;
  EmuOutcome outcome;
  EvidenceProvenance provenance;
};

enum class BranchClaimVerdict : uint8_t
{
  NO_OBSERVATION = 0,
  CORROBORATED,
  COUNTEREXAMPLE,
  MIXED,
};

struct BranchClaimCheck
{
  BranchClaimVerdict verdict = BranchClaimVerdict::NO_OBSERVATION;
  size_t matching = 0;
  size_t opposing = 0;
  size_t opposing_context_complete = 0;
  size_t other = 0;
  std::set<uint32_t> matching_runs;
  std::set<uint32_t> opposing_runs;
  std::set<uint32_t> opposing_context_complete_runs;

  bool falsifies_universal_claim() const
  {
    return opposing_context_complete != 0
        && (verdict == BranchClaimVerdict::COUNTEREXAMPLE
         || verdict == BranchClaimVerdict::MIXED);
  }
};

struct EvidenceSummary
{
  size_t ida_instruction_heads = 0;
  size_t static_instructions = 0;
  size_t ida_macro_heads = 0;
  size_t ida_macro_components = 0;
  size_t smir_effects = 0;
  size_t completed_runs = 0;
  size_t returned_runs = 0;
  size_t definitive_terminal_runs = 0;
  size_t instruction_budget_runs = 0;
  size_t timeout_runs = 0;
  size_t escaped_image_runs = 0;
  size_t unmodeled_external_runs = 0;
  size_t environment_model_failure_runs = 0;
  size_t external_model_runs = 0;
  size_t synthetic_entry_context_runs = 0;
  size_t attempted_steps_unknown_runs = 0;
  size_t summarized_calls = 0;
  size_t executed_instruction_addresses = 0;
  size_t executed_addresses_without_static_record = 0;
  size_t conditional_observations = 0;
  size_t conditional_sites = 0;
  size_t predicate_state_inputs = 0;
  size_t indirect_targets = 0;
  size_t indirect_sites = 0;
  size_t unique_indirect_targets = 0;
  size_t image_reads = 0;
  size_t image_writes = 0;
  size_t final_write_ranges = 0;
  size_t pointer_value_reads = 0;
  size_t executable_pointer_reads = 0;
  size_t self_modifying_ranges = 0;
  size_t decoder_disagreements = 0;
  size_t decoder_disagreement_flags = 0;
  size_t decoder_comparisons = 0;
  size_t decoder_size_disagreements = 0;
  size_t decoder_flow_disagreements = 0;
  size_t decoder_target_disagreements = 0;
  size_t decoder_fallthrough_disagreements = 0;
  size_t context_identity_ranges = 0;
  uint64_t context_identity_bytes = 0;
  size_t permission_violating_runs = 0;
  size_t memory_observation_requested_runs = 0;
  size_t memory_observation_available_runs = 0;
  size_t context_incomplete_runs = 0;
};

enum class IdentityMismatchKind : uint8_t
{
  NONE = 0,
  BYTE_VECTOR_SIZE,
  MASK_VECTOR_SIZE,
  LOADED_STATE,
  BYTE_VALUE,
};

struct IdentityComparison
{
  IdentityMismatchKind mismatch = IdentityMismatchKind::NONE;
  size_t offset = 0;
  size_t expected_size = 0;
  size_t actual_size = 0;
  uint8_t expected_byte = 0;
  uint8_t actual_byte = 0;

  bool matches() const { return mismatch == IdentityMismatchKind::NONE; }
};

// Compare only address-bearing bits and only byte values that both identities
// mark loaded. Padding bits in the final mask byte and payload at uninitialized
// addresses have no database semantics and must not invalidate evidence.
IdentityComparison hybrid_compare_identity_bytes(
    const std::vector<uint8_t> &expected_bytes,
    const std::vector<uint8_t> &expected_mask,
    const std::vector<uint8_t> &actual_bytes,
    const std::vector<uint8_t> &actual_mask);

struct FunctionChunkIdentity
{
  uint64_t start = 0;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> loaded_mask;
};

// Exact immutable-image ranges that a concrete run consumed outside or inside
// the selected function: executed instruction bytes and observed image reads.
// This makes freshness context-sensitive without re-hashing the entire IDB.
struct ContextRangeIdentity
{
  uint64_t start = 0;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> loaded_mask;
};

struct TargetEvidence
{
  EvidenceProvenance scope;
  HybridArch architecture = HybridArch::UNSUPPORTED;
  HybridEntryMode entry_mode = HybridEntryMode::DEFAULT;
  HybridFunctionProfile function_profile;
  std::vector<FunctionChunkIdentity> function_identity;
  std::vector<ContextRangeIdentity> context_identity;
  StaticAnalysisResult static_analysis;
  std::vector<ConcreteInput> inputs;
  std::vector<RunObservation> runs;
  std::vector<BranchObservation> branches;
  std::vector<IndirectTargetObservation> indirect_targets;
  EmuEvents events;
  EvidenceSummary summary;
  std::string diagnostic;

  bool matches(uint64_t function_start, uint64_t function_hash) const;
  BranchClaimCheck check_branch_claim(uint64_t instruction,
                                      bool expected_taken) const;
};

TargetEvidence hybrid_build_target_evidence(
    const ProgramImage &image, const FuncRange &function,
    uint64_t focus_address, const StaticAnalysisResult &static_analysis,
    const std::vector<ConcreteInput> &inputs,
    const EmulationJobResult &emulation);

const char *hybrid_branch_verdict_name(BranchClaimVerdict verdict);

} // namespace chernobog::hybrid
