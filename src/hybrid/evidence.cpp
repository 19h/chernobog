#include "evidence.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <tuple>
#include <unordered_set>

namespace chernobog::hybrid {
namespace {

EvidenceProvenance provenance_for(
    const ProgramImage &image, const FuncRange &function,
    uint64_t focus, uint64_t ticket, uint32_t run_id, uint64_t seed)
{
  EvidenceProvenance result;
  result.producer = EvidenceProducer::RAX_CONCRETE;
  result.proof = ProofCharacter::CONCRETE_WITNESS;
  result.function_start = function.start;
  result.function_hash = function.byte_hash;
  result.image_hash = image.content_hash;
  result.generation = function.generation;
  result.focus_address = focus;
  result.ticket = ticket;
  result.run_id = run_id;
  result.seed = seed;
  return result;
}

bool conditional_projection(const StaticInstructionEvidence &item,
                            uint64_t *target, uint64_t *fallthrough)
{
  const DecoderInstruction *projection = nullptr;
  if ( !item.ida_macro_component
    && item.ida.valid && item.ida.flow == RAX_FLOW_COND_BRANCH
    && item.ida.has_target && item.ida.has_fallthrough )
  {
    projection = &item.ida;
  }
  else if ( item.rax.status == DecoderDecodeStatus::Valid
         && item.rax.instruction.flow == RAX_FLOW_COND_BRANCH
         && item.rax.instruction.has_target
         && item.rax.instruction.has_fallthrough )
  {
    projection = &item.rax.instruction;
  }
  if ( projection == nullptr )
    return false;
  *target = projection->target;
  *fallthrough = projection->fallthrough;
  return true;
}

bool static_indirect_at(const StaticAnalysisResult &analysis, uint64_t address)
{
  const StaticInstructionEvidence *item = analysis.find(address);
  if ( item == nullptr )
    return false;
  return (!item->ida_macro_component && item->ida.indirect)
      || (item->rax.status == DecoderDecodeStatus::Valid
       && item->rax.instruction.indirect);
}

struct DependencyRange
{
  uint64_t start = 0;
  uint64_t end = 0;
};

void append_dependency_range(std::vector<DependencyRange> &ranges,
                             const ProgramImage &image,
                             uint64_t address, uint64_t size)
{
  if ( size == 0 || address > std::numeric_limits<uint64_t>::max() - size )
    return;
  const uint64_t requested_end = address + size;
  uint64_t cursor = address;
  while ( cursor < requested_end )
  {
    const SegImage *segment = image.segment_at(cursor);
    if ( segment == nullptr )
      return;
    const uint64_t end = std::min(requested_end, segment->end);
    ranges.push_back(DependencyRange{ cursor, end });
    cursor = end;
  }
}

ContextRangeIdentity capture_context_identity(
    const ProgramImage &image, uint64_t start, uint64_t end)
{
  ContextRangeIdentity identity;
  identity.start = start;
  if ( end <= start )
    return identity;
  const size_t size = size_t(end - start);
  identity.bytes.assign(size, 0);
  identity.loaded_mask.assign((size + 7) / 8, 0);
  for ( size_t offset = 0; offset < size; ++offset )
  {
    const uint64_t address = start + uint64_t(offset);
    const SegImage *segment = image.segment_at(address);
    if ( segment == nullptr || !segment->byte_loaded(address) )
      continue;
    identity.bytes[offset] = segment->bytes[size_t(address - segment->start)];
    identity.loaded_mask[offset / 8] |= uint8_t(1u << (offset & 7));
  }
  return identity;
}

} // namespace

IdentityComparison hybrid_compare_identity_bytes(
    const std::vector<uint8_t> &expected_bytes,
    const std::vector<uint8_t> &expected_mask,
    const std::vector<uint8_t> &actual_bytes,
    const std::vector<uint8_t> &actual_mask)
{
  IdentityComparison result;
  if ( expected_bytes.size() != actual_bytes.size() )
  {
    result.mismatch = IdentityMismatchKind::BYTE_VECTOR_SIZE;
    result.expected_size = expected_bytes.size();
    result.actual_size = actual_bytes.size();
    return result;
  }

  const size_t required_mask_size = (expected_bytes.size() + 7) / 8;
  if ( expected_mask.size() < required_mask_size
    || actual_mask.size() < required_mask_size )
  {
    result.mismatch = IdentityMismatchKind::MASK_VECTOR_SIZE;
    result.expected_size = expected_mask.size();
    result.actual_size = actual_mask.size();
    return result;
  }

  for ( size_t offset = 0; offset < expected_bytes.size(); ++offset )
  {
    const uint8_t bit = uint8_t(1u << (offset & 7));
    const bool expected_loaded = (expected_mask[offset / 8] & bit) != 0;
    const bool actual_loaded = (actual_mask[offset / 8] & bit) != 0;
    if ( expected_loaded != actual_loaded )
    {
      result.mismatch = IdentityMismatchKind::LOADED_STATE;
      result.offset = offset;
      result.expected_byte = expected_loaded ? 1 : 0;
      result.actual_byte = actual_loaded ? 1 : 0;
      return result;
    }
    if ( expected_loaded && expected_bytes[offset] != actual_bytes[offset] )
    {
      result.mismatch = IdentityMismatchKind::BYTE_VALUE;
      result.offset = offset;
      result.expected_byte = expected_bytes[offset];
      result.actual_byte = actual_bytes[offset];
      return result;
    }
  }
  return result;
}

bool TargetEvidence::matches(uint64_t function_start,
                             uint64_t function_hash) const
{
  return scope.function_start == function_start
      && scope.function_hash == function_hash;
}

std::vector<RuntimeStringCandidate> hybrid_consensus_runtime_strings(
    const TargetEvidence &evidence, size_t minimum_length,
    size_t maximum_length)
{
  std::vector<RuntimeStringCandidate> result;
  if ( minimum_length == 0 || maximum_length < minimum_length )
    return result;

  using RunKey = std::pair<uint32_t, uint64_t>;
  std::set<RunKey> eligible;
  for ( const RunObservation &run : evidence.runs )
  {
    if ( run.ran && run.outcome.memory_observation_available )
      eligible.emplace(run.provenance.run_id, run.provenance.seed);
  }
  if ( eligible.empty() )
    return result;

  // One address may appear more than once in a backend trace (for example,
  // after model-replay evidence is merged). Retain one exact value per run and
  // reject that run/address if its final ranges disagree.
  std::map<uint64_t, std::map<RunKey, std::string>> values;
  std::map<uint64_t, std::set<RunKey>> ambiguous;
  for ( const MemoryBytes &written : evidence.events.final_writes )
  {
    const RunKey run{ written.run_id, written.seed };
    if ( written.scope != DataScope::IMAGE || eligible.count(run) == 0
      || written.bytes.empty() )
    {
      continue;
    }

    size_t length = 0;
    while ( length < written.bytes.size() && written.bytes[length] != 0 )
    {
      const uint8_t byte = written.bytes[length];
      if ( byte < 0x20 || byte > 0x7E || length == maximum_length )
      {
        length = 0;
        break;
      }
      ++length;
    }
    // A captured range without its terminator could be a prefix of arbitrary
    // binary data; do not turn it into a string fact.
    if ( length < minimum_length || length >= written.bytes.size()
      || written.bytes[length] != 0 )
    {
      continue;
    }

    const std::string candidate(
        reinterpret_cast<const char *>(written.bytes.data()), length);
    auto &per_run = values[written.addr];
    const auto prior = per_run.find(run);
    if ( prior == per_run.end() )
      per_run.emplace(run, candidate);
    else if ( prior->second != candidate )
      ambiguous[written.addr].insert(run);
  }

  for ( const auto &address_values : values )
  {
    const uint64_t address = address_values.first;
    const auto &per_run = address_values.second;
    if ( per_run.size() != eligible.size()
      || !ambiguous[address].empty() )
    {
      continue;
    }
    const std::string &consensus = per_run.begin()->second;
    bool same = true;
    RuntimeStringCandidate candidate;
    candidate.address = address;
    candidate.value = consensus;
    candidate.eligible_runs = eligible.size();
    for ( const RunKey &run : eligible )
    {
      const auto observed = per_run.find(run);
      if ( observed == per_run.end() || observed->second != consensus )
      {
        same = false;
        break;
      }
      candidate.runs.push_back(run.first);
    }
    if ( same )
    {
      candidate.observations = candidate.runs.size();
      result.push_back(std::move(candidate));
    }
  }
  return result;
}

BranchClaimCheck TargetEvidence::check_branch_claim(
    uint64_t instruction, bool expected_taken) const
{
  BranchClaimCheck result;
  for ( const BranchObservation &observation : branches )
  {
    if ( observation.instruction != instruction )
      continue;
    if ( observation.disposition == BranchDisposition::OTHER_SUCCESSOR )
    {
      ++result.other;
      continue;
    }
    const bool observed_taken =
        observation.disposition == BranchDisposition::TAKEN;
    if ( observed_taken == expected_taken )
    {
      ++result.matching;
      result.matching_runs.insert(observation.provenance.run_id);
    }
    else
    {
      ++result.opposing;
      result.opposing_runs.insert(observation.provenance.run_id);
      if ( observation.consumed_context_complete )
      {
        ++result.opposing_context_complete;
        result.opposing_context_complete_runs.insert(
            observation.provenance.run_id);
      }
    }
  }
  if ( result.matching != 0 && result.opposing != 0 )
    result.verdict = BranchClaimVerdict::MIXED;
  else if ( result.opposing != 0 )
    result.verdict = BranchClaimVerdict::COUNTEREXAMPLE;
  else if ( result.matching != 0 )
    result.verdict = BranchClaimVerdict::CORROBORATED;
  return result;
}

TargetEvidence hybrid_build_target_evidence(
    const ProgramImage &image, const FuncRange &function,
    uint64_t focus_address, const StaticAnalysisResult &static_analysis,
    const std::vector<ConcreteInput> &inputs,
    const EmulationJobResult &emulation)
{
  TargetEvidence result;
  result.scope = provenance_for(
      image, function, focus_address, emulation.ticket, 0, 0);
  result.scope.proof = ProofCharacter::CROSS_CHECK;
  result.architecture = image.arch;
  result.entry_mode = function.entry_mode;
  result.function_profile = function.profile;
  for ( const FuncChunk &chunk : function.chunks )
  {
    if ( chunk.end <= chunk.start )
      continue;
    FunctionChunkIdentity identity;
    identity.start = chunk.start;
    const size_t size = size_t(chunk.end - chunk.start);
    identity.bytes.resize(size);
    identity.loaded_mask.assign((size + 7) / 8, 0);
    for ( size_t offset = 0; offset < size; ++offset )
    {
      const uint64_t address = chunk.start + uint64_t(offset);
      const SegImage *segment = image.segment_at(address);
      if ( segment == nullptr || !segment->byte_loaded(address) )
        continue;
      identity.bytes[offset] =
          segment->bytes[size_t(address - segment->start)];
      identity.loaded_mask[offset / 8] |= uint8_t(1u << (offset & 7));
    }
    result.function_identity.push_back(std::move(identity));
  }
  result.static_analysis = static_analysis;
  result.inputs = inputs;
  result.events = emulation.merged;
  result.diagnostic = emulation.diagnostic;

  result.summary.ida_instruction_heads = static_analysis.stats.instruction_heads;
  result.summary.static_instructions = static_analysis.stats.canonical_instructions != 0
      ? static_analysis.stats.canonical_instructions
      : static_analysis.instructions.size();
  result.summary.ida_macro_heads = static_analysis.stats.ida_macro_heads;
  result.summary.ida_macro_components = static_analysis.stats.ida_macro_components;
  result.summary.decoder_disagreements =
      static_analysis.stats.mismatched_instructions;
  result.summary.decoder_disagreement_flags =
      static_analysis.stats.size_disagreements
    + static_analysis.stats.flow_disagreements
    + static_analysis.stats.target_disagreements
    + static_analysis.stats.fallthrough_disagreements;
  result.summary.decoder_comparisons = static_analysis.stats.decoder_comparisons;
  result.summary.decoder_size_disagreements = static_analysis.stats.size_disagreements;
  result.summary.decoder_flow_disagreements = static_analysis.stats.flow_disagreements;
  result.summary.decoder_target_disagreements = static_analysis.stats.target_disagreements;
  result.summary.decoder_fallthrough_disagreements =
      static_analysis.stats.fallthrough_disagreements;
  for ( const StaticInstructionEvidence &instruction : static_analysis.instructions )
    result.summary.smir_effects += instruction.smir.effects.size();

  result.runs.reserve(emulation.runs.size());
  for ( const EmulationRunResult &run : emulation.runs )
  {
    RunObservation observation;
    observation.ran = run.ran;
    observation.outcome = run.outcome;
    observation.provenance = provenance_for(
        image, function, focus_address, emulation.ticket, run.run_id, run.seed);
    result.runs.push_back(std::move(observation));
    if ( run.ran )
      ++result.summary.completed_runs;
    if ( run.ran && run.outcome.returned )
      ++result.summary.returned_runs;
    if ( run.ran && run.outcome.definitive_terminal() )
      ++result.summary.definitive_terminal_runs;
    if ( run.ran && run.outcome.stop_reason == RAX_STOP_COUNT )
      ++result.summary.instruction_budget_runs;
    if ( run.ran && run.outcome.stop_reason == RAX_STOP_TIMEOUT )
      ++result.summary.timeout_runs;
    if ( run.ran && run.outcome.escaped_image )
      ++result.summary.escaped_image_runs;
    if ( run.ran && run.outcome.function_boundary )
      ++result.summary.function_boundary_runs;
    if ( run.ran && run.outcome.unmodeled_external )
      ++result.summary.unmodeled_external_runs;
    if ( run.ran && run.outcome.environment_model_failure )
      ++result.summary.environment_model_failure_runs;
    if ( run.ran && run.outcome.external_model_used )
      ++result.summary.external_model_runs;
    if ( run.ran && run.outcome.synthetic_entry_context )
      ++result.summary.synthetic_entry_context_runs;
    if ( run.ran && !run.outcome.attempted_steps_valid )
      ++result.summary.attempted_steps_unknown_runs;
    result.summary.summarized_calls += run.outcome.summarized_calls;
    if ( run.outcome.permission_violation )
      ++result.summary.permission_violating_runs;
    if ( run.ran && run.outcome.memory_observation_requested )
      ++result.summary.memory_observation_requested_runs;
    if ( run.ran && run.outcome.memory_observation_available )
      ++result.summary.memory_observation_available_runs;
    if ( run.ran && !run.outcome.consumed_context_complete )
      ++result.summary.context_incomplete_runs;
  }

  // Preserve exact context actually consumed by the concrete traces. Code-hook
  // sizes cover only the selected function; image reads cover global tables,
  // strings, and summary-modeled memory. Repeated loop accesses collapse into
  // segment-local intervals before bytes are copied.
  std::vector<DependencyRange> dependencies;
  dependencies.reserve(result.events.execution.size() + result.events.data.size());
  for ( const ExecPoint &point : result.events.execution )
    append_dependency_range(dependencies, image, point.pc,
                            point.size == 0 ? 1 : point.size);
  for ( const ConsumedImageRange &access : result.events.consumed_image_reads )
    append_dependency_range(dependencies, image, access.addr, access.size);
  std::sort(dependencies.begin(), dependencies.end(),
            [](const DependencyRange &left, const DependencyRange &right)
  {
    return std::tie(left.start, left.end) < std::tie(right.start, right.end);
  });
  std::vector<DependencyRange> merged_dependencies;
  for ( const DependencyRange &range : dependencies )
  {
    const SegImage *segment = image.segment_at(range.start);
    const SegImage *prior_segment = merged_dependencies.empty()
        ? nullptr : image.segment_at(merged_dependencies.back().start);
    if ( !merged_dependencies.empty() && segment == prior_segment
      && range.start <= merged_dependencies.back().end )
    {
      merged_dependencies.back().end =
          std::max(merged_dependencies.back().end, range.end);
    }
    else
    {
      merged_dependencies.push_back(range);
    }
  }
  result.context_identity.reserve(merged_dependencies.size());
  for ( const DependencyRange &range : merged_dependencies )
  {
    ContextRangeIdentity identity = capture_context_identity(
        image, range.start, range.end);
    result.summary.context_identity_bytes += identity.bytes.size();
    result.context_identity.push_back(std::move(identity));
  }
  result.summary.context_identity_ranges = result.context_identity.size();

  std::unordered_set<uint64_t> canonical_static;
  canonical_static.reserve(static_analysis.instructions.size());
  for ( const StaticInstructionEvidence &instruction : static_analysis.instructions )
    canonical_static.insert(instruction.address);
  std::unordered_set<uint64_t> executed;
  std::unordered_set<uint64_t> executed_without_static;
  for ( const ExecPoint &point : result.events.execution )
    if ( function.contains(point.pc) )
    {
      if ( canonical_static.count(point.pc) != 0 )
        executed.insert(point.pc);
      else
        executed_without_static.insert(point.pc);
    }
  result.summary.executed_instruction_addresses = executed.size();
  result.summary.executed_addresses_without_static_record =
      executed_without_static.size();
  for ( const StatePoint &state : result.events.states )
    if ( state.kind == StatePoint::Kind::PredicateInput )
      ++result.summary.predicate_state_inputs;

  // Conditional outcomes are reconstructed from successive code hooks. Event
  // sequence numbers need not be adjacent because memory hooks share the same
  // counter; vector order within a run is the relevant total code order.
  std::map<std::pair<uint32_t, uint64_t>, std::vector<const ExecPoint *>> by_run;
  std::map<std::pair<uint32_t, uint64_t>, bool> complete_context_by_run;
  for ( const EmulationRunResult &run : emulation.runs )
    complete_context_by_run[{ run.run_id, run.seed }] =
        run.outcome.consumed_context_complete;
  for ( const ExecPoint &point : result.events.execution )
    by_run[{ point.run_id, point.seed }].push_back(&point);
  for ( auto &entry : by_run )
  {
    auto &points = entry.second;
    std::sort(points.begin(), points.end(), [](const ExecPoint *left,
                                              const ExecPoint *right)
    {
      return std::tie(left->sequence, left->pc)
           < std::tie(right->sequence, right->pc);
    });
    for ( size_t index = 0; index + 1 < points.size(); ++index )
    {
      const ExecPoint &current = *points[index];
      const ExecPoint &next = *points[index + 1];
      const StaticInstructionEvidence *instruction =
          static_analysis.find(current.pc);
      uint64_t target = 0;
      uint64_t fallthrough = 0;
      if ( instruction == nullptr
        || !conditional_projection(*instruction, &target, &fallthrough) )
        continue;
      BranchObservation branch;
      branch.instruction = current.pc;
      branch.encoded_target = target;
      branch.fallthrough = fallthrough;
      branch.observed_successor = next.pc;
      branch.sequence = current.sequence;
      branch.consumed_context_complete =
          complete_context_by_run[{ current.run_id, current.seed }];
      branch.provenance = provenance_for(
          image, function, focus_address, emulation.ticket,
          current.run_id, current.seed);
      branch.disposition = next.pc == target ? BranchDisposition::TAKEN
                         : next.pc == fallthrough ? BranchDisposition::FALLTHROUGH
                                                 : BranchDisposition::OTHER_SUCCESSOR;
      result.branches.push_back(std::move(branch));
    }
  }
  std::sort(result.branches.begin(), result.branches.end(),
            [](const BranchObservation &left, const BranchObservation &right)
  {
    return std::tie(left.instruction, left.provenance.run_id,
                    left.provenance.seed, left.sequence,
                    left.observed_successor)
         < std::tie(right.instruction, right.provenance.run_id,
                    right.provenance.seed, right.sequence,
                    right.observed_successor);
  });
  result.summary.conditional_observations = result.branches.size();
  {
    std::set<uint64_t> sites;
    for ( const BranchObservation &branch : result.branches )
      sites.insert(branch.instruction);
    result.summary.conditional_sites = sites.size();
  }

  for ( const ExecEdge &edge : result.events.edges )
  {
    if ( edge.kind == ExecEdge::Kind::Unknown
      || !function.contains(edge.from)
      || !static_indirect_at(static_analysis, edge.from) )
      continue;
    result.indirect_targets.push_back(IndirectTargetObservation{
        edge.from, edge.to, edge.kind,
        provenance_for(image, function, focus_address, emulation.ticket,
                       edge.run_id, edge.seed) });
  }
  std::sort(result.indirect_targets.begin(), result.indirect_targets.end(),
            [](const IndirectTargetObservation &left,
               const IndirectTargetObservation &right)
  {
    return std::tie(left.instruction, left.target, left.provenance.run_id,
                    left.provenance.seed)
         < std::tie(right.instruction, right.target, right.provenance.run_id,
                    right.provenance.seed);
  });
  result.summary.indirect_targets = result.indirect_targets.size();
  {
    std::set<uint64_t> sites;
    std::set<std::pair<uint64_t, uint64_t>> targets;
    for ( const IndirectTargetObservation &target : result.indirect_targets )
    {
      sites.insert(target.instruction);
      targets.insert({ target.instruction, target.target });
    }
    result.summary.indirect_sites = sites.size();
    result.summary.unique_indirect_targets = targets.size();
  }

  for ( const DataAcc &access : result.events.data )
  {
    if ( access.scope != DataScope::IMAGE )
      continue;
    if ( access.kind == RAX_MEM_WRITE )
      ++result.summary.image_writes;
    else if ( access.kind == RAX_MEM_READ )
    {
      ++result.summary.image_reads;
      if ( image.contains(access.value) )
      {
        ++result.summary.pointer_value_reads;
        if ( image.executable(access.value) )
          ++result.summary.executable_pointer_reads;
      }
    }
  }
  for ( const MemoryBytes &bytes : result.events.final_writes )
  {
    if ( bytes.scope == DataScope::IMAGE )
    {
      ++result.summary.final_write_ranges;
      if ( image.executable(bytes.addr) )
        ++result.summary.self_modifying_ranges;
    }
  }
  return result;
}

const char *hybrid_branch_verdict_name(BranchClaimVerdict verdict)
{
  switch ( verdict )
  {
    case BranchClaimVerdict::NO_OBSERVATION: return "no-observation";
    case BranchClaimVerdict::CORROBORATED: return "corroborated";
    case BranchClaimVerdict::COUNTEREXAMPLE: return "counterexample";
    case BranchClaimVerdict::MIXED: return "mixed";
    default: return "unknown";
  }
}

} // namespace chernobog::hybrid
