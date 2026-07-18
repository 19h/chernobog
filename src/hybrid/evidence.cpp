#include "evidence.hpp"

#include <algorithm>
#include <limits>
#include <map>
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
  if ( item.ida.valid && item.ida.flow == RAX_FLOW_COND_BRANCH
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
  return item->ida.indirect
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

bool TargetEvidence::matches(uint64_t function_start,
                             uint64_t function_hash) const
{
  return scope.function_start == function_start
      && scope.function_hash == function_hash;
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

  result.summary.static_instructions = static_analysis.instructions.size();
  result.summary.decoder_disagreements =
      static_analysis.stats.size_disagreements
    + static_analysis.stats.flow_disagreements
    + static_analysis.stats.target_disagreements
    + static_analysis.stats.fallthrough_disagreements;
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
    if ( run.outcome.permission_violation )
      ++result.summary.permission_violating_runs;
    if ( run.ran && !run.outcome.consumed_context_complete )
      ++result.summary.context_incomplete_runs;
  }

  // Preserve exact context actually consumed by the concrete traces. Code-hook
  // sizes cover instruction fetches (including callees); image reads cover
  // global tables, strings, and summary-modeled memory. Repeated loop accesses
  // collapse into segment-local intervals before bytes are copied.
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

  std::unordered_set<uint64_t> executed;
  for ( const ExecPoint &point : result.events.execution )
    if ( function.contains(point.pc) )
      executed.insert(point.pc);
  result.summary.executed_instruction_addresses = executed.size();
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
