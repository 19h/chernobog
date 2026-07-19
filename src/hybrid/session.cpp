#include "session.hpp"

#include "call_summary.hpp"
#include "emulation_rax_executor.hpp"
#include "entry_state.hpp"
#include "evidence.hpp"
#include "hybrid_config.hpp"
#include "program_model.hpp"
#include "rax_loader.hpp"
#include "static_analysis.hpp"
#include "z3_bridge.hpp"
#include "../ida_analysis/evidence_apply.hpp"
#include "../plugin/component_registry.h"

#include <pro.h>
#include <ida.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <iterator>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace chernobog::hybrid {
namespace {

std::mutex &sessions_mutex()
{
  static std::mutex value;
  return value;
}

std::map<int64_t, Session *> &sessions()
{
  static std::map<int64_t, Session *> value;
  return value;
}

uint64_t model_seed(const Z3ModelReplayRequest &request)
{
  uint64_t hash = UINT64_C(14695981039346656037);
  auto add = [&](uint64_t value)
  {
    for ( unsigned shift = 0; shift < 64; shift += 8 )
      hash = (hash ^ uint8_t(value >> shift)) * UINT64_C(1099511628211);
  };
  add(request.function_start);
  add(request.claim_address);
  for ( uint64_t argument : request.arguments )
    add(argument);
  return hash == 0 ? UINT64_C(0xA0761D6478BD642F) : hash;
}

const char *job_status_name(EmulationJobStatus status)
{
  switch ( status )
  {
    case EmulationJobStatus::COMPLETED: return "completed";
    case EmulationJobStatus::CANCELLED: return "cancelled";
    case EmulationJobStatus::UNAVAILABLE: return "unavailable";
    case EmulationJobStatus::FAILED: return "failed";
    default: return "unknown";
  }
}

const char *edge_kind_name(ExecEdge::Kind kind)
{
  switch ( kind )
  {
    case ExecEdge::Kind::Call: return "call";
    case ExecEdge::Kind::Jump: return "jump";
    case ExecEdge::Kind::Return: return "return";
    default: return "unknown";
  }
}

const char *function_flavor_name(HybridFunctionFlavor flavor)
{
  switch ( flavor )
  {
    case HybridFunctionFlavor::NATIVE: return "native";
    case HybridFunctionFlavor::OBJC_INSTANCE: return "objc-instance";
    case HybridFunctionFlavor::OBJC_CLASS: return "objc-class";
    default: return "unknown";
  }
}

ea_t action_target_address(const action_ctx_base_t *context)
{
  // In text mode an explicit batch address is authoritative. The screen EA
  // can retain an unrelated loader/autoanalysis location, so consulting it
  // first would silently analyze a different function than the caller named.
  if ( batch )
  {
    qstring raw;
    if ( !qgetenv("CHERNOBOG_RAX_BATCH_EA", &raw) || raw.empty() )
      return BADADDR;
    errno = 0;
    char *end = nullptr;
    // The MSVC UCRT maps the C name to global `_strtoui64`; qualifying it
    // with `std::` after IDA/Windows headers is therefore not portable.
    const unsigned long long parsed = ::strtoull(raw.c_str(), &end, 0);
    if ( errno != 0 || end == raw.c_str() || *end != '\0' )
      return BADADDR;
    return ea_t(parsed);
  }
  if ( context != nullptr && context->cur_ea != BADADDR )
    return context->cur_ea;
  const ea_t screen = get_screen_ea();
  if ( screen != BADADDR )
    return screen;
  return BADADDR;
}

std::string printable_preview(const std::vector<uint8_t> &bytes)
{
  std::string result;
  for ( uint8_t byte : bytes )
  {
    if ( byte == 0 )
      break;
    if ( byte < 0x20 || byte > 0x7E )
      return {};
    if ( result.size() == 80 )
    {
      result += "...";
      break;
    }
    result.push_back(char(byte));
  }
  return result.size() >= 4 ? result : std::string{};
}

struct WaitBox
{
  WaitBox() { show_wait_box("Exploring current function with rax..."); }
  ~WaitBox() { hide_wait_box(); }
};

} // namespace

struct Session::Impl
{
  explicit Impl(Session *owner_value) : owner(owner_value) {}

  Session *owner = nullptr;
  HybridConfig config;
  uint64_t generation = 0;
  std::shared_ptr<const ProgramImage> image;
  FuncRange function;
  uint64_t focus_address = 0;
  StaticAnalysisResult static_analysis;
  std::vector<ConcreteInput> inputs;
  EmulationJobResult accumulated;
  std::unique_ptr<EmulationWorkerPool> worker;
  std::shared_ptr<const TargetEvidence> evidence;
  qtimer_t timer = nullptr;
  uint64_t pending_ticket = 0;
  uint32_t next_run_id = 0;
  bool pending = false;
  bool summary_reported = false;
  bool analysis_changed = false;
  uint64_t reported_generation = 0;
  size_t reported_run_count = 0;

  static int idaapi timer_callback(void *user)
  {
    Impl *self = static_cast<Impl *>(user);
    return self == nullptr ? -1 : self->poll();
  }

  void unregister_poll_timer()
  {
    if ( timer != nullptr )
    {
      unregister_timer(timer);
      timer = nullptr;
    }
  }

  bool start_timer()
  {
    if ( timer != nullptr )
      return true;
    timer = register_timer(config.poll_ms, timer_callback, this);
    return timer != nullptr;
  }

  void reset_worker()
  {
    unregister_poll_timer();
    if ( worker )
    {
      worker->cancel_pending();
      worker->shutdown();
      worker.reset();
    }
    pending = false;
    pending_ticket = 0;
  }

  void append_result(EmulationJobResult result)
  {
    if ( accumulated.ticket == 0 )
      accumulated.ticket = result.ticket;
    accumulated.function_start = result.function_start;
    accumulated.status = result.status;
    accumulated.diagnostic = result.diagnostic;
    accumulated.merged.merge_from(result.merged);
    accumulated.merged.normalize();
    for ( EmulationRunResult &run : result.runs )
      accumulated.runs.push_back(std::move(run));

    std::shared_ptr<const TargetEvidence> candidate =
        std::make_shared<TargetEvidence>(hybrid_build_target_evidence(
            *image, function, focus_address, static_analysis, inputs, accumulated));
    if ( hybrid_publish_evidence(owner->database_id(), candidate) )
    {
      evidence = std::move(candidate);
      // Completion polling and bounded synchronous waits both execute on
      // IDA's main thread. Project only fresh evidence after publication, so
      // every IDB mutation retains the exact function/context identity check.
      const chernobog::ida_analysis::EvidenceApplyStats applied =
          chernobog::ida_analysis::apply_evidence_to_ida(*evidence);
      analysis_changed = analysis_changed || applied.total() != 0;
    }
    else
    {
      evidence.reset();
      msg("[chernobog][rax] Discarded completed evidence: function or consumed context bytes changed\n");
    }
  }

  void report(bool verbose)
  {
    if ( !evidence )
    {
      msg("[chernobog][rax] No evidence is available for the current database\n");
      return;
    }
    const EvidenceSummary &summary = evidence->summary;
    const bool already_reported = summary_reported
        && reported_generation == evidence->scope.generation
        && reported_run_count == evidence->runs.size();
    if ( !verbose || !already_reported )
    {
      const size_t coverage_hundredths = summary.static_instructions == 0
          ? 0 : (summary.executed_instruction_addresses * size_t(10000))
              / summary.static_instructions;
      msg("[chernobog][rax] function=%a focus=%a generation=%llu "
          "job=%s runs_ran=%zu/%zu inputs=%zu\n",
          ea_t(evidence->scope.function_start), ea_t(evidence->scope.focus_address),
          static_cast<unsigned long long>(evidence->scope.generation),
          job_status_name(accumulated.status), summary.completed_runs,
          evidence->runs.size(), evidence->inputs.size());
      const HybridFunctionProfile &profile = evidence->function_profile;
      msg("[chernobog][rax] entry: flavor=%s name=%s selector=%s "
          "explicit_args=%zu (%s) hidden_args=%zu\n",
          function_flavor_name(profile.flavor),
          profile.name.empty() ? "<unnamed>" : profile.name.c_str(),
          profile.objc_selector.empty() ? "<none>" : profile.objc_selector.c_str(),
          profile.explicit_arguments,
          profile.explicit_arguments_known ? "known" : "unknown",
          profile.implicit_arguments());
      msg("[chernobog][rax] outcomes: returned=%zu terminal=%zu "
          "budget=%zu timeout=%zu escaped=%zu function_boundary=%zu "
          "unmodeled_external=%zu "
          "model_failure=%zu permission=%zu external_model_runs=%zu "
          "synthetic_entry_runs=%zu attempted_unknown=%zu summarized_calls=%zu\n",
          summary.returned_runs, summary.definitive_terminal_runs,
          summary.instruction_budget_runs, summary.timeout_runs,
          summary.escaped_image_runs, summary.function_boundary_runs,
          summary.unmodeled_external_runs,
          summary.environment_model_failure_runs,
          summary.permission_violating_runs, summary.external_model_runs,
          summary.synthetic_entry_context_runs,
          summary.attempted_steps_unknown_runs, summary.summarized_calls);
      msg("[chernobog][rax] coverage: physical=%zu/%zu (%zu.%02zu%%) "
          "unmatched_executed=%zu; branches=%zu sites/%zu observations "
          "predicate_inputs=%zu; indirect=%zu sites/%zu unique targets/%zu observations\n",
          summary.executed_instruction_addresses, summary.static_instructions,
          coverage_hundredths / 100, coverage_hundredths % 100,
          summary.executed_addresses_without_static_record,
          summary.conditional_sites, summary.conditional_observations,
          summary.predicate_state_inputs, summary.indirect_sites,
          summary.unique_indirect_targets, summary.indirect_targets);
      msg("[chernobog][rax] static: IDA_heads=%zu physical=%zu "
          "macro_heads=%zu macro_components=%zu smir_effects=%zu; "
          "decoder=%zu compared/%zu mismatched/%zu flags "
          "(size=%zu flow=%zu target=%zu fallthrough=%zu)\n",
          summary.ida_instruction_heads, summary.static_instructions,
          summary.ida_macro_heads, summary.ida_macro_components,
          summary.smir_effects, summary.decoder_comparisons,
          summary.decoder_disagreements, summary.decoder_disagreement_flags,
          summary.decoder_size_disagreements,
          summary.decoder_flow_disagreements,
          summary.decoder_target_disagreements,
          summary.decoder_fallthrough_disagreements);
      msg("[chernobog][rax] memory: observation_available=%zu/%zu "
          "requested=%zu reads=%zu writes=%zu pointer_values=%zu "
          "code_pointers=%zu final_ranges=%zu smc=%zu; "
          "context=%zu ranges/%llu bytes complete=%zu incomplete=%zu\n",
          summary.memory_observation_available_runs, summary.completed_runs,
          summary.memory_observation_requested_runs,
          summary.image_reads, summary.image_writes,
          summary.pointer_value_reads, summary.executable_pointer_reads,
          summary.final_write_ranges, summary.self_modifying_ranges,
          summary.context_identity_ranges,
          static_cast<unsigned long long>(summary.context_identity_bytes),
          summary.completed_runs - std::min(summary.completed_runs,
                                            summary.context_incomplete_runs),
          summary.context_incomplete_runs);
      if ( !evidence->diagnostic.empty() )
        msg("[chernobog][rax] diagnostic: %s\n", evidence->diagnostic.c_str());
      summary_reported = true;
      reported_generation = evidence->scope.generation;
      reported_run_count = evidence->runs.size();
    }
    if ( !verbose )
      return;

    size_t shown = 0;
    for ( const RunObservation &run : evidence->runs )
    {
      msg("[chernobog][rax] run=%u seed=0x%llX ran=%s outcome=%s "
          "rax_stop=%s(%d) stop_pc=%a stop_metadata=%s "
          "retired=%llu attempted=%llu%s summaries=%u external_model=%s "
          "entry_context=%s memory=%s context=%s "
          "sp_delta=%lld%s\n",
          run.provenance.run_id,
          static_cast<unsigned long long>(run.provenance.seed),
          run.ran ? "yes" : "no", hybrid_emu_outcome_name(run.outcome),
          hybrid_rax_stop_reason_name(run.outcome.stop_reason),
          run.outcome.stop_reason, ea_t(run.outcome.stop_pc),
          run.outcome.stop_valid ? "available" : "unavailable",
          static_cast<unsigned long long>(run.outcome.instruction_count),
          static_cast<unsigned long long>(run.outcome.attempted_steps),
          run.outcome.attempted_steps_valid ? "" : " (partial/unknown)",
          run.outcome.summarized_calls,
          run.outcome.external_model_used ? "used" : "none",
          run.outcome.synthetic_entry_context ? "synthetic" : "observed/native",
          run.outcome.memory_observation_available ? "available"
            : run.outcome.memory_observation_requested ? "unavailable" : "disabled",
          run.outcome.consumed_context_complete ? "complete" : "incomplete",
          static_cast<long long>(run.outcome.sp_delta),
          run.outcome.sp_valid ? "" : " (unknown)");
      if ( run.outcome.function_boundary )
      {
        msg("[chernobog][rax] run=%u function-boundary kind=%s source=%a target=%a "
            "(target instruction not executed)\n",
            run.provenance.run_id,
            edge_kind_name(run.outcome.function_boundary_kind),
            ea_t(run.outcome.function_boundary_source),
            ea_t(run.outcome.function_boundary_target));
      }
      if ( run.outcome.stop_reason == RAX_STOP_ERROR )
      {
        msg("[chernobog][rax] run=%u engine-status=%s(%d)%s%s\n",
            run.provenance.run_id,
            hybrid_rax_status_name(run.outcome.stop_status),
            run.outcome.stop_status,
            run.outcome.engine_error.empty() ? "" : " detail=",
            run.outcome.engine_error.c_str());
      }
      const auto input = std::find_if(
          evidence->inputs.begin(), evidence->inputs.end(),
          [&](const ConcreteInput &candidate)
          { return candidate.input.run_id == run.provenance.run_id; });
      if ( input != evidence->inputs.end() )
      {
        msg("[chernobog][rax] run=%u input=%s positional_args=%zu "
            "offset=%u abi_overrides=%zu register_overrides=%zu "
            "stack_args=%zu\n",
            run.provenance.run_id,
            input->label.empty() ? "<unlabeled>" : input->label.c_str(),
            input->input.args.size(), input->input.positional_argument_offset,
            input->input.arg_overrides.size(),
            input->input.register_overrides.size(),
            input->input.stack_args.size());
        if ( !input->input.args.empty() )
        {
          msg("[chernobog][rax] run=%u source-args", run.provenance.run_id);
          const size_t limit = std::min<size_t>(input->input.args.size(), 8);
          for ( size_t index = 0; index < limit; ++index )
            msg(" [%zu]=0x%llX", index,
                static_cast<unsigned long long>(input->input.args[index]));
          if ( limit != input->input.args.size() )
            msg(" ... (%zu total)", input->input.args.size());
          msg("\n");
        }
        if ( !input->input.arg_overrides.empty() )
        {
          msg("[chernobog][rax] run=%u physical-abi-overrides",
              run.provenance.run_id);
          const size_t limit = std::min<size_t>(
              input->input.arg_overrides.size(), 8);
          for ( size_t index = 0; index < limit; ++index )
          {
            const EmuInput::ArgOverride &argument =
                input->input.arg_overrides[index];
            msg(" [%u]=0x%llX", argument.index,
                static_cast<unsigned long long>(argument.value));
          }
          if ( limit != input->input.arg_overrides.size() )
            msg(" ... (%zu total)", input->input.arg_overrides.size());
          msg("\n");
        }
      }
      if ( run.outcome.unmodeled_external
        || run.outcome.environment_model_failure )
      {
        msg("[chernobog][rax] run=%u external target=%a name=%s model=%s\n",
            run.provenance.run_id, ea_t(run.outcome.external_target),
            run.outcome.external_name.empty()
              ? "<unknown>" : run.outcome.external_name.c_str(),
            run.outcome.environment_model_failure ? "failed" : "unmodeled");
      }
      if ( run.outcome.escaped_image )
        msg("[chernobog][rax] run=%u escaped snapshotted image from=%a to=%a\n",
            run.provenance.run_id, ea_t(run.outcome.escape_source),
            ea_t(run.outcome.stop_pc));
      if ( ++shown == 20 )
        break;
    }

    shown = 0;
    for ( const StaticInstructionEvidence &instruction :
          evidence->static_analysis.instructions )
    {
      const DecoderComparison &comparison = instruction.comparison;
      if ( !comparison.comparable
        || (!comparison.size_disagreement && !comparison.flow_disagreement
         && !comparison.target_disagreement
         && !comparison.fallthrough_disagreement) )
        continue;
      msg("[chernobog][rax] decoder-diff %a: IDA(size=%u flow=%s) "
          "rax(size=%u flow=%s)\n",
          ea_t(instruction.address), instruction.ida.size,
          hybrid_decoder_flow_name(instruction.ida.flow),
          instruction.rax.instruction.size,
          hybrid_decoder_flow_name(instruction.rax.instruction.flow));
      if ( ++shown == 12 )
        break;
    }

    std::map<std::tuple<uint64_t, uint64_t, BranchDisposition>, size_t> branches;
    for ( const BranchObservation &branch : evidence->branches )
      ++branches[{ branch.instruction, branch.observed_successor,
                   branch.disposition }];
    shown = 0;
    for ( const auto &entry : branches )
    {
      const auto [instruction, successor, disposition] = entry.first;
      const char *name = disposition == BranchDisposition::TAKEN ? "taken"
                       : disposition == BranchDisposition::FALLTHROUGH
                           ? "fallthrough" : "other";
      msg("[chernobog][rax] branch %a -> %a: %s (%zu observations)\n",
          ea_t(instruction), ea_t(successor), name, entry.second);
      if ( ++shown == 20 )
        break;
    }

    std::map<std::pair<uint64_t, uint64_t>, size_t> indirect;
    for ( const IndirectTargetObservation &target : evidence->indirect_targets )
      ++indirect[{ target.instruction, target.target }];
    shown = 0;
    for ( const auto &entry : indirect )
    {
      msg("[chernobog][rax] indirect %a -> %a (%zu observations)\n",
          ea_t(entry.first.first), ea_t(entry.first.second), entry.second);
      if ( ++shown == 20 )
        break;
    }

    shown = 0;
    for ( const MemoryBytes &written : evidence->events.final_writes )
    {
      const std::string preview = printable_preview(written.bytes);
      if ( preview.empty() )
        continue;
      msg("[chernobog][rax] runtime-bytes %a: \"%s\" "
          "(run=%u seed=0x%llX)\n",
          ea_t(written.addr), preview.c_str(), written.run_id,
          static_cast<unsigned long long>(written.seed));
      if ( ++shown == 12 )
        break;
    }
  }

  bool submit_job(EmulationJob job)
  {
    uint64_t ticket = 0;
    if ( !worker || !worker->try_submit(std::move(job), &ticket) )
      return false;
    pending_ticket = ticket;
    pending = true;
    return true;
  }

  bool submit_model_replays()
  {
    if ( pending || !worker || !image )
      return false;
    std::vector<Z3ModelReplayRequest> requests = hybrid_take_z3_model_replays(
        owner->database_id(), function.start);
    if ( requests.empty() )
      return false;
    if ( !evidence || !hybrid_current_evidence_is_fresh(function.start) )
    {
      msg("[chernobog][rax] Discarded %zu queued Z3 model replay(s): "
          "function or consumed context bytes changed\n", requests.size());
      return false;
    }

    EmulationJob job;
    job.function = function;
    job.config = config;
    std::vector<ConcreteInput> added;
    for ( const Z3ModelReplayRequest &model : requests )
    {
      EmulationRunRequest run;
      run.has_input = true;
      run.record_pcs = true;
      run.input.seed = model_seed(model);
      run.input.run_id = next_run_id++;
      run.input.positional_argument_offset =
          uint32_t(function.profile.implicit_arguments());
      run.input.args = model.arguments;
      run.seed = run.input.seed;
      run.run_id = run.input.run_id;
      job.runs.push_back(run);

      ConcreteInput input;
      input.origin = InputOrigin::Z3_MODEL;
      input.input = run.input;
      input.label = model.label.empty() ? "Z3 model" : model.label;
      added.push_back(std::move(input));
    }
    if ( submit_job(std::move(job)) )
    {
      inputs.insert(inputs.end(),
                    std::make_move_iterator(added.begin()),
                    std::make_move_iterator(added.end()));
      msg("[chernobog][rax] Submitted %zu Z3 model replay(s) for %a\n",
          requests.size(), ea_t(function.start));
      return true;
    }
    msg("[chernobog][rax] Could not submit %zu queued Z3 model replay(s) for %a\n",
        requests.size(), ea_t(function.start));
    return false;
  }

  int poll()
  {
    if ( pending && worker )
    {
      EmulationJobResult result;
      if ( worker->try_take_next(result) )
      {
        pending = false;
        pending_ticket = 0;
        append_result(std::move(result));
        report(false);
      }
    }
    if ( pending )
      return config.poll_ms;
    if ( submit_model_replays() )
      return config.poll_ms;

    // Replay requests are produced synchronously by the decompilation that
    // armed this timer. No pending job and no queued request means the polling
    // lease is over. A later fresh-evidence decompilation rearms one poll.
    timer = nullptr;
    return -1;
  }

  bool wait_for_pending(const char *purpose)
  {
    if ( !pending )
      return evidence && hybrid_current_evidence_is_fresh(function.start);
    unregister_poll_timer();
    if ( !worker )
      return false;

    const auto finish_wait = [&](bool value)
    {
      // A GUI session gets one bounded poll lease after the prerequisite so
      // replay requests produced later in this decompilation can be consumed.
      // IDALIB/text mode has no reliable UI event loop.
      if ( !batch && !is_ida_library() )
        start_timer();
      return value;
    };

    const uint64_t count = std::max<uint64_t>(1, inputs.size());
    const uint64_t raw_wait = count * (config.timeout_ms + 100) + 5000;
    const uint64_t wait_ms = std::min<uint64_t>(raw_wait, 120000);
    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(wait_ms);
    const int quantum_ms = std::max(10, std::min(config.poll_ms, 100));
    while ( pending )
    {
      const auto now = std::chrono::steady_clock::now();
      if ( now >= deadline )
      {
        msg("[chernobog][rax] %s wait expired after %llu ms; cancelling bounded job\n",
            purpose, static_cast<unsigned long long>(wait_ms));
        worker->cancel_pending();
        return finish_wait(false);
      }
      const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
          deadline - now);
      const auto quantum = std::min(
          remaining, std::chrono::milliseconds(quantum_ms));
      EmulationJobResult result;
      if ( worker->wait_take_next(result, quantum) )
      {
        pending = false;
        pending_ticket = 0;
        append_result(std::move(result));
        report(false);
        break;
      }
      if ( !batch && user_cancelled() )
      {
        msg("[chernobog][rax] Current-function prerequisite cancelled by user\n");
        worker->cancel_pending();
        return finish_wait(false);
      }
    }
    return finish_wait(
        evidence && hybrid_current_evidence_is_fresh(function.start));
  }
};

Session::Session(int64_t database_id)
  : impl_(new Impl(this)), database_id_(database_id)
{
  impl_->config = hybrid_load_config();
  std::lock_guard<std::mutex> lock(sessions_mutex());
  sessions()[database_id_] = this;
}

Session::~Session()
{
  clear();
  std::lock_guard<std::mutex> lock(sessions_mutex());
  const auto found = sessions().find(database_id_);
  if ( found != sessions().end() && found->second == this )
    sessions().erase(found);
}

bool Session::enabled() const
{
  return impl_->config.enabled;
}

bool Session::explore_batch_target()
{
  const ea_t address = action_target_address(nullptr);
  return batch && address != BADADDR
      && explore(nullptr, uint64_t(address));
}

bool Session::explore(vdui_t *view, uint64_t fallback_address)
{
  uint64_t function_start = 0;
  uint64_t focus = 0;
  if ( view != nullptr && view->cfunc )
  {
    function_start = uint64_t(view->cfunc->entry_ea);
    focus = function_start;
    if ( view->get_current_item(USE_KEYBOARD) )
    {
      const ea_t item_address = view->item.get_ea();
      if ( item_address != BADADDR )
        focus = uint64_t(item_address);
    }
  }
  else
  {
    if ( fallback_address == UINT64_MAX )
      return false;
    func_t *selected = get_func(ea_t(fallback_address));
    if ( selected == nullptr )
      return false;
    function_start = uint64_t(selected->start_ea);
    focus = fallback_address;
  }
  clear();
  impl_->config = hybrid_load_config();
  if ( !impl_->config.enabled )
  {
    msg("[chernobog][rax] Disabled by CHERNOBOG_RAX_ENABLED=0\n");
    return false;
  }
  const RaxApi *api = rax_load();
  if ( api == nullptr )
  {
    msg("[chernobog][rax] Unavailable: %s\n", rax_unavailable_reason());
    return false;
  }

  func_t *current = get_func(ea_t(focus));
  if ( current == nullptr || uint64_t(current->start_ea) != function_start )
    focus = function_start;

  WaitBox wait;
  auto mutable_image = std::make_shared<ProgramImage>();
  mutable_image->generation = impl_->generation;
  const ProgramSnapshotStats snapshot = hybrid_snapshot_function(
      *mutable_image, impl_->config, function_start);
  if ( !snapshot.complete || mutable_image->entries.size() != 1 )
  {
    msg("[chernobog][rax] Snapshot failed for %a: %s "
        "(bytes=%llu cap=%llu)\n",
        ea_t(function_start), snapshot.diagnostic.c_str(),
        static_cast<unsigned long long>(snapshot.image_bytes_requested),
        static_cast<unsigned long long>(impl_->config.max_image_bytes));
    return false;
  }
  impl_->generation = mutable_image->generation;
  impl_->image = mutable_image;
  impl_->function = mutable_image->entries.front();
  impl_->focus_address = focus;
  impl_->static_analysis = hybrid_analyze_current_function(
      api, *mutable_image, impl_->function, impl_->config);
  if ( user_cancelled() )
  {
    msg("[chernobog][rax] Current-function exploration cancelled before execution\n");
    clear();
    return false;
  }

  EmulationJob job;
  job.function = impl_->function;
  job.config = impl_->config;
  const EntryInputPlan entry = hybrid_build_entry_inputs(
      mutable_image->arch, function_start, impl_->config.max_callsite_inputs);
  const size_t deterministic_runs = size_t(impl_->config.explore_runs);
  job.runs.reserve(deterministic_runs + entry.inputs.size());
  impl_->inputs.reserve(deterministic_runs + entry.inputs.size());
  for ( size_t index = 0; index < deterministic_runs; ++index )
  {
    EmulationRunRequest run;
    run.run_id = impl_->next_run_id++;
    run.seed = index == 0 ? 0
             : uint64_t(index) * UINT64_C(0x9E3779B97F4A7C15) + 1;
    run.record_pcs = true;
    job.runs.push_back(run);
    ConcreteInput input;
    input.origin = InputOrigin::DETERMINISTIC_SEED;
    input.input.seed = run.seed;
    input.input.run_id = run.run_id;
    input.label = "deterministic ABI seed";
    impl_->inputs.push_back(std::move(input));
  }
  for ( EmuInput input_value : entry.inputs )
  {
    EmulationRunRequest run;
    run.has_input = true;
    run.record_pcs = true;
    input_value.run_id = impl_->next_run_id++;
    run.input = input_value;
    run.run_id = input_value.run_id;
    run.seed = input_value.seed;
    job.runs.push_back(run);
    ConcreteInput input;
    input.origin = InputOrigin::CALLSITE_TRACKER;
    input.input = input_value;
    input.label = "IDA register-tracker call-site context";
    impl_->inputs.push_back(std::move(input));
  }

  const std::vector<EmuCallSummary> summaries =
      impl_->config.want_import_summaries
      ? hybrid_collect_call_summaries(
            impl_->function, impl_->config.max_static_instructions)
      : std::vector<EmuCallSummary>{};
  RaxWorkerOptions options;
  options.api = api;
  options.image = impl_->image;
  options.strict_perms = impl_->config.strict_perms;
  options.windows_x64 = hybrid_detect_abi(mutable_image->arch)
                     == HybridAbi::X86_64_WIN64;
  options.call_summaries = summaries;
  impl_->worker.reset(new EmulationWorkerPool(
      1, hybrid_make_rax_worker_factory(std::move(options)), 1));
  impl_->accumulated = EmulationJobResult{};
  impl_->summary_reported = false;
  impl_->analysis_changed = false;
  impl_->reported_generation = 0;
  impl_->reported_run_count = 0;
  if ( !impl_->submit_job(std::move(job)) )
  {
    msg("[chernobog][rax] Could not submit current-function job\n");
    clear();
    return false;
  }

  msg("[chernobog][rax] Exploring only %a (focus=%a, chunks=%zu, "
      "image=%llu bytes, deterministic=%zu, callsite=%zu, ticket=%llu)\n",
      ea_t(function_start), ea_t(focus), impl_->function.chunks.size(),
      static_cast<unsigned long long>(snapshot.image_bytes_copied),
      deterministic_runs, entry.inputs.size(),
      static_cast<unsigned long long>(impl_->pending_ticket));

  if ( batch || !impl_->start_timer() )
  {
    // Batch/headless IDA has no reliable UI event loop for poll timers. The job
    // remains bounded by the sum of its per-run caps; wait here so explicit
    // invocation deterministically produces evidence before the script exits.
    if ( !impl_->wait_for_pending("Headless") )
      return false;
  }
  return true;
}

EnsureExploredResult Session::ensure_explored(
    uint64_t function_start, uint64_t focus_address)
{
  const auto begin_projection = [&](EnsureExploredResult success)
  {
    if ( !hybrid_begin_deobfuscation_projection(function_start) )
    {
      msg("[chernobog][rax] Fresh evidence changed before the deobfuscation projection could begin at %a\n",
          ea_t(function_start));
      return EnsureExploredResult::FAILED;
    }
    // Z3 replay requests are queued later in this same synchronous Hex-Rays
    // pipeline. Consume them once the GUI event loop resumes, without keeping
    // a permanent idle timer alive between decompilations.
    if ( !batch && !is_ida_library() )
      impl_->start_timer();
    return success;
  };

  impl_->config = hybrid_load_config();
  if ( !impl_->config.enabled )
    return EnsureExploredResult::DISABLED;
  if ( hybrid_current_evidence_is_fresh(function_start) )
    return begin_projection(EnsureExploredResult::ALREADY_FRESH);
  if ( rax_load() == nullptr )
  {
    msg("[chernobog][rax] Pre-deobfuscation exploration unavailable: %s\n",
        rax_unavailable_reason());
    return EnsureExploredResult::UNAVAILABLE;
  }

  const bool matching_pending = impl_->pending
      && impl_->function.start == function_start;
  if ( !matching_pending )
  {
    const uint64_t focus = focus_address == UINT64_MAX
                         ? function_start : focus_address;
    if ( !explore(nullptr, focus) )
      return user_cancelled() ? EnsureExploredResult::CANCELLED
                              : EnsureExploredResult::FAILED;
  }
  if ( !impl_->pending )
    return hybrid_current_evidence_is_fresh(function_start)
         ? begin_projection(EnsureExploredResult::EXPLORED)
         : EnsureExploredResult::FAILED;

  WaitBox wait;
  if ( impl_->wait_for_pending("Pre-deobfuscation") )
    return begin_projection(EnsureExploredResult::EXPLORED);
  return user_cancelled() ? EnsureExploredResult::CANCELLED
                          : EnsureExploredResult::FAILED;
}

void Session::show_last(vdui_t *view) const
{
  if ( view != nullptr && view->cfunc && impl_->evidence
    && uint64_t(view->cfunc->entry_ea) != impl_->evidence->scope.function_start )
  {
    msg("[chernobog][rax] Last evidence belongs to %a, not the displayed %a\n",
        ea_t(impl_->evidence->scope.function_start), view->cfunc->entry_ea);
    return;
  }
  if ( impl_->evidence
    && !hybrid_current_evidence_is_fresh(
          impl_->evidence->scope.function_start) )
  {
    msg("[chernobog][rax] Last evidence is stale: function or consumed context bytes changed\n");
    return;
  }
  impl_->report(true);
}

void Session::cancel()
{
  if ( impl_->worker )
  {
    impl_->worker->cancel_pending();
    msg("[chernobog][rax] Cancellation requested; the current run will stop at its next instruction boundary\n");
  }
}

void Session::clear()
{
  impl_->reset_worker();
  impl_->image.reset();
  impl_->function = FuncRange{};
  impl_->focus_address = 0;
  impl_->static_analysis = StaticAnalysisResult{};
  impl_->inputs.clear();
  impl_->accumulated = EmulationJobResult{};
  impl_->evidence.reset();
  impl_->next_run_id = 0;
  impl_->summary_reported = false;
  impl_->analysis_changed = false;
  impl_->reported_generation = 0;
  impl_->reported_run_count = 0;
  hybrid_clear_evidence(database_id_);
}

void Session::invalidate_function(uint64_t function_start)
{
  if ( impl_->function.start == function_start )
    clear();
}

bool Session::take_analysis_changes()
{
  const bool changed = impl_->analysis_changed;
  impl_->analysis_changed = false;
  return changed;
}

Session *hybrid_current_session()
{
  const int64_t database_id = int64_t(get_dbctx_id());
  std::lock_guard<std::mutex> lock(sessions_mutex());
  const auto found = sessions().find(database_id);
  return found == sessions().end() ? nullptr : found->second;
}

EnsureExploredResult hybrid_ensure_current_function_explored(
    uint64_t function_start, uint64_t focus_address)
{
  Session *session = hybrid_current_session();
  return session == nullptr
       ? EnsureExploredResult::UNAVAILABLE
       : session->ensure_explored(function_start, focus_address);
}

} // namespace chernobog::hybrid

namespace {

struct hybrid_action_handler_t : public action_handler_t
{
  enum class Kind { Explore, Show, Cancel } kind;
  explicit hybrid_action_handler_t(Kind value) : kind(value) {}

  int idaapi activate(action_activation_ctx_t *context) override
  {
    if ( context == nullptr )
      return 0;
    vdui_t *view = context->widget != nullptr
                 ? get_widget_vdui(context->widget) : nullptr;
    chernobog::hybrid::Session *session =
        chernobog::hybrid::hybrid_current_session();
    if ( session == nullptr )
      return 0;
    const ea_t context_address =
        chernobog::hybrid::action_target_address(context);
    switch ( kind )
    {
      case Kind::Explore:
        return session->explore(
            view, context_address == BADADDR
                ? UINT64_MAX : uint64_t(context_address)) ? 1 : 0;
      case Kind::Show: session->show_last(view); return 1;
      case Kind::Cancel: session->cancel(); return 1;
    }
    return 0;
  }

  action_state_t idaapi update(action_update_ctx_t *context) override
  {
    if ( context == nullptr || get_hexdsp() == nullptr
      || chernobog::hybrid::hybrid_current_session() == nullptr )
      return AST_DISABLE_FOR_WIDGET;
    if ( batch )
    {
      const ea_t context_address =
          chernobog::hybrid::action_target_address(context);
      return context_address != BADADDR && get_func(context_address) != nullptr
           ? AST_ENABLE_ALWAYS : AST_DISABLE_ALWAYS;
    }
    if ( context->widget == nullptr )
      return AST_DISABLE_FOR_WIDGET;
    return get_widget_vdui(context->widget) != nullptr
         ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
  }
};

hybrid_action_handler_t explore_handler(hybrid_action_handler_t::Kind::Explore);
hybrid_action_handler_t show_handler(hybrid_action_handler_t::Kind::Show);
hybrid_action_handler_t cancel_handler(hybrid_action_handler_t::Kind::Cancel);

const action_desc_t hybrid_actions[] = {
  ACTION_DESC_LITERAL("chernobog:rax_explore",
      "Explore current function with rax", &explore_handler,
      "Ctrl+Shift+E", nullptr, -1),
  ACTION_DESC_LITERAL("chernobog:rax_show",
      "Show current-function rax evidence", &show_handler,
      nullptr, nullptr, -1),
  ACTION_DESC_LITERAL("chernobog:rax_cancel",
      "Cancel current-function rax exploration", &cancel_handler,
      nullptr, nullptr, -1),
};

size_t hybrid_action_users = 0;
bool hybrid_actions_active = false;
std::set<int64_t> hybrid_initialized_databases;

bool hybrid_available()
{
  return chernobog::hybrid::hybrid_load_config().enabled;
}

bool hybrid_active()
{
  return hybrid_initialized_databases.find(int64_t(get_dbctx_id()))
      != hybrid_initialized_databases.end();
}

void hybrid_init()
{
  if ( !hybrid_initialized_databases.insert(int64_t(get_dbctx_id())).second )
    return;
  ++hybrid_action_users;
  if ( hybrid_action_users != 1 )
    return;
  bool any = false;
  for ( const action_desc_t &action : hybrid_actions )
    any |= register_action(action);
  hybrid_actions_active = any;
}

void hybrid_done()
{
  const auto initialized =
      hybrid_initialized_databases.find(int64_t(get_dbctx_id()));
  if ( initialized == hybrid_initialized_databases.end() )
    return;
  hybrid_initialized_databases.erase(initialized);
  if ( hybrid_action_users == 0 )
    return;
  --hybrid_action_users;
  if ( hybrid_action_users != 0 )
    return;
  if ( hybrid_actions_active )
    for ( const action_desc_t &action : hybrid_actions )
      unregister_action(action.name);
  hybrid_actions_active = false;
}

void hybrid_attach_popup(TWidget *widget, TPopupMenu *popup, vdui_t *view)
{
  if ( view == nullptr )
    return;
  for ( const action_desc_t &action : hybrid_actions )
    attach_action_to_popup(widget, popup, action.name);
}

REGISTER_COMPONENT(
    hybrid_available,
    hybrid_active,
    hybrid_init,
    hybrid_done,
    hybrid_attach_popup,
    "Current-function rax exploration",
    rax_hybrid,
    rax_hybrid)

} // namespace
