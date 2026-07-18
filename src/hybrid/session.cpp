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
#include "../plugin/component_registry.h"

#include <pro.h>
#include <ida.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>

#include <algorithm>
#include <chrono>
#include <cctype>
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
      msg("[chernobog][rax] outcomes: returned=%zu terminal=%zu "
          "budget=%zu timeout=%zu escaped=%zu unmodeled_external=%zu "
          "model_failure=%zu permission=%zu external_model_runs=%zu "
          "synthetic_entry_runs=%zu attempted_unknown=%zu summarized_calls=%zu\n",
          summary.returned_runs, summary.definitive_terminal_runs,
          summary.instruction_budget_runs, summary.timeout_runs,
          summary.escaped_image_runs, summary.unmodeled_external_runs,
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

  void submit_model_replays()
  {
    if ( pending || !worker || !image || !evidence )
      return;
    if ( !hybrid_current_evidence_is_fresh(function.start) )
    {
      hybrid_take_z3_model_replays(owner->database_id(), function.start);
      msg("[chernobog][rax] Discarded queued Z3 model replay: function or consumed context bytes changed\n");
      return;
    }
    std::vector<Z3ModelReplayRequest> requests = hybrid_take_z3_model_replays(
        owner->database_id(), function.start);
    if ( requests.empty() )
      return;

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
    }
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
    if ( !pending )
      submit_model_replays();
    return pending ? config.poll_ms : 250;
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

bool Session::explore(vdui_t *view)
{
  if ( view == nullptr || !view->cfunc )
    return false;
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

  const uint64_t function_start = uint64_t(view->cfunc->entry_ea);
  uint64_t focus = function_start;
  if ( view->get_current_item(USE_KEYBOARD) )
  {
    const ea_t item_address = view->item.get_ea();
    if ( item_address != BADADDR )
      focus = uint64_t(item_address);
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

  if ( !impl_->start_timer() )
  {
    // Headless IDA has no UI timer. The job remains bounded by the sum of its
    // per-run caps; wait here so explicit invocation still produces evidence.
    const uint64_t count = uint64_t(deterministic_runs + entry.inputs.size());
    const uint64_t raw_wait = count * (impl_->config.timeout_ms + 100) + 5000;
    const uint64_t wait_ms = std::min<uint64_t>(raw_wait, 120000);
    EmulationJobResult result;
    if ( impl_->worker->wait_take_next(
          result, std::chrono::milliseconds(wait_ms)) )
    {
      impl_->pending = false;
      impl_->pending_ticket = 0;
      impl_->append_result(std::move(result));
      impl_->report(false);
    }
    else
    {
      msg("[chernobog][rax] Headless wait expired; cancelling bounded job\n");
      impl_->worker->cancel_pending();
      return false;
    }
  }
  return true;
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
  impl_->reported_generation = 0;
  impl_->reported_run_count = 0;
  hybrid_clear_evidence(database_id_);
}

void Session::invalidate_function(uint64_t function_start)
{
  if ( impl_->function.start == function_start )
    clear();
}

Session *hybrid_current_session()
{
  const int64_t database_id = int64_t(get_dbctx_id());
  std::lock_guard<std::mutex> lock(sessions_mutex());
  const auto found = sessions().find(database_id);
  return found == sessions().end() ? nullptr : found->second;
}

} // namespace chernobog::hybrid

namespace {

struct hybrid_action_handler_t : public action_handler_t
{
  enum class Kind { Explore, Show, Cancel } kind;
  explicit hybrid_action_handler_t(Kind value) : kind(value) {}

  int idaapi activate(action_activation_ctx_t *context) override
  {
    if ( context == nullptr || context->widget == nullptr )
      return 0;
    vdui_t *view = get_widget_vdui(context->widget);
    chernobog::hybrid::Session *session =
        chernobog::hybrid::hybrid_current_session();
    if ( session == nullptr )
      return 0;
    switch ( kind )
    {
      case Kind::Explore: return session->explore(view) ? 1 : 0;
      case Kind::Show: session->show_last(view); return 1;
      case Kind::Cancel: session->cancel(); return 1;
    }
    return 0;
  }

  action_state_t idaapi update(action_update_ctx_t *context) override
  {
    if ( context == nullptr || context->widget == nullptr || get_hexdsp() == nullptr )
      return AST_DISABLE_FOR_WIDGET;
    return get_widget_vdui(context->widget) != nullptr
        && chernobog::hybrid::hybrid_current_session() != nullptr
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
