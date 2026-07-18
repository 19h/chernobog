#include "emulation_rax_executor.hpp"

#include <set>
#include <tuple>
#include <utility>

namespace chernobog::hybrid {

namespace {

bool cancellation_probe(const void *user)
{
  const EmulationCancellation *token =
      static_cast<const EmulationCancellation *>(user);
  return token == nullptr || token->cancelled();
}

class RaxEmulationExecutor final : public EmulationExecutor
{
public:
  explicit RaxEmulationExecutor(const RaxWorkerOptions &options)
    : image_(options.image)
  {
    if ( options.api == nullptr )
    {
      unavailable_ = "rax API is unavailable";
      return;
    }
    if ( image_ == nullptr )
    {
      unavailable_ = "program image snapshot is unavailable";
      return;
    }
    driver_.reset(new EmuDriver(options.api, *image_, options.strict_perms,
                                options.windows_x64, options.call_summaries));
    if ( !driver_->can_discover() )
    {
      unavailable_ = "rax backend cannot discover from this image";
      driver_.reset();
    }
  }

  bool available() const noexcept override
  {
    return driver_ != nullptr;
  }

  std::string unavailable_reason() const override
  {
    return unavailable_;
  }

  EmulationJobResult execute(const EmulationJob &job,
                             const EmulationCancellation &cancel) override
  {
    EmulationJobResult result;
    result.function_start = job.function.start;
    if ( driver_ == nullptr || image_ == nullptr )
    {
      result.status = EmulationJobStatus::UNAVAILABLE;
      result.diagnostic = unavailable_;
      return result;
    }

    const FuncRange *snapshot_func = image_->function_at(job.function.start);
    if ( snapshot_func == nullptr || snapshot_func->start != job.function.start
      || snapshot_func->end != job.function.end
      || snapshot_func->byte_hash != job.function.byte_hash
      || snapshot_func->generation != job.function.generation )
    {
      result.status = EmulationJobStatus::FAILED;
      result.diagnostic = "emulation job does not match immutable image generation";
      return result;
    }

    std::set<std::pair<uint32_t, uint64_t>> provenance;
    for ( const EmulationRunRequest &request : job.runs )
    {
      const uint64_t effective_seed = request.has_input ? request.input.seed : request.seed;
      const uint32_t effective_run = request.has_input ? request.input.run_id : request.run_id;
      if ( !provenance.emplace(effective_run, effective_seed).second )
      {
        result.status = EmulationJobStatus::FAILED;
        result.diagnostic = "duplicate emulation run provenance";
        return result;
      }
    }

    result.runs.reserve(job.runs.size());
    for ( const EmulationRunRequest &request : job.runs )
    {
      if ( cancel.cancelled() )
      {
        result.status = EmulationJobStatus::CANCELLED;
        result.diagnostic = "emulation generation cancelled";
        result.merged.normalize();
        return result;
      }

      EmulationRunResult run;
      run.seed = request.has_input ? request.input.seed : request.seed;
      run.run_id = request.has_input ? request.input.run_id : request.run_id;
      const EmuInput *input = request.has_input ? &request.input : nullptr;
      run.ran = driver_->emulate_from(job.function.start, job.function.end,
                                      job.config, run.events, &run.outcome,
                                      request.record_pcs, request.seed,
                                      request.run_id, input,
                                      cancellation_probe,
                                      &cancel);
      if ( !run.ran )
      {
        result.runs.push_back(std::move(run));
        result.status = EmulationJobStatus::FAILED;
        result.diagnostic = "rax emulation run could not be started";
        result.merged.normalize();
        return result;
      }
      result.merged.merge_from(run.events);
      result.runs.push_back(std::move(run));
      if ( cancel.cancelled() )
      {
        result.status = EmulationJobStatus::CANCELLED;
        result.diagnostic = "emulation generation cancelled";
        result.merged.normalize();
        return result;
      }
    }

    result.merged.normalize();
    result.status = EmulationJobStatus::COMPLETED;
    return result;
  }

private:
  std::shared_ptr<const ProgramImage> image_;
  std::unique_ptr<EmuDriver> driver_;
  std::string unavailable_;
};

} // namespace

EmulationExecutorFactory hybrid_make_rax_worker_factory(RaxWorkerOptions options)
{
  // Capture one immutable options value; each executor takes its own copy of
  // call summaries and constructs its engine only after the worker starts.
  return [options = std::move(options)](size_t) -> std::unique_ptr<EmulationExecutor>
  {
    return std::unique_ptr<EmulationExecutor>(new RaxEmulationExecutor(options));
  };
}

} // namespace chernobog::hybrid
