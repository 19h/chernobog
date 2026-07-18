/*
 * emulation_workers.hpp -- deterministic, IDA-free emulation scheduling.
 *
 * Jobs crossing this boundary contain only copied hybrid model/configuration data.
 * Worker executors are constructed inside their worker thread, which lets each
 * rax-backed executor own an entirely independent engine.  Results are exposed
 * strictly in submission order even when execution completes out of order.
 */
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "emu_driver.hpp"
#include "program_model.hpp"
#include "hybrid_config.hpp"

namespace chernobog::hybrid {

struct EmulationRunRequest
{
  uint64_t seed = 0;
  uint32_t run_id = 0;
  bool record_pcs = true;
  bool has_input = false;
  EmuInput input;
};

// A complete, immutable unit of worker-side work. The main thread must build
// call-site inputs before submission; no worker implementation may query IDA.
struct EmulationJob
{
  FuncRange function;
  HybridConfig config;
  std::vector<EmulationRunRequest> runs;
};

struct EmulationRunResult
{
  uint64_t seed = 0;
  uint32_t run_id = 0;
  bool ran = false;
  EmuEvents events;
  EmuOutcome outcome;
};

enum class EmulationJobStatus : uint8_t
{
  COMPLETED = 0,
  CANCELLED,
  UNAVAILABLE,
  FAILED,
};

struct EmulationJobResult
{
  uint64_t ticket = 0; // assigned by EmulationWorkerPool
  uint64_t function_start = 0;
  EmulationJobStatus status = EmulationJobStatus::FAILED;
  std::string diagnostic;
  std::vector<EmulationRunResult> runs;
  EmuEvents merged;

  bool completed() const { return status == EmulationJobStatus::COMPLETED; }
};

// A generation-bound cancellation view. It remains valid until the executor
// returns. The rax executor also samples the generation from its code hook, so
// an in-flight interpreter run stops at its next instruction boundary.
class EmulationCancellation
{
public:
  EmulationCancellation() = default;
  bool cancelled() const noexcept;

private:
  friend class EmulationWorkerPool;
  EmulationCancellation(std::shared_ptr<const void> state, uint64_t generation);

  std::shared_ptr<const void> state_;
  uint64_t generation_ = 0;
};

// One instance is created inside each worker. Implementations must be
// thread-confined: the pool never calls an executor from another thread.
class EmulationExecutor
{
public:
  virtual ~EmulationExecutor() = default;
  virtual bool available() const noexcept = 0;
  virtual std::string unavailable_reason() const = 0;
  virtual EmulationJobResult execute(const EmulationJob &job,
                                     const EmulationCancellation &cancel) = 0;
};

using EmulationExecutorFactory =
    std::function<std::unique_ptr<EmulationExecutor>(size_t worker_index)>;

struct EmulationWorkerStats
{
  size_t requested_workers = 0;
  size_t initialized_workers = 0;
  size_t available_workers = 0;
  size_t unavailable_workers = 0;
  uint64_t submitted = 0;
  uint64_t settled = 0;
  uint64_t delivered = 0;
  size_t queued = 0;
  size_t running = 0;
  size_t ready_in_order_or_later = 0;
  bool stopping = false;
};

class EmulationWorkerPool
{
public:
  // max_queued_jobs==0 means no explicit queue limit. A bounded value makes
  // try_submit() provide backpressure without ever blocking IDA's main thread.
  EmulationWorkerPool(size_t worker_count, EmulationExecutorFactory factory,
                      size_t max_queued_jobs = 0);
  ~EmulationWorkerPool();

  EmulationWorkerPool(const EmulationWorkerPool &) = delete;
  EmulationWorkerPool &operator=(const EmulationWorkerPool &) = delete;

  // Returns false only after shutdown or while a bounded queue is full.
  // `ticket` is monotonically increasing and is assigned only on success.
  bool try_submit(EmulationJob job, uint64_t *ticket = nullptr);

  // Results are delivered in ticket order. Later completed results remain
  // buffered until every earlier ticket has settled.
  bool try_take_next(EmulationJobResult &out);
  bool wait_take_next(EmulationJobResult &out, std::chrono::milliseconds timeout);
  std::vector<EmulationJobResult> take_ready(size_t maximum = 0);

  // Cancels queued and running jobs from the current generation. Partial run
  // evidence from a running job is retained in its CANCELLED result. Jobs may
  // be submitted again after cancellation; they belong to the new generation.
  void cancel_pending();

  // Cooperative, idempotent shutdown. Queued jobs settle as CANCELLED and
  // workers join after their current bounded emulation call returns.
  void shutdown();

  bool wait_for_initialization(std::chrono::milliseconds timeout) const;
  bool wait_until_idle(std::chrono::milliseconds timeout) const;
  bool initialized() const;
  bool usable() const;
  bool idle() const;
  EmulationWorkerStats stats() const;
  // First bounded executor-initialization failure, empty when none has been
  // observed. Returned by value under the same lock as stats().
  std::string initialization_diagnostic() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace chernobog::hybrid
