/* rax-backed executor factory for EmulationWorkerPool (IDA-free). */
#pragma once

#include <memory>
#include <vector>

#include "emulation_workers.hpp"

namespace chernobog::hybrid {

struct RaxWorkerOptions
{
  const RaxApi *api = nullptr;
  std::shared_ptr<const ProgramImage> image;
  bool strict_perms = true;
  bool windows_x64 = false;
  std::vector<EmuCallSummary> call_summaries;
};

// The returned factory is safe to copy. Each invocation constructs an
// independent EmuDriver (and therefore an independent rax engine) on the
// invoking worker thread while retaining the immutable ProgramImage snapshot.
EmulationExecutorFactory hybrid_make_rax_worker_factory(RaxWorkerOptions options);

} // namespace chernobog::hybrid

