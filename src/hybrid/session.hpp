/* Per-IDB, one-current-function exploratory rax session. */
#pragma once

#include "../common/warn_off.h"
#include <hexrays.hpp>
#include "../common/warn_on.h"

#include <cstdint>
#include <memory>

namespace chernobog::hybrid {

enum class EnsureExploredResult : uint8_t
{
  ALREADY_FRESH = 0,
  EXPLORED,
  DISABLED,
  UNAVAILABLE,
  CANCELLED,
  FAILED,
};

class Session
{
public:
  explicit Session(int64_t database_id);
  ~Session();

  Session(const Session &) = delete;
  Session &operator=(const Session &) = delete;

  bool explore(vdui_t *view, uint64_t fallback_address = UINT64_MAX);
  // Bounded main-thread prerequisite used by deobfuscation. It reuses exact
  // fresh evidence, waits for a matching job, or explores only this function.
  EnsureExploredResult ensure_explored(
      uint64_t function_start, uint64_t focus_address = UINT64_MAX);
  bool explore_batch_target();
  void show_last(vdui_t *view) const;
  void cancel();
  void clear();
  void invalidate_function(uint64_t function_start);
  // Consume the one-shot signal that fresh evidence changed IDA analysis.
  // Hex-Rays flowchart callbacks use it to request a coherent rebuild.
  bool take_analysis_changes();

  int64_t database_id() const { return database_id_; }
  bool enabled() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
  int64_t database_id_ = 0;
};

Session *hybrid_current_session();
EnsureExploredResult hybrid_ensure_current_function_explored(
    uint64_t function_start, uint64_t focus_address = UINT64_MAX);

} // namespace chernobog::hybrid
