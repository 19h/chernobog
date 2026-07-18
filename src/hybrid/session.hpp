/* Per-IDB, one-current-function exploratory rax session. */
#pragma once

#include "../common/warn_off.h"
#include <hexrays.hpp>
#include "../common/warn_on.h"

#include <cstdint>
#include <memory>

namespace chernobog::hybrid {

class Session
{
public:
  explicit Session(int64_t database_id);
  ~Session();

  Session(const Session &) = delete;
  Session &operator=(const Session &) = delete;

  bool explore(vdui_t *view);
  void show_last(vdui_t *view) const;
  void cancel();
  void clear();
  void invalidate_function(uint64_t function_start);

  int64_t database_id() const { return database_id_; }
  bool enabled() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
  int64_t database_id_ = 0;
};

Session *hybrid_current_session();

} // namespace chernobog::hybrid
