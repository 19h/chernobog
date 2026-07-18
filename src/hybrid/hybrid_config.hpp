/*
 * Runtime policy for one explicitly selected Hex-Rays function.
 *
 * There are intentionally no database-sweep, epoch, worker-count, or automatic
 * mutation controls here.  A session owns one worker and replaces its pending
 * generation whenever the user selects another function.
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace chernobog::hybrid {

inline constexpr uint64_t kHybridDefaultMaxInstructions = 200000;
inline constexpr uint64_t kHybridHardMaxInstructions = 100000000;
inline constexpr uint64_t kHybridDefaultTimeoutMs = 1000;
inline constexpr uint64_t kHybridHardTimeoutMs = 60000;

enum class HybridLogLevel : uint8_t
{
  QUIET = 0,
  SUMMARY = 1,
  TRACE = 2,
};

struct HybridConfig
{
  bool enabled = true;
  HybridLogLevel log_level = HybridLogLevel::SUMMARY;

  // Each concrete run is independently bounded by both limits.
  uint64_t max_insns = kHybridDefaultMaxInstructions;
  uint64_t timeout_ms = kHybridDefaultTimeoutMs;
  int explore_runs = 4;
  size_t max_callsite_inputs = 8;

  // Main-thread snapshot and UI polling bounds.
  uint64_t max_image_bytes = 512ull * 1024ull * 1024ull;
  size_t max_static_instructions = 65536;
  int poll_ms = 50;

  // Observation producers.  All remain read-only with respect to the IDB.
  bool want_static = true;
  bool want_smir = true;
  bool want_drefs = true;
  bool want_runtime_strings = true;
  bool want_smc_evidence = true;
  bool want_import_summaries = true;
  bool strict_perms = true;
  uint64_t max_runtime_bytes = 1ull << 20;
};

// Invalid values fail closed to bounded defaults. Environment variables use
// the CHERNOBOG_RAX_* prefix documented in RAX_HYBRID.md.
HybridConfig hybrid_load_config();

} // namespace chernobog::hybrid
