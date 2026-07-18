#include "hybrid_config.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace chernobog::hybrid {
namespace {

bool env_bool(const char *name, bool fallback)
{
  const char *value = std::getenv(name);
  if ( value == nullptr || value[0] == '\0' )
    return fallback;
  return std::strcmp(value, "0") != 0 && std::strcmp(value, "false") != 0
      && std::strcmp(value, "no") != 0 && std::strcmp(value, "off") != 0;
}

uint64_t env_u64(const char *name, uint64_t fallback)
{
  const char *value = std::getenv(name);
  if ( value == nullptr || value[0] == '\0' )
    return fallback;
  while ( *value == ' ' || *value == '\t' )
    ++value;
  if ( *value == '-' )
    return fallback;
  errno = 0;
  char *end = nullptr;
  const unsigned long long parsed = std::strtoull(value, &end, 0);
  if ( end == value || errno == ERANGE )
    return fallback;
  while ( *end == ' ' || *end == '\t' || *end == '\r' || *end == '\n' )
    ++end;
  return *end == '\0' ? uint64_t(parsed) : fallback;
}

size_t env_size(const char *name, size_t fallback)
{
  const uint64_t parsed = env_u64(name, uint64_t(fallback));
  return parsed > uint64_t(std::numeric_limits<size_t>::max())
       ? fallback : size_t(parsed);
}

int env_int(const char *name, int fallback)
{
  const uint64_t parsed = env_u64(name, uint64_t(fallback));
  return parsed > uint64_t(std::numeric_limits<int>::max())
       ? fallback : int(parsed);
}

} // namespace

HybridConfig hybrid_load_config()
{
  HybridConfig config;
  config.enabled = env_bool("CHERNOBOG_RAX_ENABLED", config.enabled);
  int level = env_int("CHERNOBOG_RAX_LOG_LEVEL", int(config.log_level));
  if ( level < int(HybridLogLevel::QUIET) ) level = int(HybridLogLevel::QUIET);
  if ( level > int(HybridLogLevel::TRACE) ) level = int(HybridLogLevel::TRACE);
  config.log_level = HybridLogLevel(level);

  config.max_insns = env_u64("CHERNOBOG_RAX_MAX_INSNS", config.max_insns);
  config.timeout_ms = env_u64("CHERNOBOG_RAX_TIMEOUT_MS", config.timeout_ms);
  config.explore_runs = env_int("CHERNOBOG_RAX_EXPLORE_RUNS", config.explore_runs);
  config.max_callsite_inputs = env_size(
      "CHERNOBOG_RAX_MAX_CALLSITE_INPUTS", config.max_callsite_inputs);
  config.max_image_bytes = env_u64(
      "CHERNOBOG_RAX_MAX_IMAGE_BYTES", config.max_image_bytes);
  config.max_static_instructions = env_size(
      "CHERNOBOG_RAX_MAX_STATIC_INSNS", config.max_static_instructions);
  config.poll_ms = env_int("CHERNOBOG_RAX_POLL_MS", config.poll_ms);

  config.want_static = env_bool("CHERNOBOG_RAX_STATIC", config.want_static);
  config.want_smir = env_bool("CHERNOBOG_RAX_SMIR", config.want_smir);
  config.want_drefs = env_bool("CHERNOBOG_RAX_DREFS", config.want_drefs);
  config.want_runtime_strings = env_bool(
      "CHERNOBOG_RAX_RUNTIME_STRINGS", config.want_runtime_strings);
  config.want_smc_evidence = env_bool(
      "CHERNOBOG_RAX_SMC_EVIDENCE", config.want_smc_evidence);
  config.want_import_summaries = env_bool(
      "CHERNOBOG_RAX_IMPORT_SUMMARIES", config.want_import_summaries);
  config.strict_perms = env_bool("CHERNOBOG_RAX_STRICT_PERMS", config.strict_perms);
  config.max_runtime_bytes = env_u64(
      "CHERNOBOG_RAX_MAX_RUNTIME_BYTES", config.max_runtime_bytes);

  // Zero never means unbounded.
  if ( config.max_insns == 0 )
    config.max_insns = kHybridDefaultMaxInstructions;
  if ( config.max_insns > kHybridHardMaxInstructions )
    config.max_insns = kHybridHardMaxInstructions;
  if ( config.timeout_ms == 0 )
    config.timeout_ms = kHybridDefaultTimeoutMs;
  if ( config.timeout_ms > kHybridHardTimeoutMs )
    config.timeout_ms = kHybridHardTimeoutMs;
  if ( config.explore_runs < 1 ) config.explore_runs = 1;
  if ( config.explore_runs > 32 ) config.explore_runs = 32;
  if ( config.max_callsite_inputs > 32 ) config.max_callsite_inputs = 32;
  if ( config.max_image_bytes < (1ull << 20) ) config.max_image_bytes = 1ull << 20;
  if ( config.max_image_bytes > (4ull << 30) ) config.max_image_bytes = 4ull << 30;
  if ( config.max_static_instructions == 0 ) config.max_static_instructions = 1;
  if ( config.max_static_instructions > 1000000 ) config.max_static_instructions = 1000000;
  if ( config.poll_ms < 10 ) config.poll_ms = 10;
  if ( config.poll_ms > 1000 ) config.poll_ms = 1000;
  if ( config.max_runtime_bytes > 64ull * 1024ull * 1024ull )
    config.max_runtime_bytes = 64ull * 1024ull * 1024ull;
  return config;
}

} // namespace chernobog::hybrid
