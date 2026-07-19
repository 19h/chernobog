#include "analysis_config.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace chernobog::ida_analysis {
namespace {

bool env_bool(const char *name, bool fallback)
{
  const char *value = std::getenv(name);
  if ( value == nullptr || value[0] == '\0' )
    return fallback;
  return std::strcmp(value, "0") != 0
      && std::strcmp(value, "false") != 0
      && std::strcmp(value, "no") != 0
      && std::strcmp(value, "off") != 0;
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

int env_int(const char *name, int fallback)
{
  const uint64_t value = env_u64(name, uint64_t(fallback));
  return value <= uint64_t(std::numeric_limits<int>::max())
       ? int(value) : fallback;
}

size_t env_size(const char *name, size_t fallback)
{
  const uint64_t value = env_u64(name, uint64_t(fallback));
  return value <= uint64_t(std::numeric_limits<size_t>::max())
       ? size_t(value) : fallback;
}

bool transformations_disabled()
{
  return env_bool("CHERNOBOG_DISABLE", false);
}

} // namespace

NativeAnalysisConfig load_native_analysis_config()
{
  NativeAnalysisConfig config;
  config.enabled = env_bool("CHERNOBOG_IDA_ANALYSIS", config.enabled)
                && !transformations_disabled();
  config.redundant_prefixes = env_bool(
      "CHERNOBOG_IDA_REDUNDANT_PREFIX", config.redundant_prefixes);
  config.call_pop_get_pc = env_bool(
      "CHERNOBOG_IDA_CALL_POP", config.call_pop_get_pc);
  config.push_return = env_bool(
      "CHERNOBOG_IDA_PUSH_RET", config.push_return);
  config.zero_register_branches = env_bool(
      "CHERNOBOG_IDA_ZERO_REGISTER", config.zero_register_branches);
  config.opposite_branches = env_bool(
      "CHERNOBOG_IDA_OPPOSITE_BRANCHES", config.opposite_branches);
  config.entry_predicates = env_bool(
      "CHERNOBOG_IDA_ENTRY_PREDICATES", config.entry_predicates);
  config.known_x86_flags = env_bool(
      "CHERNOBOG_IDA_KNOWN_FLAGS", config.known_x86_flags);
  config.indirect_branches = env_bool(
      "CHERNOBOG_IDA_INDIRECT_BRANCHES", config.indirect_branches);
  config.jump_gaps = env_bool(
      "CHERNOBOG_IDA_JUMP_GAPS", config.jump_gaps);
  config.orphan_functions = env_bool(
      "CHERNOBOG_IDA_ORPHAN_FUNCTIONS", config.orphan_functions);
  config.outline_wrappers = env_bool(
      "CHERNOBOG_IDA_OUTLINE_WRAPPERS", config.outline_wrappers);

  config.pop_ret_depth = env_int(
      "CHERNOBOG_IDA_POP_RET_DEPTH", config.pop_ret_depth);
  config.flag_scan_depth = env_int(
      "CHERNOBOG_IDA_FLAG_SCAN_DEPTH", config.flag_scan_depth);
  config.register_scan_depth = env_int(
      "CHERNOBOG_IDA_REGISTER_SCAN_DEPTH", config.register_scan_depth);
  config.wrapper_max_instructions = env_int(
      "CHERNOBOG_IDA_WRAPPER_MAX_INSNS", config.wrapper_max_instructions);
  config.wrapper_max_callers = env_int(
      "CHERNOBOG_IDA_WRAPPER_MAX_CALLERS", config.wrapper_max_callers);
  config.orphan_scan_instructions = env_int(
      "CHERNOBOG_IDA_ORPHAN_SCAN_INSNS", config.orphan_scan_instructions);
  config.maximum_post_scan_heads = env_size(
      "CHERNOBOG_IDA_POST_SCAN_HEADS", config.maximum_post_scan_heads);
  config.maximum_post_scan_functions = env_size(
      "CHERNOBOG_IDA_POST_SCAN_FUNCTIONS",
      config.maximum_post_scan_functions);
  config.maximum_gap = env_u64(
      "CHERNOBOG_IDA_MAX_GAP", config.maximum_gap);
  config.entry_predicate_window = env_u64(
      "CHERNOBOG_IDA_ENTRY_WINDOW", config.entry_predicate_window);

  if ( config.pop_ret_depth < 1 ) config.pop_ret_depth = 1;
  if ( config.pop_ret_depth > 64 ) config.pop_ret_depth = 64;
  if ( config.flag_scan_depth < 1 ) config.flag_scan_depth = 1;
  if ( config.flag_scan_depth > 64 ) config.flag_scan_depth = 64;
  if ( config.register_scan_depth < 0 ) config.register_scan_depth = 0;
  if ( config.register_scan_depth > 1024 ) config.register_scan_depth = 1024;
  if ( config.wrapper_max_instructions < 1 )
    config.wrapper_max_instructions = 1;
  if ( config.wrapper_max_instructions > 256 )
    config.wrapper_max_instructions = 256;
  if ( config.wrapper_max_callers < 0 ) config.wrapper_max_callers = 0;
  if ( config.wrapper_max_callers > 1000000 )
    config.wrapper_max_callers = 1000000;
  if ( config.orphan_scan_instructions < 1 )
    config.orphan_scan_instructions = 1;
  if ( config.orphan_scan_instructions > 1000000 )
    config.orphan_scan_instructions = 1000000;
  if ( config.maximum_post_scan_heads < 1 )
    config.maximum_post_scan_heads = 1;
  if ( config.maximum_post_scan_heads > 100000000 )
    config.maximum_post_scan_heads = 100000000;
  if ( config.maximum_post_scan_functions < 1 )
    config.maximum_post_scan_functions = 1;
  if ( config.maximum_post_scan_functions > 10000000 )
    config.maximum_post_scan_functions = 10000000;
  if ( config.maximum_gap > (1ull << 20) )
    config.maximum_gap = 1ull << 20;
  if ( config.entry_predicate_window > (1ull << 20) )
    config.entry_predicate_window = 1ull << 20;
  return config;
}

EvidenceApplyConfig load_evidence_apply_config()
{
  EvidenceApplyConfig config;
  config.enabled = env_bool("CHERNOBOG_RAX_APPLY_ANALYSIS", config.enabled)
                && env_bool("CHERNOBOG_IDA_ANALYSIS", true)
                && !transformations_disabled();
  config.code_references = env_bool(
      "CHERNOBOG_RAX_APPLY_CREFS", config.code_references);
  config.data_references = env_bool(
      "CHERNOBOG_RAX_APPLY_DREFS", config.data_references);
  config.make_code = env_bool(
      "CHERNOBOG_RAX_MAKE_CODE", config.make_code);
  config.pointer_offsets = env_bool(
      "CHERNOBOG_RAX_POINTER_OFFSETS", config.pointer_offsets);
  config.data_types = env_bool(
      "CHERNOBOG_RAX_TYPE_DATA", config.data_types);
  config.strings = env_bool(
      "CHERNOBOG_RAX_CREATE_STRINGS", config.strings);
  config.comments = env_bool(
      "CHERNOBOG_RAX_COMMENTS", config.comments);
  config.function_recovery = env_bool(
      "CHERNOBOG_RAX_FUNCTION_RECOVERY", config.function_recovery);
  config.stack_purge = env_bool(
      "CHERNOBOG_RAX_PURGE", config.stack_purge);
  config.argument_registers = env_bool(
      "CHERNOBOG_RAX_ARGREGS", config.argument_registers);
  config.no_return_comments = env_bool(
      "CHERNOBOG_RAX_NORET", config.no_return_comments);
  config.set_no_return = env_bool(
      "CHERNOBOG_RAX_SET_NORET", config.set_no_return);
  config.switch_recovery = env_bool(
      "CHERNOBOG_RAX_SWITCH", config.switch_recovery);
  config.opaque_comments = env_bool(
      "CHERNOBOG_RAX_OPAQUE", config.opaque_comments);
  config.minimum_dynamic_runs = env_size(
      "CHERNOBOG_RAX_MIN_DYNAMIC_RUNS", config.minimum_dynamic_runs);
  config.minimum_noret_runs = env_size(
      "CHERNOBOG_RAX_MIN_NORET_RUNS", config.minimum_noret_runs);
  if ( config.minimum_dynamic_runs < 1 ) config.minimum_dynamic_runs = 1;
  if ( config.minimum_dynamic_runs > 32 ) config.minimum_dynamic_runs = 32;
  if ( config.minimum_noret_runs < 2 ) config.minimum_noret_runs = 2;
  if ( config.minimum_noret_runs > 64 ) config.minimum_noret_runs = 64;
  return config;
}

EarlyHexRaysConfig load_early_hexrays_config()
{
  EarlyHexRaysConfig config;
  config.enabled = env_bool("CHERNOBOG_IDA_EARLY_HEXRAYS", config.enabled)
                && env_bool("CHERNOBOG_IDA_ANALYSIS", true)
                && !transformations_disabled();
  config.call_pop_flowchart = env_bool(
      "CHERNOBOG_IDA_CALL_POP_FLOWCHART", config.call_pop_flowchart);
  config.call_pop_codegen = env_bool(
      "CHERNOBOG_IDA_CALL_POP_CODEGEN", config.call_pop_codegen);
  config.generated_gotos = env_bool(
      "CHERNOBOG_IDA_GENERATED_GOTOS", config.generated_gotos);
  config.constant_folding = env_bool(
      "CHERNOBOG_IDA_EARLY_CONSTANTS", config.constant_folding);
  config.force_char_strings = env_bool(
      "CHERNOBOG_IDA_FORCE_CHAR_STRINGS", config.force_char_strings);
  config.gadget_scan_depth = env_int(
      "CHERNOBOG_IDA_GADGET_SCAN_DEPTH", config.gadget_scan_depth);
  config.maximum_blocks = env_size(
      "CHERNOBOG_IDA_EARLY_MAX_BLOCKS", config.maximum_blocks);
  config.maximum_instructions = env_size(
      "CHERNOBOG_IDA_EARLY_MAX_INSNS", config.maximum_instructions);

  if ( config.gadget_scan_depth < 1 ) config.gadget_scan_depth = 1;
  if ( config.gadget_scan_depth > 64 ) config.gadget_scan_depth = 64;
  if ( config.maximum_blocks < 1 ) config.maximum_blocks = 1;
  if ( config.maximum_blocks > 1000000 )
    config.maximum_blocks = 1000000;
  if ( config.maximum_instructions < 1 ) config.maximum_instructions = 1;
  if ( config.maximum_instructions > 100000000 )
    config.maximum_instructions = 100000000;
  return config;
}

} // namespace chernobog::ida_analysis
