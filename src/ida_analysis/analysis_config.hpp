/* Runtime controls for native IDA analysis and rax evidence materialization. */
#pragma once

#include <cstddef>
#include <cstdint>

namespace chernobog::ida_analysis {

struct NativeAnalysisConfig
{
  bool enabled = true;
  bool redundant_prefixes = true;
  bool call_pop_get_pc = true;
  bool push_return = true;
  bool zero_register_branches = true;
  bool opposite_branches = true;
  bool entry_predicates = true;
  bool known_x86_flags = true;
  bool indirect_branches = true;
  bool jump_gaps = true;
  bool orphan_functions = true;
  bool outline_wrappers = true;

  int pop_ret_depth = 4;
  int flag_scan_depth = 8;
  int register_scan_depth = 0;
  int wrapper_max_instructions = 20;
  int wrapper_max_callers = 1;
  int orphan_scan_instructions = 2000;
  size_t maximum_post_scan_heads = 1000000;
  size_t maximum_post_scan_functions = 100000;
  uint64_t maximum_gap = 0x100;
  uint64_t entry_predicate_window = 0x10;
};

struct EvidenceApplyConfig
{
  bool enabled = true;
  bool code_references = true;
  bool data_references = true;
  bool make_code = true;
  bool pointer_offsets = true;
  bool data_types = true;
  bool strings = true;
  bool comments = true;
  bool function_recovery = true;
  bool stack_purge = true;
  bool argument_registers = true;
  bool no_return_comments = true;

  // These change higher-level IDA metadata from incomplete dynamic coverage
  // and therefore retain separate explicit opt-ins, matching viy's policy.
  bool set_no_return = false;
  bool switch_recovery = false;
  bool opaque_comments = false;

  size_t minimum_dynamic_runs = 2;
  size_t minimum_noret_runs = 3;
};

/*
 * Hex-Rays analysis passes that must run before Chernobog's MMAT_LOCOPT
 * deobfuscation pipeline.  These are deliberately separate from
 * NativeAnalysisConfig: they exist only while the decompiler dispatcher is
 * available and operate on an individual function's in-flight flowchart/MBA.
 */
struct EarlyHexRaysConfig
{
  bool enabled = true;
  bool call_pop_flowchart = true;
  bool call_pop_codegen = true;
  bool generated_gotos = true;
  bool constant_folding = true;
  bool force_char_strings = true;

  int gadget_scan_depth = 8;
  size_t maximum_blocks = 100000;
  size_t maximum_instructions = 1000000;
};

NativeAnalysisConfig load_native_analysis_config();
EvidenceApplyConfig load_evidence_apply_config();
EarlyHexRaysConfig load_early_hexrays_config();

} // namespace chernobog::ida_analysis
