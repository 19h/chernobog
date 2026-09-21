/* Per-database native IDA analysis-quality engine. */
#pragma once

#include <cstddef>
#include <cstdarg>
#include <memory>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace chernobog::ida_analysis {

// Read-only projection of live conclusions, never persisted ownership receipts.
struct NativeInspection
{
  static constexpr size_t proof_limit = 128, dependency_limit = 64;
  bool available = false;
  int64_t database = -1;
  uint64_t function = 0;
  size_t omitted = 0;
  std::vector<std::map<std::string, std::string>> records;
};

struct NativeAnalysisStats
{
  size_t redundant_prefixes = 0;
  size_t get_pc_gadgets = 0;
  size_t push_return_targets = 0;
  size_t zero_register_branches = 0;
  size_t opposite_branch_pairs = 0;
  size_t entry_predicates = 0;
  size_t known_flag_branches = 0;
  size_t indirect_targets = 0;
  size_t gaps_retyped = 0;
  size_t get_pc_tail_extensions = 0;
  size_t orphan_functions = 0;
  size_t outlined_wrappers = 0;
  size_t post_scan_heads = 0;
  size_t post_scan_functions = 0;
  bool post_scan_truncated = false;
};

class NativeAnalysisEngine
{
public:
  NativeAnalysisEngine();
  ~NativeAnalysisEngine();

  NativeAnalysisEngine(const NativeAnalysisEngine &) = delete;
  NativeAnalysisEngine &operator=(const NativeAnalysisEngine &) = delete;

  bool enabled() const;
  void reset();
  void on_autoanalysis_complete();
  void on_database_event(int event, va_list arguments);
  const NativeAnalysisStats &stats() const;
  NativeInspection inspect(uint64_t function_start) const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace chernobog::ida_analysis
