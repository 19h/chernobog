/* Stage-correct, per-function Hex-Rays analysis-quality passes. */
#pragma once

#include <pro.h>

#include <cstddef>
#include <memory>

class bitset_t;
class cfunc_t;
class mba_t;
class qflow_chart_t;
#if IDA_SDK_VERSION >= 940
class qflow_chart_ea_t;
#endif

namespace chernobog::ida_analysis {

struct EarlyHexRaysStats
{
  size_t flowchart_edges = 0;
  size_t codegen_returns = 0;
  size_t generated_gotos = 0;
  size_t folded_instructions = 0;
  size_t character_operands = 0;
  size_t bounded_skips = 0;
};

class EarlyHexRaysAnalysis
{
public:
  EarlyHexRaysAnalysis();
  ~EarlyHexRaysAnalysis();

  EarlyHexRaysAnalysis(const EarlyHexRaysAnalysis &) = delete;
  EarlyHexRaysAnalysis &operator=(const EarlyHexRaysAnalysis &) = delete;

  // Installs/removes only the instruction-to-microcode filter. Event-stage
  // methods below are dispatched by the owning per-IDB plugin callback.
  bool install();
  void uninstall(bool dispatcher_available = true);
  bool enabled() const;
  void reset();

  int on_flowchart(
      const qflow_chart_t *flowchart,
      bitset_t *reachable);
#if IDA_SDK_VERSION >= 940
  int on_flowchart(
      const qflow_chart_ea_t *flowchart,
      bitset_t *reachable);
#endif
  int on_microcode(mba_t *mba);
  int on_preoptimized(mba_t *mba);

  const EarlyHexRaysStats &stats() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace chernobog::ida_analysis
