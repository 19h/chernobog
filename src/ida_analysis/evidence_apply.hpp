/* Guarded main-thread projection of current-function rax evidence into IDA. */
#pragma once

#include <cstddef>

namespace chernobog::hybrid {
struct TargetEvidence;
}

namespace chernobog::ida_analysis {

struct EvidenceApplyStats
{
  size_t static_crefs = 0;
  size_t dynamic_crefs = 0;
  size_t drefs = 0;
  size_t code_items = 0;
  size_t pointer_offsets = 0;
  size_t typed_globals = 0;
  size_t strings = 0;
  size_t functions = 0;
  size_t purges = 0;
  size_t noret_annotations = 0;
  size_t argument_annotations = 0;
  size_t opaque_annotations = 0;
  size_t switches = 0;
  size_t comments = 0;

  size_t total() const
  {
    return static_crefs + dynamic_crefs + drefs + code_items
         + pointer_offsets + typed_globals + strings + functions + purges
         + noret_annotations + argument_annotations + opaque_annotations
         + switches + comments;
  }
};

EvidenceApplyStats apply_evidence_to_ida(
    const chernobog::hybrid::TargetEvidence &evidence);

} // namespace chernobog::ida_analysis
