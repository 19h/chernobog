#pragma once
#include "region.hpp"
#include <map>
namespace chernobog::hybrid { struct TargetEvidence; }
namespace chernobog::vm {
struct ObservationView
{
  using Row = std::map<std::string, std::string>;
  std::vector<Row> records;
  size_t omitted = 0;
  size_t transition_attempts = 0, queries = 0;
  bool available = false;
  std::string reason;
};
// Read-only association of fresh register captures with current IDB role
// hypotheses. No execution admission or logical-state merging. The default is
// solver-free; explicit validation checks at most 16 captured local transitions.
// At most 64 candidates, 128 rows, 16 displayed accesses per row; reject input
// above 262144 trace records rather than silently interpreting a trace prefix.
ObservationView project_observations(const std::vector<Candidate> &,
    const hybrid::TargetEvidence &, uint64_t function, uint64_t revision, bool fresh,
    bool validate_transitions=false, int64_t database=-1);
}
