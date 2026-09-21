#pragma once
#include "region.hpp"
#include <map>
namespace chernobog::vm {
using SummaryRow=std::map<std::string,std::string>;
struct SummaryView
{
  std::vector<SummaryRow> references, bindings;
  size_t omitted=0, queries=0;
};
// Explicit inspection: at most 16 candidates and 32 equivalence queries.
// Shared references require a fresh UNSAT result, never syntax/hash equality.
SummaryView project_summaries(const std::vector<Candidate> &, int64_t database,
                             uint64_t function);
}
