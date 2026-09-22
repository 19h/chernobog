#pragma once
#include "region.hpp"
#include "../hybrid/emu_driver.hpp"
namespace chernobog::vm {
enum class TransitionResult { corroborated, different, inconsistent, unknown, unsupported };
struct TransitionCheck
{
  TransitionResult result = TransitionResult::unsupported;
  std::string reason;
  unsigned queries = 0;
};
// Caller must establish current candidate bytes/roles, the complete local
// execution path and complete captured access interval. This checks one
// normal-completion model against a concrete observation, never all VM inputs.
// For near-return dispatch, the model requires CET shadow stacks disabled.
// All GPRs, defined arithmetic flags, target and ordered accesses are checked.
// Read constraints describe observed initial memory; earlier observed writes
// are respected. Input satisfiability is checked before output mismatch.
TransitionCheck check_transition(const Candidate &, const hybrid::StatePoint &entry,
    const hybrid::StatePoint &output, const std::vector<hybrid::DataAcc> &,
    unsigned timeout_ms=100, unsigned resource_limit=200000);
const char *transition_result_name(TransitionResult);
}
