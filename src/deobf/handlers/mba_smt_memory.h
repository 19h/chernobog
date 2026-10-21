#pragma once
#include "mba_smt.h"

namespace chernobog::mba_smt
{
// Explicit deterministic test seam; product callers leave it null.
struct MemorySliceTestHooks
{
    std::function<std::chrono::steady_clock::time_point()> now;
    std::function<bool()> cancelled;
    std::function<void(cinsn_t &, lvars_t &)> before_commit;
};
// Stage ordered reads as private ctree values. Nothing is installed unless the
// complete slice, both value proofs and the immutable effect frame are valid.
int simplify_memory_values(cfunc_t &function, FunctionBudget &budget,
                           const MemorySliceTestHooks *tests = nullptr);
}
