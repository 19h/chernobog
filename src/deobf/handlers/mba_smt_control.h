#pragma once
#include "mba_smt.h"

namespace chernobog::mba_smt
{
struct ControlFlowTestHooks
{
    std::function<std::chrono::steady_clock::time_point()> now;
    std::function<bool()> cancelled;
    std::function<void(cinsn_t &, lvars_t &)> before_commit;
};
// Complete bounded path specialization. Unknown loop/switch state, unresolved
// jumps, resource limits or a failed proof discard the entire staged result.
int simplify_bounded_control_flow(cfunc_t &function, FunctionBudget &budget,
                                  const ControlFlowTestHooks *tests = nullptr);
}
