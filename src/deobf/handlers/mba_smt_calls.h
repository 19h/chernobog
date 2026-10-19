#pragma once

#include "mba_smt.h"

namespace chernobog::mba_smt
{
// Specialize pure scalar helpers in their caller's expression context.
// Summaries and local bindings belong to this ctree invocation only.
struct CallSimplification
{
    int changes = 0;
    bool refresh_caller = false;
};

CallSimplification simplify_calls(cfunc_t *function, FunctionBudget &budget);
}
