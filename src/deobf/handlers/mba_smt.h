#pragma once
#include "../deobf_types.h"
#include "../analysis/mba_smt.hpp"

namespace chernobog::mba_smt
{
// Elapsed work is accumulated across all maturities of one MBA generation.
struct FunctionBudget
{
    Backend backend = selected_backend();
    const char *backend_notice = backend_diagnostic();
    Profile profile = Profile::Normal;
    SnapshotToken snapshot;
    unsigned limit_ms = 1000;
    uint64_t spent_ns = 0;
    Statistics totals;
};

int simplify(mbl_array_t *mba, FunctionBudget &budget);
} // namespace chernobog::mba_smt
