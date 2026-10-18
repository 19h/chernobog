#pragma once
#include <z3++.h>
#include <cstdint>

namespace chernobog::warbird
{
struct StackState
{
    z3::expr floor;
    z3::expr native_top;
    z3::expr reserved;
};
struct StackUpdate
{
    StackState state;
    z3::expr minimum;
    z3::expr allowed;
    z3::expr grows;
};
// Normal-return bookkeeping of the admitted x64 dispatcher. Native probing
// faults are not certified. The limit bounds modeled growth, not guest memory.
StackUpdate update_stack(const StackState &, const z3::expr &minimum, uint64_t limit);
}
