#pragma once
#include <z3++.h>
#include <optional>
#include <string>
#include <vector>

namespace chernobog::warbird
{
struct PoolBlock
{
    z3::expr address;
    z3::expr bytes;
    z3::expr tag;
    bool live = true;
};
struct PoolState
{
    std::vector<PoolBlock> blocks;
};
struct PoolOutcome
{
    PoolState state;
    z3::expr condition;
    z3::expr result;
    std::optional<size_t> changed_region;
    std::string frontier;
};
// Normal-return relation for the documented base pool types 0, 1 and 512.
// Environment effects, IRQL and runtime import binding are separate frontiers
// in the explorer. Unrecognized flags are never silently masked off.
std::vector<PoolOutcome> pool_allocate(const PoolState &, const z3::expr &type,
                                       const z3::expr &bytes, const z3::expr &tag,
                                       const z3::expr &new_address);
std::vector<PoolOutcome> pool_free(const PoolState &, const z3::expr &address, const z3::expr &tag,
                                   const z3::expr &void_result);
}
