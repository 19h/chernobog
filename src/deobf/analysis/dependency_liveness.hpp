#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace chernobog::analysis {

struct bit_liveness_transfer_t
{
    bool observed = false;
    uint64_t live_after = 0;
};

// Apply one instruction's read/write masks to the subset of register bits
// that still contain an incoming value. Reads precede writes semantically.
inline bit_liveness_transfer_t transfer_bit_liveness(
    uint64_t incoming,
    uint64_t read_mask,
    uint64_t write_mask)
{
    return {
        (incoming & read_mask) != 0,
        incoming & ~write_mask,
    };
}

// Propagate liveness from observable roots through destination-to-source
// dependency edges. Invalid edges are ignored so callers can fail closed by
// retaining their corresponding statements outside this graph.
inline std::vector<uint8_t> propagate_dependency_liveness(
    size_t variable_count,
    const std::vector<uint8_t> &observable,
    const std::vector<std::vector<size_t>> &dependencies)
{
    std::vector<uint8_t> live(variable_count, 0);
    std::vector<size_t> worklist;
    for ( size_t index = 0; index < variable_count; ++index )
    {
        if ( index < observable.size() && observable[index] != 0 )
        {
            live[index] = 1;
            worklist.push_back(index);
        }
    }

    while ( !worklist.empty() )
    {
        const size_t destination = worklist.back();
        worklist.pop_back();
        if ( destination >= dependencies.size() )
            continue;
        for ( size_t source : dependencies[destination] )
        {
            if ( source < variable_count && live[source] == 0 )
            {
                live[source] = 1;
                worklist.push_back(source);
            }
        }
    }
    return live;
}

} // namespace chernobog::analysis
