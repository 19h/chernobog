#pragma once

#include "x86_abstract.h"

#include <array>
#include <map>

namespace chernobog::x86_abstract
{
// A finite concretization, never a clipped prefix of an unbounded domain.
struct RepeatCounts
{
    std::array<unsigned, 9> values{};
    unsigned size = 0;
};

inline std::optional<RepeatCounts> repeat_counts(const Word &count, unsigned address_bits)
{
    if (address_bits != 32 && address_bits != 64)
        return std::nullopt;
    const uint64_t m = mask(address_bits), known = count.known & m;
    const uint64_t fixed = count.value & known;
    const uint64_t largest = fixed | (m & ~known);
    if (largest > 8)
        return std::nullopt;
    RepeatCounts result;
    for (unsigned i = 0; i <= largest; ++i)
        if ((i & known) == fixed)
            result.values[result.size++] = i;
    return result;
}

using StringMemory = std::map<uint64_t, uint8_t>;

struct StringRepeat
{
    unsigned address_bits = 0;
    unsigned element_bytes = 0;
    bool move = false;
    std::optional<uint64_t> destination, source, accumulator;
};

// Replay normal completion for every compatible count and both DF values.
// MOVS reads before each write, including overlap with previous iterations.
// Unknown payloads erase only the validated destination footprint. Failed
// destination validation rejects the whole domain and leaves input unchanged.
// No initial image bytes or segment-base assumptions enter this helper.
template <class Readable, class Writable>
bool repeat_string_memory(StringMemory &memory, const Word &count, const StringRepeat &repeat,
                          Readable readable, Writable writable)
{
    const auto counts = repeat_counts(count, repeat.address_bits);
    const unsigned bytes = repeat.element_bytes;
    if (!counts || (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8) || memory.size() > 128)
        return false;
    const uint64_t m = mask(repeat.address_bits);
    if (counts->size == 1 && counts->values[0] == 0)
        return true;
    if (!repeat.destination || *repeat.destination > m)
        return false;
    StringMemory common;
    bool first = true;
    for (unsigned c = 0; c < counts->size; ++c)
        for (unsigned reverse = 0; reverse < 2; ++reverse)
        {
            StringMemory state = memory;
            for (unsigned i = 0; i < counts->values[c]; ++i)
            {
                const uint64_t distance = uint64_t(i) * bytes;
                const uint64_t offset = reverse ? uint64_t{0} - distance : distance;
                const uint64_t destination = (*repeat.destination + offset) & m;
                if (destination > m - (bytes - 1) || !writable(destination, bytes))
                    return false;
                auto value = repeat.move ? std::optional<uint64_t>{} : repeat.accumulator;
                if (repeat.move && repeat.source && *repeat.source <= m)
                {
                    const uint64_t source = (*repeat.source + offset) & m;
                    if (source <= m - (bytes - 1) && readable(source, bytes))
                    {
                        uint64_t loaded = 0;
                        bool complete = true;
                        for (unsigned j = 0; j < bytes; ++j)
                        {
                            const auto found = state.find(source + j);
                            if (found == state.end())
                            {
                                complete = false;
                                break;
                            }
                            loaded |= uint64_t(found->second) << (j * 8);
                        }
                        if (complete)
                            value = loaded;
                    }
                }
                for (unsigned j = 0; j < bytes; ++j)
                {
                    state.erase(destination + j);
                    if (value)
                    {
                        if (state.size() == 128)
                            state.erase(state.begin());
                        state[destination + j] = uint8_t(*value >> (j * 8));
                    }
                }
            }
            if (first)
            {
                common = std::move(state);
                first = false;
            }
            else
                for (auto it = common.begin(); it != common.end();)
                {
                    const auto found = state.find(it->first);
                    if (found == state.end() || found->second != it->second)
                        it = common.erase(it);
                    else
                        ++it;
                }
        }
    memory = std::move(common);
    return true;
}
} // namespace chernobog::x86_abstract
