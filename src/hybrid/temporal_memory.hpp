/* Bounded, run-local heap lifetimes and immutable bytes at semantic uses.
 * No backend or database access. Addresses/generations identify witnesses;
 * allocation origin/occurrence identify corresponding objects across runs.
 */
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <tuple>
#include <vector>

namespace chernobog::hybrid
{

enum class DataScope : uint8_t
{
    IMAGE = 0,
    STACK,
    HEAP,
    OTHER
};
enum class UseProducer : uint8_t
{
    EXECUTED_READ = 0,
    MODELED_ARGUMENT,
    EXECUTED_READ_STREAM
};

inline const char *use_producer_name(UseProducer producer)
{
    switch (producer)
    {
    case UseProducer::EXECUTED_READ:
        return "executed-read";
    case UseProducer::MODELED_ARGUMENT:
        return "modeled-argument";
    case UseProducer::EXECUTED_READ_STREAM:
        return "executed-read-stream";
    }
    return "unknown";
}
enum class UseCaptureStatus : uint8_t
{
    EXACT = 0,
    UNKNOWN_OBJECT,
    OUTSIDE_LIFETIME,
    OBJECT_BOUNDARY,
    BYTE_LIMIT,
    INCOMPLETE_VALUE,
};

struct AllocationLifetime
{
    uint64_t id = 0, generation = 0, address = 0, size = 0;
    uint64_t context = 0, site = 0, callee = 0, occurrence = 0;
    uint64_t allocated = 0, released = 0;
    bool live = true;
    uint32_t run_id = 0;
    uint64_t seed = 0;

    auto key() const
    {
        return std::tie(run_id, seed, id, generation, address, size, context, site, callee,
                        occurrence, allocated, released, live);
    }
};

struct UseSnapshot
{
    uint64_t context = 0, site = 0, callee = 0, occurrence = 0;
    // -1 denotes an executed read; nonnegative indices are modeled arguments.
    int argument = -1;
    UseProducer producer = UseProducer::EXECUTED_READ;
    uint8_t model_kind = 0; // EmuSummaryKind value; zero for executed reads
    DataScope scope = DataScope::OTHER;
    uint64_t object_site = 0, object_callee = 0, object_occurrence = 0;
    uint64_t object_size = 0;
    int64_t offset = 0; // stack offsets are relative to selected-function entry SP
    uint64_t allocation_id = 0, generation = 0, address = 0;
    uint64_t sequence = 0, observed_size = 0;
    uint32_t run_id = 0;
    uint64_t seed = 0;
    UseCaptureStatus status = UseCaptureStatus::UNKNOWN_OBJECT;
    std::vector<uint8_t> bytes;

    auto semantic_key() const
    {
        return std::make_tuple(context, site, callee, occurrence, argument, producer, model_kind,
                               scope, object_site, object_callee, object_occurrence, object_size,
                               offset);
    }
    auto witness_key() const
    {
        return std::tie(run_id, seed, sequence, allocation_id, generation, address, observed_size,
                        status, bytes);
    }
};

class TemporalMemory
{
  public:
    static constexpr size_t allocation_limit = 4096;
    static constexpr size_t use_limit = 4096;
    static constexpr size_t snapshot_limit = 4096;
    static constexpr size_t total_byte_limit = 1u << 20;
    uint64_t context = 0, entry_sp = 0, heap_begin = 0, heap_end = 0;
    uint32_t run_id = 0;
    uint64_t seed = 0;
    bool enabled = false, truncated = false, allocation_exhausted = false;
    size_t byte_budget = total_byte_limit;
    std::vector<AllocationLifetime> allocations;
    std::vector<UseSnapshot> uses;

    uint64_t allocate(uint64_t size, uint64_t site, uint64_t callee, uint64_t sequence)
    {
        if (allocation_attempts_ >= allocation_limit)
        {
            allocation_exhausted = true;
            return 0;
        }
        ++allocation_attempts_;
        const uint64_t occurrence = ++allocation_occurrences_[{site, callee}];
        if (size == 0 || size > (1u << 20))
            return 0;
        const uint64_t capacity = (size + 15) & ~uint64_t(15);
        Block *selected = nullptr;
        for (auto &block : blocks_)
            if (!allocations[block.current].live && block.capacity >= capacity)
            {
                selected = &block;
                break;
            }
        if (selected == nullptr)
        {
            const uint64_t next =
                blocks_.empty() ? heap_begin : blocks_.back().address + blocks_.back().capacity;
            if (next > heap_end || capacity > heap_end - next)
                return 0;
            blocks_.push_back({next, capacity, 0, 0});
            selected = &blocks_.back();
        }
        AllocationLifetime allocation;
        allocation.id = allocations.size() + 1;
        allocation.generation = ++selected->generation;
        allocation.address = selected->address;
        allocation.size = size;
        allocation.context = context;
        allocation.site = site;
        allocation.callee = callee;
        allocation.occurrence = occurrence;
        allocation.allocated = sequence;
        allocation.run_id = run_id;
        allocation.seed = seed;
        selected->current = allocations.size();
        allocations.push_back(allocation);
        return allocation.address;
    }

    bool release(uint64_t address, uint64_t sequence)
    {
        if (address == 0)
            return true;
        const auto block = std::lower_bound(blocks_.begin(), blocks_.end(), address,
                                            [](const Block &block, uint64_t value)
                                            { return block.address < value; });
        if (block == blocks_.end() || block->address != address)
            return false;
        auto &allocation = allocations[block->current];
        if (!allocation.live)
            return false;
        allocation.live = false;
        allocation.released = sequence;
        return true;
    }

    UseCaptureStatus identify(uint64_t address, uint64_t size, UseSnapshot *use = nullptr) const
    {
        auto next = std::upper_bound(blocks_.begin(), blocks_.end(), address,
                                     [](uint64_t value, const Block &block)
                                     { return value < block.address; });
        if (next != blocks_.begin())
        {
            const auto &block = *--next;
            if (address - block.address >= block.capacity)
                return UseCaptureStatus::UNKNOWN_OBJECT;
            const auto &allocation = allocations[block.current];
            const uint64_t offset = address - allocation.address;
            if (use != nullptr)
            {
                use->allocation_id = allocation.id;
                use->generation = allocation.generation;
                use->object_site = allocation.site;
                use->object_callee = allocation.callee;
                use->object_occurrence = allocation.occurrence;
                use->object_size = allocation.size;
                use->offset = int64_t(offset);
            }
            if (!allocation.live)
                return UseCaptureStatus::OUTSIDE_LIFETIME;
            if (offset > allocation.size || size > allocation.size - offset)
                return UseCaptureStatus::OBJECT_BOUNDARY;
            return UseCaptureStatus::EXACT;
        }
        return UseCaptureStatus::UNKNOWN_OBJECT;
    }

    void capture(uint64_t site, uint64_t callee, int argument, UseProducer producer,
                 DataScope scope, uint64_t address, const uint8_t *bytes, size_t available,
                 uint64_t observed_size, uint64_t sequence, uint8_t model_kind = 0)
    {
        if (!enabled)
            return;
        if (use_attempts_ >= use_limit)
        {
            truncated = true;
            return;
        }
        ++use_attempts_;
        const uint64_t occurrence = ++use_occurrences_[{site, callee, argument, producer}];
        // Zero-byte models consume no bytes but still occupy their call occurrence.
        if (observed_size == 0)
            return;
        UseSnapshot use;
        use.context = context;
        use.site = site;
        use.callee = callee;
        use.argument = argument;
        use.producer = producer;
        use.model_kind = model_kind;
        use.occurrence = occurrence;
        const bool invalid_span = observed_size > std::numeric_limits<uint64_t>::max() - address;
        if (!invalid_span && address < heap_end && address + observed_size > heap_begin)
            scope = DataScope::HEAP; // crossings must not masquerade as stack-frame uses
        use.scope = scope;
        use.address = address;
        use.sequence = sequence;
        use.observed_size = observed_size;
        use.run_id = run_id;
        use.seed = seed;
        if (invalid_span)
            use.status = UseCaptureStatus::OBJECT_BOUNDARY;
        else if (scope == DataScope::HEAP)
            use.status = identify(address, observed_size, &use);
        else if (scope == DataScope::IMAGE)
        {
            use.object_site = address;
            use.status = UseCaptureStatus::EXACT;
        }
        else if (scope == DataScope::STACK)
        {
            const uint64_t delta = address >= entry_sp ? address - entry_sp : entry_sp - address;
            if (delta <= uint64_t(std::numeric_limits<int64_t>::max()))
            {
                use.offset = address >= entry_sp ? int64_t(delta) : -int64_t(delta);
                use.object_site = context; // a frame, not a recovered C lexical object
                use.status = UseCaptureStatus::EXACT;
            }
        }
        const size_t remaining = byte_budget > retained_ ? byte_budget - retained_ : 0;
        const size_t count = std::min({available, snapshot_limit, remaining,
                                       size_t(std::min<uint64_t>(observed_size, snapshot_limit))});
        if (bytes != nullptr && count != 0)
            use.bytes.assign(bytes, bytes + count);
        retained_ += use.bytes.size();
        if (use.bytes.size() < observed_size)
        {
            if (count < std::min<uint64_t>(available, observed_size))
            {
                truncated = true;
                use.status = UseCaptureStatus::BYTE_LIMIT;
            }
            else
                use.status = UseCaptureStatus::INCOMPLETE_VALUE;
        }
        uses.push_back(std::move(use));
    }

  private:
    struct Block
    {
        uint64_t address, capacity, generation;
        size_t current;
    };
    std::vector<Block> blocks_;
    size_t retained_ = 0;
    size_t allocation_attempts_ = 0, use_attempts_ = 0;
    std::map<std::pair<uint64_t, uint64_t>, uint64_t> allocation_occurrences_;
    std::map<std::tuple<uint64_t, uint64_t, int, UseProducer>, uint64_t> use_occurrences_;
};

} // namespace chernobog::hybrid
