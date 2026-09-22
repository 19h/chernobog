#include "evidence.hpp"
#include "../common/string_recovery.h"
#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <tuple>

namespace chernobog::hybrid
{
namespace
{
using Run = std::pair<uint32_t, uint64_t>;
using Shape = std::vector<std::pair<uint64_t, uint64_t>>;
using Key = std::pair<decltype(UseSnapshot{}.semantic_key()), Shape>;
struct Stream
{
    UseSnapshot use;
    std::vector<UseSnapshot> parts;
    std::string value;
};
using Endpoint = std::tuple<DataScope, uint64_t, uint64_t, uint64_t>;
Endpoint endpoint(const UseSnapshot &use, uint64_t address)
{
    return {use.scope, use.scope == DataScope::HEAP ? use.allocation_id : 0,
            use.scope == DataScope::HEAP ? use.generation : 0, address};
}
struct Records
{
    std::vector<const UseSnapshot *> uses;
    std::map<uint64_t, const DataAcc *> data;
    std::map<uint64_t, const AllocationLifetime *> objects;
    std::set<uint64_t> barriers;
    size_t snapshot_bytes = 0;
};

bool valid_object(const UseSnapshot &use, const Records &records, uint64_t context)
{
    if (use.context != context || use.status != UseCaptureStatus::EXACT || !use.occurrence ||
        use.bytes.empty() || use.bytes.size() > TemporalMemory::snapshot_limit ||
        use.bytes.size() != use.observed_size || use.sequence == UINT64_MAX ||
        use.address > UINT64_MAX - use.observed_size)
        return false;
    if (use.scope == DataScope::IMAGE)
        return use.object_site == use.address;
    if (use.scope == DataScope::STACK)
        return use.object_site == use.context;
    if (use.scope != DataScope::HEAP)
        return false;
    const auto object = records.objects.find(use.allocation_id);
    if (object == records.objects.end())
        return false;
    const auto &a = *object->second;
    return a.id && a.generation == use.generation && a.context == use.context &&
           a.site == use.object_site && a.callee == use.object_callee &&
           a.occurrence == use.object_occurrence && a.size == use.object_size &&
           use.address >= a.address && use.address - a.address <= a.size && use.offset >= 0 &&
           uint64_t(use.offset) == use.address - a.address &&
           use.observed_size <= a.size - (use.address - a.address) && use.sequence > a.allocated &&
           (a.live ? a.released == 0 : use.sequence < a.released);
}

bool valid_read(const UseSnapshot &use, const Records &records, uint64_t context)
{
    if (!valid_object(use, records, context) || use.producer != UseProducer::EXECUTED_READ ||
        use.argument != -1 || use.callee || use.model_kind || use.bytes.size() > 8)
        return false;
    const auto found = records.data.find(use.sequence + 1);
    if (found == records.data.end())
        return false;
    const auto &data = *found->second;
    if (data.kind != RAX_MEM_READ || data.from != use.site || data.addr != use.address ||
        data.size != use.observed_size || data.scope != use.scope)
        return false;
    for (size_t i = 0; i < use.bytes.size(); ++i)
        if (use.bytes[i] != uint8_t(data.value >> (8 * i)))
            return false;
    if (use.scope == DataScope::HEAP)
    {
        const auto &object = *records.objects.at(use.allocation_id);
        if (!object.live && use.sequence + 1 >= object.released)
            return false;
    }
    return true;
}

bool valid_argument(const UseSnapshot &use, const Records &records, uint64_t context,
                    const std::vector<EmuCallSummary> &bindings)
{
    if (!valid_object(use, records, context) || use.producer != UseProducer::MODELED_ARGUMENT)
        return false;
    const auto binding = std::find_if(
        bindings.begin(), bindings.end(), [&](const auto &item)
        { return item.address == use.callee && uint8_t(item.kind) == use.model_kind; });
    if (binding == bindings.end())
        return false;
    switch (binding->kind)
    {
    case EmuSummaryKind::STRLEN:
    case EmuSummaryKind::STRNLEN:
    case EmuSummaryKind::MEMCHR:
        return use.argument == 0;
    case EmuSummaryKind::STRCMP:
        return use.argument == 0 || use.argument == 1;
    case EmuSummaryKind::MEMCPY:
    case EmuSummaryKind::MEMMOVE:
    case EmuSummaryKind::STRCPY:
    case EmuSummaryKind::STRNCPY:
        return use.argument == 1;
    default:
        return false;
    }
}

bool follows(const Stream &stream, const UseSnapshot &next, const Records &records)
{
    if (stream.parts.empty())
        return false;
    const auto &first = stream.use;
    const auto &last = stream.parts.back();
    if (last.sequence + 1 >= next.sequence || first.context != next.context ||
        first.scope != next.scope || first.address > UINT64_MAX - first.observed_size ||
        first.address + first.observed_size != next.address)
        return false;
    auto barrier = records.barriers.upper_bound(last.sequence);
    if (barrier != records.barriers.end() && *barrier <= next.sequence)
        return false;
    // Read-only interleaving does not change the observed bytes. Writes,
    // calls, modeled uses and lifetime changes remain global barriers.
    if (first.scope == DataScope::HEAP)
        return first.allocation_id == next.allocation_id && first.generation == next.generation;
    if (first.scope == DataScope::STACK)
        return first.observed_size <= uint64_t(INT64_MAX) &&
               first.offset <= INT64_MAX - int64_t(first.observed_size) &&
               first.offset + int64_t(first.observed_size) == next.offset;
    return true;
}
std::vector<RuntimeUseStringCandidate>
derive_streams(uint64_t context, const std::vector<Run> &identities,
               const std::vector<const EmuEvents *> &events, size_t minimum_length,
               size_t maximum_length, bool *valid = nullptr,
               const std::vector<EmuCallSummary> *bindings = nullptr)
{
    if (valid)
        *valid = false;
    std::vector<RuntimeUseStringCandidate> result;
    if (!minimum_length || maximum_length < minimum_length || identities.empty())
        return result;
    std::map<Run, Records> runs;
    for (const auto &identity : identities)
        if (!runs.emplace(identity, Records{}).second)
            return {};
    for (const auto *ledger : events)
    {
        for (const auto &use : ledger->uses)
        {
            const auto run = runs.find({use.run_id, use.seed});
            if (run == runs.end())
                return {};
            auto &r = run->second;
            if (r.uses.size() == TemporalMemory::use_limit ||
                use.bytes.size() > TemporalMemory::snapshot_limit ||
                use.bytes.size() > TemporalMemory::total_byte_limit - r.snapshot_bytes)
                return {};
            r.snapshot_bytes += use.bytes.size();
            r.uses.push_back(&use);
            if (use.producer != UseProducer::EXECUTED_READ)
                r.barriers.insert(use.sequence);
        }
        for (const auto &data : ledger->data)
        {
            const auto run = runs.find({data.run_id, data.seed});
            if (run == runs.end())
                return {};
            auto &r = run->second;
            if (r.data.size() == 65536 || !r.data.emplace(data.sequence, &data).second)
                return {};
            if (data.kind != RAX_MEM_READ)
                r.barriers.insert(data.sequence);
        }
        for (const auto &a : ledger->allocations)
        {
            const auto run = runs.find({a.run_id, a.seed});
            if (run == runs.end())
                return {};
            auto &r = run->second;
            if (r.objects.size() == TemporalMemory::allocation_limit ||
                !r.objects.emplace(a.id, &a).second)
                return {};
            r.barriers.insert(a.allocated);
            if (!a.live)
                r.barriers.insert(a.released);
        }
        for (const auto &edge : ledger->edges)
        {
            const auto run = runs.find({edge.run_id, edge.seed});
            if (run == runs.end())
                return {};
            if (edge.kind == ExecEdge::Kind::Call || edge.kind == ExecEdge::Kind::Unknown)
            {
                if (run->second.barriers.size() >= 81920)
                    return {};
                run->second.barriers.insert(edge.sequence);
            }
        }
    }
    std::map<Key, std::map<Run, Stream>> values;
    std::set<Key> ambiguous;
    for (auto &[identity, records] : runs)
    {
        std::sort(records.uses.begin(), records.uses.end(),
                  [](const auto *a, const auto *b) { return a->sequence < b->sequence; });
        std::map<Endpoint, Stream> pending;
        uint64_t previous = 0;
        bool first = true;
        size_t retained = 0;
        const auto retain = [&](Stream value)
        {
            Shape shape;
            for (const auto &part : value.parts)
                shape.emplace_back(part.site, part.observed_size);
            Key key{value.use.semantic_key(), std::move(shape)};
            const auto decoded = string_recovery::recover_runtime_utf8_prefix(
                value.use.bytes, minimum_length, maximum_length);
            if (!decoded)
            {
                ambiguous.insert(key);
                return true;
            }
            if (value.use.bytes.size() > TemporalMemory::total_byte_limit - retained)
                return false;
            retained += value.use.bytes.size();
            value.value = decoded->utf8;
            if (!values[key].emplace(identity, std::move(value)).second)
                ambiguous.insert(key);
            return true;
        };
        for (const auto *pointer : records.uses)
        {
            const auto &use = *pointer;
            if (!first && use.sequence <= previous)
                return {};
            const auto barrier = records.barriers.upper_bound(previous);
            if (barrier != records.barriers.end() && *barrier <= use.sequence)
                pending.clear();
            previous = use.sequence;
            first = false;
            if (bindings && use.producer == UseProducer::MODELED_ARGUMENT)
            {
                pending.clear();
                if (!valid_argument(use, records, context, *bindings))
                    ambiguous.insert({use.semantic_key(), {{use.site, use.observed_size}}});
                else if (!retain(Stream{use, {use}, {}}))
                    return {};
                continue;
            }
            if (!valid_read(use, records, context))
            {
                if (bindings)
                    ambiguous.insert({use.semantic_key(), {{use.site, use.observed_size}}});
                pending.clear();
                continue;
            }
            if (bindings && !retain(Stream{use, {use}, {}}))
                return {};
            Stream stream;
            if (const auto found = pending.find(endpoint(use, use.address)); found != pending.end())
            {
                stream = std::move(found->second);
                pending.erase(found);
            }
            if (!follows(stream, use, records))
                stream = {};
            if (stream.parts.empty())
            {
                stream.use = use;
                stream.use.producer = UseProducer::EXECUTED_READ_STREAM;
                stream.use.bytes.clear();
                stream.use.observed_size = 0;
            }
            if (use.bytes.size() > TemporalMemory::snapshot_limit - stream.use.bytes.size())
            {
                stream = {};
                continue;
            }
            stream.use.bytes.insert(stream.use.bytes.end(), use.bytes.begin(), use.bytes.end());
            stream.use.observed_size += use.observed_size;
            stream.parts.push_back(use);
            if (std::find(use.bytes.begin(), use.bytes.end(), 0) == use.bytes.end())
            {
                const auto key =
                    endpoint(stream.use, stream.use.address + stream.use.observed_size);
                const auto [found, inserted] = pending.emplace(key, std::move(stream));
                if (!inserted)
                    pending.erase(found); // No arbitrary choice between overlapping prefixes.
                continue;
            }
            if (stream.parts.size() > 1 && !retain(std::move(stream)))
                return {};
        }
    }
    for (auto &[key, witnesses] : values)
    {
        if (ambiguous.count(key) || witnesses.size() != runs.size())
            continue;
        RuntimeUseStringCandidate candidate;
        const auto &first = witnesses.begin()->second;
        candidate.use = first.use;
        candidate.value = first.value;
        candidate.eligible_runs = runs.size();
        bool same = true;
        for (auto &[run, stream] : witnesses)
        {
            if (stream.value != candidate.value)
            {
                same = false;
                break;
            }
            candidate.witnesses.push_back(stream.use);
            if (stream.use.producer != UseProducer::MODELED_ARGUMENT)
                candidate.read_fragments.push_back(std::move(stream.parts));
        }
        if (same)
            result.push_back(std::move(candidate));
    }
    if (valid)
        *valid = true;
    return result;
}
}

std::vector<RuntimeUseStringCandidate>
hybrid_consensus_native_read_strings(const TargetEvidence &evidence, size_t minimum_length,
                                     size_t maximum_length)
{
    std::vector<Run> runs;
    for (const auto &run : evidence.runs)
    {
        const auto &out = run.outcome;
        if (!run.ran || out.native_region || !out.temporal_observation_available ||
            !out.temporal_capture_complete || out.temporal_capture_truncated ||
            !out.memory_observation_available || out.data_trace_filtered ||
            out.data_trace_truncated)
            return {};
        runs.emplace_back(run.provenance.run_id, run.provenance.seed);
    }
    // Completed environment models may supply malloc/free semantics. This
    // admits temporal observations, never the model-free proof contract.
    return derive_streams(evidence.scope.function_start, runs, {&evidence.events}, minimum_length,
                          maximum_length);
}

namespace
{
bool bounded_prefix(const NativeTemporalStringRun &run)
{
    const auto &out = run.outcome;
    const auto end = out.native_temporal_prefix_end;
    if (!out.native_temporal_prefix_complete || !end || run.events.execution.empty() ||
        run.events.execution.size() > 4096 || run.events.edges.size() > 4096 ||
        run.events.uses.size() > TemporalMemory::use_limit || run.events.data.size() > 65536 ||
        run.events.allocations.size() > TemporalMemory::allocation_limit)
        return false;
    const bool boundary = out.region_boundary && !out.returned && !out.native_temporal_complete &&
                          out.stop_reason == RAX_STOP_STOPPED &&
                          out.stop_pc == out.region_boundary_target &&
                          run.events.execution.back().pc == out.region_boundary_source;
    if (!boundary && !(out.returned && out.native_temporal_complete && !out.region_boundary &&
                       out.stop_reason == RAX_STOP_UNTIL))
        return false;
    uint64_t last = 0, previous = 0;
    bool first = true;
    const auto before_end = [&](uint64_t sequence)
    {
        if (sequence >= end)
            return false;
        last = std::max(last, sequence);
        return true;
    };
    for (const auto &point : run.events.execution)
    {
        if (point.run_id != run.run_id || point.seed != run.seed || !point.size ||
            point.size > 15 || (!first && point.sequence <= previous) ||
            !before_end(point.sequence))
            return false;
        previous = point.sequence;
        first = false;
    }
    for (const auto &use : run.events.uses)
        if (!before_end(use.sequence))
            return false;
    for (const auto &access : run.events.data)
        if (!before_end(access.sequence))
            return false;
    for (const auto &allocation : run.events.allocations)
        if (!before_end(allocation.allocated) ||
            (allocation.live ? allocation.released != 0
                             : (allocation.released <= allocation.allocated ||
                                !before_end(allocation.released))))
            return false;
    for (const auto &edge : run.events.edges)
        if (!(boundary && edge.sequence == end && edge.from == out.region_boundary_source &&
              edge.to == out.region_boundary_target) &&
            !before_end(edge.sequence))
            return false;
    return last + 1 == end;
}

NativeTemporalStringProjection
project_native_strings(const std::vector<NativeTemporalStringRun> &source, size_t minimum_length,
                       size_t maximum_length, bool prefix)
{
    NativeTemporalStringProjection result;
    auto reject = [&](const char *reason)
    {
        result.reason = reason;
        result.captures.clear();
        return result;
    };
    if (source.empty() || source.size() > 16 || !minimum_length ||
        maximum_length < minimum_length || maximum_length > TemporalMemory::snapshot_limit)
        return reject("invalid bounded corpus");
    using Binding = std::tuple<uint64_t, EmuSummaryKind, std::string>;
    std::vector<Binding> expected;
    std::vector<Run> identities;
    std::vector<const EmuEvents *> events;
    std::set<uint64_t> captures;
    const auto &first = source.front();
    for (const auto &run : source)
    {
        const auto &out = run.outcome;
        if (!run.capture || !captures.insert(run.capture).second ||
            !result.captures.emplace(Run{run.run_id, run.seed}, run.capture).second)
            return reject("duplicate or absent capture/run identity");
        if (!run.context || !run.image_hash || !run.generation || run.context != first.context ||
            run.image_hash != first.image_hash || run.generation != first.generation)
            return reject("incompatible capture scopes");
        const bool complete = out.native_temporal_complete && out.returned &&
                              !out.region_boundary && out.stop_reason == RAX_STOP_UNTIL;
        if (!run.ran || !out.native_region || !out.region_identity ||
            !out.native_temporal_requested || !(prefix ? bounded_prefix(run) : complete) ||
            !out.stop_valid || out.stop_status != RAX_OK || out.conclusive() ||
            out.temporal_capture_complete || out.consumed_context_complete ||
            !out.temporal_observation_available || !out.memory_observation_available ||
            out.temporal_capture_truncated || out.data_trace_truncated || out.data_trace_filtered ||
            out.region_code_changed || out.function_boundary || out.permission_violation ||
            out.cancelled || out.escaped_image || out.unmodeled_external ||
            out.environment_model_failure)
            return reject("incomplete or incompatible temporal capture");
        if (run.bindings.empty() || run.bindings.size() > 32)
            return reject("invalid model contract");
        std::vector<Binding> actual;
        std::set<uint64_t> addresses;
        for (const auto &binding : run.bindings)
        {
            if (!binding.address || binding.kind == EmuSummaryKind::UNMODELED ||
                binding.kind > EmuSummaryKind::STRNLEN || binding.name.empty() ||
                binding.name.size() > 128 || !addresses.insert(binding.address).second)
                return reject("invalid model contract");
            actual.emplace_back(binding.address, binding.kind, binding.name);
        }
        std::sort(actual.begin(), actual.end());
        if (expected.empty())
            expected = actual;
        else if (actual != expected)
            return reject("incompatible model contracts");
        const auto matching = [&](const auto &row)
        { return row.run_id == run.run_id && row.seed == run.seed; };
        if (!std::all_of(run.events.uses.begin(), run.events.uses.end(), matching) ||
            !std::all_of(run.events.data.begin(), run.events.data.end(), matching) ||
            !std::all_of(run.events.allocations.begin(), run.events.allocations.end(), matching) ||
            !std::all_of(run.events.edges.begin(), run.events.edges.end(), matching))
            return reject("foreign event identity");
        identities.emplace_back(run.run_id, run.seed);
        events.push_back(&run.events);
    }
    bool valid = false;
    result.observations = derive_streams(first.context, identities, events, minimum_length,
                                         maximum_length, &valid, &first.bindings);
    if (!valid)
        return reject("invalid or over-quota event ledger");
    result.available = true;
    result.reason =
        prefix
            ? "completed-prefix named-model observations; execution return not implied; no function or VM proof publication"
            : "completed named-model observations; no function or VM proof publication";
    return result;
}
}

NativeTemporalStringProjection
hybrid_native_temporal_strings(const std::vector<NativeTemporalStringRun> &source,
                               size_t minimum_length, size_t maximum_length)
{
    return project_native_strings(source, minimum_length, maximum_length, false);
}
NativeTemporalStringProjection
hybrid_native_temporal_prefix_strings(const std::vector<NativeTemporalStringRun> &source,
                                      size_t minimum_length, size_t maximum_length)
{
    return project_native_strings(source, minimum_length, maximum_length, true);
}
} // namespace chernobog::hybrid
