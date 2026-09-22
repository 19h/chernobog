#include "native_region.hpp"
#include <algorithm>
#include <deque>
#include <map>
#include <set>

namespace chernobog::vm
{
namespace
{
uint64_t native_identity(const NativeRegion &region)
{
    uint64_t identity = UINT64_C(14695981039346656037);
    auto mix = [&](uint64_t value)
    {
        for (unsigned n = 0; n < 8; ++n)
        {
            identity ^= uint8_t(value >> (8 * n));
            identity *= UINT64_C(1099511628211);
        }
    };
    mix(region.image_hash());
    mix(region.generation());
    mix(region.entry());
    for (const auto &head : region.heads())
    {
        mix(head.address);
        mix(head.bytes.size());
        for (uint8_t byte : head.bytes)
            mix(byte);
    }
    return identity ? identity : 1;
}
}
const NativeHead *NativeRegion::at(uint64_t address) const
{
    const auto found =
        std::lower_bound(heads_.begin(), heads_.end(), address,
                         [](const NativeHead &head, uint64_t ea) { return head.address < ea; });
    return found != heads_.end() && found->address == address ? &*found : nullptr;
}
bool NativeRegion::matches(const hybrid::ProgramImage &image) const
{
    return available() && image.arch == arch_ && !image.big_endian &&
           image.generation == generation_ &&
           hybrid::hybrid_program_content_hash(image) == image_hash_;
}
NativeRegion plan_native_region(const hybrid::ProgramImage &image, const hybrid::RaxApi *api,
                                uint64_t entry, size_t maximum_heads, const NativeDecoder &decoder)
{
    using namespace hybrid;
    NativeRegion result;
    result.entry_ = entry;
    result.arch_ = image.arch;
    result.generation_ = image.generation;
    auto frontier = [&](uint64_t site, const char *reason)
    { result.frontiers_.push_back({site, reason}); };
    const bool is64 = image.arch == HybridArch::X86_64;
    if ((!is64 && image.arch != HybridArch::X86_32) || image.big_endian ||
        (!decoder && (!api || !api->decode)) || entry == bad_address)
    {
        frontier(entry, "unsupported_request");
        return result;
    }
    // The linked stateless RAX oracle currently decodes x86 through its 64-bit
    // lifter even for RAX_MODE_32. Never use that oracle to admit 32-bit spans.
    if (!is64 && !decoder)
    {
        frontier(entry, "mode_aware_decoder_required");
        return result;
    }
    maximum_heads = std::min(maximum_heads, size_t(4096));
    if (!maximum_heads)
    {
        result.truncated_ = true;
        frontier(entry, "head_limit");
        return result;
    }
    result.image_hash_ = hybrid_program_content_hash(image);
    std::deque<uint64_t> pending{entry};
    std::set<uint64_t> scheduled{entry};
    std::map<uint64_t, uint64_t> spans;
    auto schedule = [&](uint64_t address)
    {
        if (scheduled.count(address))
            return;
        if (scheduled.size() == maximum_heads)
        {
            result.truncated_ = true;
            frontier(address, "head_limit");
            return;
        }
        scheduled.insert(address);
        pending.push_back(address);
    };
    while (!pending.empty())
    {
        const uint64_t address = pending.front();
        pending.pop_front();
        const auto *segment = image.segment_at(address);
        if (!segment || segment->kind == HybridSegmentKind::EXTERNAL ||
            !segment->has_perm(HybridSegPerm::EXEC))
        {
            frontier(address, "nonexecutable_or_external");
            continue;
        }
        if (segment->bitness != (is64 ? 2 : 1) || (!is64 && address > UINT32_MAX))
        {
            frontier(address, "mode_boundary");
            continue;
        }
        const auto view = image.loaded_view(address, 15);
        if (!view.data || !view.size)
        {
            frontier(address, "unloaded_code");
            continue;
        }
        rax_decoded decoded{};
        const bool decoded_ok = decoder ? decoder(address, view.data, view.size, decoded)
                                        : api->decode(RAX_ARCH_X86, RAX_MODE_64, address, view.data,
                                                      view.size, &decoded) == RAX_OK;
        if (!decoded_ok || decoded.valid != 1 || !decoded.size || decoded.is_indirect > 1 ||
            decoded.has_target > 1 || decoded.size > 15 || decoded.size > view.size ||
            address >= bad_address - decoded.size || address + decoded.size > segment->end ||
            (!is64 && address + decoded.size > uint64_t(UINT32_MAX) + 1))
        {
            frontier(address, "invalid_decode");
            continue;
        }
        if (decoded.flow < RAX_FLOW_FALLTHROUGH || decoded.flow > RAX_FLOW_RETURN)
        {
            frontier(address, "unsupported_control");
            continue;
        }
        const auto next = spans.lower_bound(address);
        if ((next != spans.end() && next->first < address + decoded.size) ||
            (next != spans.begin() && std::prev(next)->second > address))
        {
            frontier(address, "overlapping_decode");
            continue;
        }
        spans.emplace(address, address + decoded.size);
        result.heads_.push_back({address, {view.data, view.data + decoded.size}, decoded.flow});
        if (decoded.flow == RAX_FLOW_BRANCH || decoded.flow == RAX_FLOW_COND_BRANCH ||
            decoded.flow == RAX_FLOW_CALL)
        {
            if (decoded.has_target && !decoded.is_indirect && decoded.target != bad_address)
                schedule(decoded.target);
            else
                frontier(address, "unknown_direct_target");
        }
        if (decoded.flow == RAX_FLOW_FALLTHROUGH || decoded.flow == RAX_FLOW_COND_BRANCH ||
            decoded.flow == RAX_FLOW_CALL || decoded.flow == RAX_FLOW_INDIRECT_CALL)
            schedule(address + decoded.size);
        if (decoded.flow == RAX_FLOW_INDIRECT_JUMP || decoded.flow == RAX_FLOW_INDIRECT_CALL)
            frontier(address, "indirect_targets_not_enumerated");
        if (decoded.flow == RAX_FLOW_RETURN)
            frontier(address, "return_targets_not_enumerated");
    }
    std::sort(result.heads_.begin(), result.heads_.end(),
              [](const auto &a, const auto &b) { return a.address < b.address; });
    // Noncryptographic publication label; runtime admission also requires exact
    // instruction bytes. This number is never an equivalence proof or cache key.
    result.identity_ = native_identity(result);
    return result;
}
NativeExtension extend_native_region(const NativeRegion &previous,
                                     const hybrid::ProgramImage &image, const hybrid::RaxApi *api,
                                     uint64_t source, uint64_t target, size_t maximum_heads,
                                     const NativeDecoder &decoder)
{
    NativeExtension result;
    result.region = previous;
    auto reject = [&](const char *reason)
    {
        result.reason = reason;
        return result;
    };
    if (!previous.matches(image))
        return reject("stale_region");
    const auto *head = previous.at(source);
    if (!head || (head->flow != RAX_FLOW_INDIRECT_JUMP && head->flow != RAX_FLOW_INDIRECT_CALL &&
                  head->flow != RAX_FLOW_RETURN))
        return reject("source_not_indirect_or_return");
    if (previous.at(target))
        return reject("target_already_admitted");
    maximum_heads = std::min(maximum_heads, size_t(4096));
    if (previous.heads_.size() >= maximum_heads)
        return reject("head_limit");
    const auto addition =
        plan_native_region(image, api, target, maximum_heads - previous.heads_.size(), decoder);
    if (!addition.available())
    {
        result.reason = addition.frontiers_.empty() ? "target_not_admissible"
                                                    : addition.frontiers_.front().reason;
        return result;
    }
    std::map<uint64_t, NativeHead> merged;
    for (const auto &old : previous.heads_)
        merged.emplace(old.address, old);
    for (const auto &candidate : addition.heads_)
    {
        auto next = merged.lower_bound(candidate.address);
        if (next != merged.end() && next->first == candidate.address)
        {
            if (next->second.bytes != candidate.bytes || next->second.flow != candidate.flow)
                return reject("conflicting_decode");
            continue;
        }
        if ((next != merged.end() && next->first < candidate.address + candidate.bytes.size()) ||
            (next != merged.begin() &&
             std::prev(next)->first + std::prev(next)->second.bytes.size() > candidate.address))
            return reject("overlapping_decode");
        merged.emplace(candidate.address, candidate);
    }
    std::set<std::pair<uint64_t, std::string>> frontiers;
    for (const auto &f : previous.frontiers_)
        frontiers.emplace(f.site, f.reason);
    for (const auto &f : addition.frontiers_)
        frontiers.emplace(f.site, f.reason);
    if (frontiers.size() > 8192)
        return reject("frontier_limit");
    result.region.heads_.clear();
    for (const auto &item : merged)
        result.region.heads_.push_back(item.second);
    result.region.frontiers_.clear();
    for (const auto &f : frontiers)
        result.region.frontiers_.push_back({f.first, f.second});
    result.region.truncated_ = previous.truncated_ || addition.truncated_;
    result.region.identity_ = native_identity(result.region);
    result.added_heads = result.region.heads_.size() - previous.heads_.size();
    result.admitted = true;
    result.reason = "observed_native_target";
    return result;
}
} // namespace chernobog::vm
