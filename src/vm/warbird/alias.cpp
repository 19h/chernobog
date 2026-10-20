#include "alias.hpp"
#include <algorithm>
#include <stdexcept>

namespace chernobog::warbird
{
AddressRanges merge_ranges(AddressRanges ranges)
{
    if (ranges.size() > 4096)
        throw std::invalid_argument("address range quota");
    for (const auto &[begin, end] : ranges)
        if (begin >= end)
            throw std::invalid_argument("invalid address range");
    std::sort(ranges.begin(), ranges.end());
    AddressRanges out;
    for (const auto &[begin, end] : ranges)
        if (!out.empty() && begin <= out.back().second)
            out.back().second = std::max(out.back().second, end);
        else
            out.emplace_back(begin, end);
    return out;
}
z3::expr overlaps(const z3::expr &address, unsigned bytes, const AddressRanges &ranges)
{
    if (!bytes || bytes > 16)
        throw std::invalid_argument("invalid alias query");
    return overlaps(address, address.ctx().bv_val(bytes, 64), ranges);
}
z3::expr overlaps(const z3::expr &address, const z3::expr &bytes, const AddressRanges &ranges)
{
    if (!address.is_bv() || address.get_sort().bv_size() != 64 || &address.ctx() != &bytes.ctx() ||
        !bytes.is_bv() || bytes.get_sort().bv_size() != 64 || ranges.size() > 256)
        throw std::invalid_argument("invalid alias span");
    auto &ctx = address.ctx();
    auto result = ctx.bool_val(false);
    const auto last = address + bytes - ctx.bv_val(1, 64);
    const auto wraps = z3::ult(last, address);
    for (const auto &[begin, end] : ranges)
    {
        if (begin >= end)
            throw std::invalid_argument("invalid address range");
        const auto starts_before_end = z3::ult(address, ctx.bv_val(end, 64));
        const auto ends_after_start = z3::uge(last, ctx.bv_val(begin, 64));
        result = result || z3::ite(wraps, starts_before_end || ends_after_start,
                                   starts_before_end && ends_after_start);
    }
    z3::params params(ctx);
    params.set("max_steps", 10000u);
    try
    {
        return (bytes != ctx.bv_val(0, 64) && result).simplify(params);
    }
    catch (const z3::exception &)
    {
        return bytes != ctx.bv_val(0, 64) && result;
    }
}
AliasResult AliasOracle::classify(const z3::expr &address, unsigned bytes, const z3::expr &domain,
                                  const AddressRanges &ranges)
{
    if (&address.ctx() != &context_ || &domain.ctx() != &context_ || !domain.is_bool())
        throw std::invalid_argument("invalid alias domain");
    const auto overlap = overlaps(address, bytes, ranges);
    if (overlap.is_false() || domain.is_false())
        return AliasResult::DISJOINT;
    if (overlap.is_true() && domain.is_true())
        return AliasResult::MAY_ALIAS;
    Key key{address.id(), domain.id(), bytes, ranges};
    if (const auto it = cache_.find(key); it != cache_.end())
        return it->second.result;
    if (queries_ >= budget_ || cache_.size() >= 1024)
        return AliasResult::UNKNOWN;
    ++queries_;
    z3::solver solver(address.ctx());
    solver.set("timeout", query_timeout_ms_);
    solver.set("rlimit", 20000u);
    solver.add(domain && overlap);
    const auto result = solver.check();
    const auto classified = result == z3::unsat ? AliasResult::DISJOINT
                            : result == z3::sat ? AliasResult::MAY_ALIAS
                                                : AliasResult::UNKNOWN;
    cache_.emplace(std::move(key), Entry{address, domain, classified});
    return classified;
}
}
