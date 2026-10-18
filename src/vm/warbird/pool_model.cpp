#include "pool_model.hpp"
#include <stdexcept>

namespace chernobog::warbird
{
namespace
{
void validate(const z3::expr &a, const z3::expr &b, const z3::expr &c, const z3::expr &d)
{
    for (const auto *e : {&a, &b, &c, &d})
        if (&e->ctx() != &a.ctx() || !e->is_bv() || e->get_sort().bv_size() != 64)
            throw std::invalid_argument("invalid pool model operand");
}
}
std::vector<PoolOutcome> pool_allocate(const PoolState &state, const z3::expr &type,
                                       const z3::expr &bytes, const z3::expr &tag,
                                       const z3::expr &address)
{
    validate(type, bytes, tag, address);
    auto &c = type.ctx();
    auto n = [&](uint64_t v) { return c.bv_val(v, 64); };
    const auto supported = (type == n(0) || type == n(1) || type == n(512)) && bytes != n(0) &&
                           tag.extract(31, 0) != c.bv_val(0, 32);
    std::vector<PoolOutcome> out;
    out.push_back({state,
                   !supported,
                   n(0),
                   {},
                   "unsupported pool type, flags or zero-sized/tagged allocation"});
    out.push_back({state, supported, n(0), {}, {}});
    if (state.blocks.size() >= 64)
    {
        out.push_back({state, supported, n(0), {}, "pool allocation history quota"});
        return out;
    }
    // Pointer identity is symbolic. Freed addresses may be reused, but live
    // blocks must be disjoint. Every returned region is non-wrapping.
    auto valid = supported && address != n(0) && z3::ugt(address + bytes, address) &&
                 (address & n(15)) == n(0) &&
                 z3::ite(z3::uge(bytes, n(4096)), (address & n(4095)) == n(0),
                         z3::ule((address & n(4095)) + bytes, n(4096)));
    for (const auto &block : state.blocks)
        if (block.live)
            valid = valid && (z3::ule(address + bytes, block.address) ||
                              z3::ule(block.address + block.bytes, address));
    auto allocated = state;
    allocated.blocks.push_back({address, bytes, z3::zext(tag.extract(31, 0), 32), true});
    out.push_back({std::move(allocated), valid, address, state.blocks.size(), {}});
    return out;
}
std::vector<PoolOutcome> pool_free(const PoolState &state, const z3::expr &address,
                                   const z3::expr &tag, const z3::expr &void_result)
{
    validate(address, tag, void_result, address);
    auto &c = address.ctx();
    auto matched = c.bool_val(false);
    std::vector<PoolOutcome> out;
    for (size_t n = 0; n < state.blocks.size(); ++n)
    {
        const auto &block = state.blocks[n];
        if (!block.live)
            continue;
        const auto equal =
            address == block.address && tag.extract(31, 0) == block.tag.extract(31, 0);
        matched = matched || equal;
        auto freed = state;
        freed.blocks[n].live = false;
        out.push_back({std::move(freed), equal, void_result, n, {}});
    }
    out.push_back(
        {state, !matched, void_result, {}, "pool free has no matching live base and tag"});
    return out;
}
}
