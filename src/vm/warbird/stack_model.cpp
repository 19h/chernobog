#include "stack_model.hpp"
#include <stdexcept>

namespace chernobog::warbird
{
StackUpdate update_stack(const StackState &before, const z3::expr &minimum, uint64_t limit)
{
    for (const auto *v : {&before.floor, &before.native_top, &before.reserved, &minimum})
        if (&v->ctx() != &minimum.ctx() || !v->is_bv() || v->get_sort().bv_size() != 64)
            throw std::invalid_argument("invalid dispatcher stack state");
    if (limit == 0 || limit > 0x10000)
        throw std::invalid_argument("invalid dispatcher stack quota");
    auto &ctx = minimum.ctx();
    auto n = [&](uint64_t v) { return ctx.bv_val(v, 64); };
    const auto grows = minimum != n(0) && z3::ult(minimum, before.floor);
    const auto delta = before.floor - minimum;
    // Native MOV EAX,EBX truncates the subtraction before 16-byte rounding.
    const auto rounded = (z3::zext(delta.extract(31, 0), 32) + n(15)) & n(~uint64_t(15));
    const auto reserved = before.reserved + rounded;
    const auto new_top = before.native_top - rounded;
    const auto within_limit = z3::ule(delta, n(limit) - before.reserved) &&
                              z3::ule(rounded, n(limit) - before.reserved) &&
                              z3::ule(rounded, before.floor) && z3::ule(rounded, before.native_top);
    return {{z3::ite(grows, new_top + n(40), before.floor),
             z3::ite(grows, new_top, before.native_top), z3::ite(grows, reserved, before.reserved)},
            z3::ite(grows, n(0), minimum),
            before.floor == before.native_top + n(40) &&
                z3::ule(before.native_top, n(UINT64_MAX - 40)) &&
                z3::ule(before.reserved, n(limit)) && (!grows || within_limit),
            grows};
}
}
