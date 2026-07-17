#pragma once

#include <z3++.h>

#include <cstdint>
#include <optional>

namespace chernobog {
namespace z3_utils {

// Return a bit-vector value only when the current solver constraints admit
// exactly one value. The caller owns the surrounding solver assertions.
// Two satisfiability checks are sufficient: obtain one model, then exclude
// its value and require the remaining domain to be unsatisfiable.
inline std::optional<uint64_t> solve_unique_bv(z3::solver &solver,
                                                const z3::expr &expr)
{
    if ( !expr.is_bv() || expr.get_sort().bv_size() > 64U )
        return std::nullopt;

    if ( solver.check() != z3::sat )
        return std::nullopt;

    const z3::expr value = solver.get_model().eval(expr, true);
    if ( !value.is_numeral() )
        return std::nullopt;

    uint64_t concrete = 0;
    if ( !Z3_get_numeral_uint64(expr.ctx(), value, &concrete) )
        return std::nullopt;

    solver.push();
    solver.add(expr != expr.ctx().bv_val(concrete,
                                         expr.get_sort().bv_size()));
    const z3::check_result alternative = solver.check();
    solver.pop();

    return alternative == z3::unsat
        ? std::optional<uint64_t>(concrete)
        : std::nullopt;
}

} // namespace z3_utils
} // namespace chernobog
