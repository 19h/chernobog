#pragma once

#include <z3++.h>

#include <cstdint>
#include <optional>

namespace chernobog {
namespace z3_utils {

// Prove fixed-width bit-vector equivalence. SAT, UNKNOWN, malformed input,
// context mismatch, and every Z3 exception fail closed.
inline bool prove_bv_equivalent(const z3::expr &left,
                                const z3::expr &right,
                                unsigned timeout_ms = 0) noexcept
{
    try
    {
        if ( &left.ctx() != &right.ctx() || !left.is_bv() || !right.is_bv()
          || left.get_sort().bv_size() != right.get_sort().bv_size() )
        {
            return false;
        }

        z3::solver proof(left.ctx());
        if ( timeout_ms != 0 )
        {
            z3::params parameters(left.ctx());
            parameters.set("timeout", timeout_ms);
            proof.set(parameters);
        }
        proof.add(left != right);
        return proof.check() == z3::unsat;
    }
    catch ( ... )
    {
        return false;
    }
}

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
