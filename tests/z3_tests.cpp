#include "common/z3_utils.h"

#include <z3++.h>

#include <cstdint>
#include <cstdio>

namespace {

int failures = 0;

void check(bool condition, const char *description)
{
    if ( condition )
        return;
    std::fprintf(stderr, "FAIL: %s\n", description);
    ++failures;
}

void test_unique_model_values()
{
    z3::context context;
    z3::solver solver(context);
    const z3::expr x = context.bv_const("x", 8);
    const z3::expr y = context.bv_const("y", 8);

    check(!chernobog::z3_utils::solve_unique_bv(solver, x).has_value(),
          "an unconstrained model value is not unique");

    solver.add(x == 7);
    const auto seven = chernobog::z3_utils::solve_unique_bv(solver, x);
    check(seven.has_value() && *seven == 7,
          "an equality-constrained value is unique");
    check(solver.check() == z3::sat,
          "uniqueness probing preserves caller solver assertions");

    solver.reset();
    solver.add(x == y);
    check(!chernobog::z3_utils::solve_unique_bv(solver, x).has_value(),
          "an equality between two free variables remains multi-valued");

    solver.reset();
    solver.add(x == 1 || x == 2);
    check(!chernobog::z3_utils::solve_unique_bv(solver, x).has_value(),
          "a finite two-value domain is not unique");

    solver.reset();
    const auto zero = chernobog::z3_utils::solve_unique_bv(solver, x - x);
    check(zero.has_value() && *zero == 0,
          "an algebraically constant expression is unique");

    solver.reset();
    solver.add(x == 1);
    solver.add(x == 2);
    check(!chernobog::z3_utils::solve_unique_bv(solver, x).has_value(),
          "an unsatisfiable state has no value");

    solver.reset();
    const z3::expr wide = context.bv_const("wide", 65);
    check(!chernobog::z3_utils::solve_unique_bv(solver, wide).has_value(),
          "values wider than uint64_t are rejected");

    const z3::expr max64 = context.bv_val(UINT64_MAX, 64);
    const auto maximum = chernobog::z3_utils::solve_unique_bv(solver, max64);
    check(maximum.has_value() && *maximum == UINT64_MAX,
          "the full uint64_t domain endpoint is supported");
}

} // namespace

int main()
{
    test_unique_model_values();
    if ( failures != 0 )
        std::fprintf(stderr, "%d Z3 test(s) failed\n", failures);
    return failures == 0 ? 0 : 1;
}
