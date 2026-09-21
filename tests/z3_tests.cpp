#include "common/z3_utils.h"

#include <z3++.h>

#include <cstdint>
#include <cstdio>

namespace {

int failures = 0;

struct QueryCollector : chernobog::solver_evidence::Collector
{
    std::vector<chernobog::solver_evidence::Row> rows;
    bool fail = false;
    bool accepts(const chernobog::solver_evidence::Origin &) override
    { if (fail) throw 1; return true; }
    void publish(const chernobog::solver_evidence::Origin &, chernobog::solver_evidence::Row row) override
    { rows.push_back(std::move(row)); }
};

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

void test_query_evidence()
{
    using namespace chernobog::solver_evidence;
    QueryCollector captured;
    collector = &captured;
    z3::context context;
    z3::solver solver(context);
    const auto x = context.bv_const("query_x", 8);
    solver.add(x == 165);
    check(chernobog::solver_evidence::check(solver, "unscoped") == z3::sat && captured.rows.empty(),
          "unscoped queries must not inherit an invented source location");
    {
      Scope scope({7, 0x1000, 0x1004, 3, "unit query"});
      check(chernobog::solver_evidence::check(solver, "actual assignment") == z3::sat,
            "observed check preserves SAT");
      const auto &row = captured.rows.back();
      check(row.at("result") == "sat" && row.at("formula_complete") == "true"
            && row.at("model_complete") == "true" && row.at("model_0_symbol") == "query_x"
            && row.at("model_0_sort") == "BV8" && row.at("model_0_value") == "#xa5",
            "SAT evidence retains an exact typed satisfying assignment");
      z3::context independent;
      z3::solver replay(independent);
      replay.from_string(row.at("formula").c_str());
      check(replay.check() == z3::sat, "complete recorded formula independently replays as SAT");
      replay.add(independent.bv_const("query_x", 8) != 165);
      check(replay.check() == z3::unsat, "recorded formula preserves the original constraint");
      solver.push(); solver.add(x != 165);
      check(chernobog::solver_evidence::check(solver, "actual exclusion") == z3::unsat,
            "observed check preserves UNSAT");
      check(captured.rows.back().at("result") == "unsat"
            && !captured.rows.back().count("model_0_symbol"), "UNSAT must not borrow an earlier SAT model");
      solver.pop();
      check(solver.check() == z3::sat && solver.get_model().eval(x).get_numeral_uint64() == 165,
            "inspection preserves caller assertions, scopes and model");
      captured.fail = true;
      check(chernobog::solver_evidence::check(solver, "collector fails") == z3::sat,
            "collector exceptions cannot change a solver result");
      captured.fail = false;

      z3::solver bounded(context);
      z3::params parameters(context); parameters.set("rlimit", 1u); bounded.set(parameters);
      const auto a = context.bv_const("budget_a", 32), b = context.bv_const("budget_b", 32);
      bounded.add(a * b == 1234567);
      check(chernobog::solver_evidence::check(bounded, "resource control", "rlimit=1") == z3::unknown,
            "resource exhaustion remains UNKNOWN");
      check(captured.rows.back().at("result") == "unknown" && !captured.rows.back().at("reason").empty()
            && !captured.rows.back().count("model_0_symbol"), "UNKNOWN retains its reason without a model");

      z3::solver large(context);
      for (unsigned i = 0; i < 64; ++i)
      {
        const std::string name = std::string(123, 'q') + std::to_string(10000 + i);
        large.add(context.bv_const(name.c_str(), 8) == int(i));
      }
      check(chernobog::solver_evidence::check(large, "display quotas") == z3::sat,
            "display caps do not change satisfiability");
      const auto &limited = captured.rows.back();
      check(limited.at("formula_complete") == "false" && limited.at("formula").size() == formula_limit
            && limited.at("model_constants_omitted") == "32" && limited.at("model_complete") == "false",
            "formula and model quotas report incomplete display explicitly");
      z3::solver deep(context);
      z3::expr expression = x;
      for (unsigned i = 0; i < 70; ++i) expression = expression + 1;
      deep.add(expression == 70);
      check(chernobog::solver_evidence::check(deep, "AST bound") == z3::sat
            && captured.rows.back().at("formula_complete") == "false"
            && !captured.rows.back().count("formula"), "oversized AST serialization is omitted, not executed again");
    }
    check(origin == nullptr, "query origin restores after its owning scope");
    collector = nullptr;
}

void test_fail_closed_equivalence()
{
    z3::context context;
    const z3::expr x = context.bv_const("eq_x", 32);
    const z3::expr y = context.bv_const("eq_y", 32);
    const z3::expr carry_form = (x ^ y) + ((x & y) * context.bv_val(2, 32));

    check(chernobog::z3_utils::prove_bv_equivalent(carry_form, x + y, 100),
          "equivalent bit-vector expressions require an UNSAT mismatch proof");
    check(!chernobog::z3_utils::prove_bv_equivalent(x & y, x + y, 100),
          "a SAT mismatch rejects a non-equivalent rewrite");

    const z3::expr narrow = context.bv_const("eq_narrow", 16);
    check(!chernobog::z3_utils::prove_bv_equivalent(x, narrow, 100),
          "different bit widths fail closed");

    z3::context other_context;
    const z3::expr foreign = other_context.bv_const("eq_foreign", 32);
    check(!chernobog::z3_utils::prove_bv_equivalent(x, foreign, 100),
          "different Z3 contexts fail closed");
}

void test_recurrent_selector_normalization()
{
    // Exact 32-bit state-0 update and decoder from the LOCOPT microcode of
    // obfuscator_sample!0x82AF0. SP and private state remain arbitrary.
    z3::context context;
    const auto bv = [&](uint32_t value) {
        return context.bv_val(static_cast<uint64_t>(value), 32);
    };
    const z3::expr sp = context.bv_const("recurrent_sp", 32);
    const z3::expr state = context.bv_const("recurrent_state", 32);
    const z3::expr r12 = bv(0xBE816175U) * ((sp + bv(12)) ^ bv(0xF978AD7DU));
    const z3::expr r14 =
        (bv(0xC2CC86A3U) * ((sp + bv(8)) ^ bv(0x4AE62630U))).rotate_left(7);
    const z3::expr mixed =
        bv(0x279D2A17U) * (state ^ bv(0x50256DAEU)) - bv(0x2E6FD155U);
    const z3::expr next_state = mixed ^ z3::lshr(mixed, bv(11));
    const z3::expr next_aux =
        (next_state ^ r12 ^ r14) ^ z3::lshr(next_state, bv(13)) ^ bv(0x318EA088U);
    const auto decode = [&](const z3::expr &decoder_r14) {
        return bv(0x83DAC1F1U)
            * ((next_aux ^ (decoder_r14 ^ ((r12 ^ next_state)
                ^ z3::lshr(next_state, bv(13))))) ^ bv(0x2ED4B00EU))
            - bv(0x0E5A9399U);
    };
    const z3::expr selector = decode(r14);
    z3::params parameters(context);
    parameters.set("bv_sort_ac", true);
    const z3::expr reduced = selector.simplify(parameters);
    uint64_t value = 0;
    check(reduced.is_numeral_u64(value) && value == 141,
          "AC normalization cancels the observed recurrence to selector 141");
    check(chernobog::z3_utils::prove_bv_equivalent(selector, bv(141), 1000),
          "independent solver proves the original recurrence equals 141");
    check(z3::ugt(selector, bv(248)).simplify(parameters).is_false(),
          "normalized valid recurrence excludes the unsigned dispatcher self-edge");
    z3::solver corrupted(context);
    corrupted.set("timeout", 1000U);
    corrupted.add(!z3::ugt(decode(r14 ^ bv(1)), bv(248)).simplify(parameters));
    check(corrupted.check() == z3::unsat,
          "a corrupted selector-register restoration retains its true self-edge");

    const z3::expr unknown = context.bv_const("recurrent_unknown", 32);
    const z3::expr unknown_selector = (selector ^ unknown).simplify(parameters);
    check(!unknown_selector.is_numeral_u64(value),
          "normalization preserves an unconstrained selector dependency");
    z3::solver solver(context);
    solver.set("timeout", 1000U);
    solver.add(z3::ugt(unknown_selector, bv(248)));
    check(solver.check() == z3::sat,
          "an unconstrained normalized selector can take the dispatcher self-edge");
    solver.reset();
    solver.add(!z3::ugt(unknown_selector, bv(248)));
    check(solver.check() == z3::sat,
          "an unconstrained normalized selector can also continue to the switch");
}

} // namespace

int main()
{
    test_query_evidence();
    test_unique_model_values();
    test_fail_closed_equivalence();
    test_recurrent_selector_normalization();
    if ( failures != 0 )
        std::fprintf(stderr, "%d Z3 test(s) failed\n", failures);
    return failures == 0 ? 0 : 1;
}
