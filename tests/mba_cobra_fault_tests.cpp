#include "deobf/analysis/mba_cobra.hpp"
#include "deobf/analysis/mba_cobra_test_hooks.hpp"
#include "mba_cobra_fixtures.hpp"
#include <cobra/core/Expr.h>
#include <cstdio>
#include <cstring>
#include <stdexcept>

using namespace chernobog::mba_smt;
namespace cb = chernobog::mba_smt::cobra_backend;
namespace
{
int failures = 0;
void check(bool value, const char *message)
{
    if (!value)
    {
        std::fprintf(stderr, "FAIL: %s\n", message);
        ++failures;
    }
}
}
int main(int argc, char **argv)
{
    auto cases = fixtures::make();
    const auto &fixture = cases.front();
    const auto original = fixture.program.blocks[0].statements[0].value;
    cb::Request request;
    request.deadline = cb::Clock::now() + std::chrono::seconds(10);
    detail::CobraTestHooks hooks;
    struct Restore
    {
        detail::CobraTestHooks *old;
        ~Restore() { detail::cobra_test_hooks = old; }
    } restore{detail::cobra_test_hooks};
    detail::cobra_test_hooks = &hooks;
    if (argc > 1)
    {
        for (const auto &f : cases)
            if (std::strcmp(f.id, argv[1]) == 0)
            {
                hooks.generated = [](cobra::SimplifyOutcome &result)
                {
                    if (result.expr)
                        std::fprintf(stderr, "Upstream: %s; verified=%d\n",
                                     cobra::Render(*result.expr, result.real_vars, 64).c_str(),
                                     result.verified);
                };
                auto outcome = cb::generate(f.program.blocks[0].statements[0].value, request);
                std::printf("status=%d reason=%d nodes=%zu\n", int(outcome.status),
                            int(outcome.reason), outcome.output_nodes);
            }
        return 0;
    }
    auto mapping_reject = [&](auto mutate)
    {
        hooks.generated = mutate;
        auto outcome = cb::generate(original, request);
        check(!outcome.candidate && outcome.status == cb::Status::Unsupported,
              "malformed mapping never publishes candidate");
    };
    mapping_reject(
        [](cobra::SimplifyOutcome &r)
        {
            r.real_vars = {"unknown"};
            r.expr = cobra::Expr::Variable(0);
        });
    mapping_reject(
        [](cobra::SimplifyOutcome &r)
        {
            r.real_vars = {"v0", "v0"};
            r.expr = cobra::Expr::Constant(0);
        });
    mapping_reject(
        [](cobra::SimplifyOutcome &r)
        {
            r.real_vars.clear();
            r.expr = cobra::Expr::Variable(0);
        });
    mapping_reject([](cobra::SimplifyOutcome &r) { r.expr = cobra::Expr::Variable(UINT32_MAX); });
    hooks.generated = [](cobra::SimplifyOutcome &r)
    {
        r.real_vars.clear();
        r.expr = cobra::Expr::Constant(1);
    };
    auto wrong = cb::generate(original, request);
    check(wrong.candidate != nullptr, "false hypothesis reaches independent proof boundary");
    Options options;
    options.max_invariants = 0;
    Analysis analysis(fixture.program, options);
    check(!analysis.prove_candidate(0, 0, wrong.candidate, true),
          "false signature hypothesis rejected by Z3");
    hooks.generated = {};
    auto limited = request;
    for (auto phase : {detail::CobraPhase::Extraction, detail::CobraPhase::Invocation,
                       detail::CobraPhase::Reconstruction, detail::CobraPhase::Cleanup})
    {
        bool cancel = false;
        hooks.entered_phase = [&](detail::CobraPhase entered)
        {
            if (entered == phase)
                cancel = true;
        };
        limited.cancelled = [&] { return cancel; };
        const auto stopped = cb::generate(original, limited);
        check(!stopped.candidate && stopped.status == cb::Status::Exhausted &&
                  stopped.reason == cb::Reason::Cancellation,
              "each adapter phase propagates cancellation without publishing a hypothesis");
    }
    hooks.entered_phase = {};
    limited = request;
    limited.now = []() -> cb::Clock::time_point { throw std::runtime_error("clock"); };
    const auto bad_clock = cb::generate(original, limited);
    check(!bad_clock.candidate && bad_clock.status == cb::Status::Failure &&
              bad_clock.reason == cb::Reason::Callback,
          "clock callback failure preserves the original without escaping");
    limited = request;
    limited.scratch_bytes = 1;
    check(cb::generate(original, limited).status == cb::Status::Exhausted,
          "allocation allowance enforced before payload allocation");
    limited = request;
    limited.cancelled = []() -> bool { throw std::runtime_error("callback"); };
    check(!cb::generate(original, limited).candidate, "callback exception preserves original");
    hooks.generated = [](cobra::SimplifyOutcome &) { throw std::runtime_error("upstream"); };
    check(cb::generate(original, request).status == cb::Status::Failure,
          "upstream exception preserves original");
    hooks.generated = [](cobra::SimplifyOutcome &) { throw std::bad_alloc{}; };
    check(cb::generate(original, request).status == cb::Status::Exhausted,
          "upstream allocation failure preserves original");
    hooks.generated = {};
    auto time = cb::Clock::time_point{};
    request.now = [&] { return time; };
    request.deadline = time + std::chrono::milliseconds(100);
    hooks.after_cleanup = [&] { time += std::chrono::milliseconds(150); };
    auto late = cb::generate(original, request);
    check(late.status == cb::Status::Exhausted && !late.candidate && late.overshoot_ns == 50000000,
          "cleanup delay cannot publish candidate");
    hooks.after_cleanup = {};
    bool cancelled = false;
    time = cb::Clock::time_point{};
    request.cancelled = [&] { return cancelled; };
    hooks.after_cleanup = [&] { cancelled = true; };
    check(!cb::generate(original, request).candidate,
          "post-cleanup cancellation cannot publish candidate");
    hooks.after_cleanup = {};
    auto receipt = analysis.prove_candidate(0, 0, fixture.reference, true);
    check(bool(receipt), "valid candidate gets snapshot-bound proof receipt");
    if (receipt)
    {
        check(!analysis.eligible_for_commit(*receipt, false, [] { return true; }),
              "candidate receipt alone never authorizes mutation");
        Analysis other(fixture.program, options);
        check(!other.prove_emission(*receipt, fixture.reference),
              "receipt from another immutable analysis rejected");
        auto emitted = analysis.prove_emission(*receipt, fixture.reference);
        check(bool(emitted), "same analysis can prove emitted expression");
        if (emitted)
            check(!analysis.eligible_for_commit(*emitted, false, [] { return false; }),
                  "stale live source rejected after both proofs");
    }
    detail::cobra_test_hooks = nullptr;
    cb::Request admission;
    admission.deadline = cb::Clock::now() + std::chrono::seconds(1);
    Term too_many = variable(0, 8);
    for (size_t i = 1; i < 9; ++i)
        too_many = expression(Op::Add, too_many, variable(i, 8));
    const auto over_limit = cb::generate(too_many, admission);
    check(over_limit.status == cb::Status::Unsupported && over_limit.scratch_peak_bytes == 0 &&
              over_limit.raw_leaves == 9,
          "raw leaf admission precedes CoBRA tree and signature allocations");
    Program collision;
    collision.widths = {8, 8};
    collision.blocks.resize(1);
    collision.blocks[0].statements.push_back(
        Statement::assign(1, expression(Op::Mul, variable(0, 8),
                                        expression(Op::Sub, variable(0, 8), constant(1, 8)))));
    Analysis false_boolean_fit(collision, options);
    check(false_boolean_fit.verify(0, 0, constant(0, 8)) == Verdict::Disproved,
          "zero/one signature collision is rejected over full words");
    check(cb::generate(expression(Op::Add, load(constant(0, 64), 8), constant(0, 8)), admission)
                  .status == cb::Status::Unsupported,
          "explicit read occurrences are excluded from generic interning");
    std::printf("CoBRA fault failures: %d\n", failures);
    return failures != 0;
}
