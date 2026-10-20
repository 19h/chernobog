#include "deobf/analysis/mba_cobra.hpp"
#include "mba_cobra_fixtures.hpp"
#include <cstdio>
#include <cstring>
#include <stdexcept>

using namespace chernobog::mba_smt;
namespace cb = chernobog::mba_smt::cobra_backend;
namespace
{
int failures = 0;
void check(bool result, const char *description)
{
    if (!result)
    {
        std::fprintf(stderr, "FAIL: %s\n", description);
        ++failures;
    }
}
size_t nodes(const Term &term) { return term ? 1 + nodes(term->left) + nodes(term->right) : 0; }
void reservation_tests()
{
    const auto now = cb::Clock::time_point{};
    for (int64_t ns : {9999999, 10000000, 10000001})
    {
        const auto budget =
            cb::reserve_site(now, now + std::chrono::seconds(1), std::chrono::nanoseconds(ns));
        check(budget.admitted == (ns >= 10000000), "exact 10 ms preflight boundary");
        if (budget.admitted)
            check(budget.candidate_deadline - now == std::chrono::nanoseconds(ns / 2),
                  "candidate half uses integer nanoseconds");
    }
    check(!cb::reserve_site(now, now, std::chrono::seconds(1)).admitted, "expired phase rejected");
    auto inherited = now + std::chrono::milliseconds(1);
    check(cb::reserve_site(now, now + std::chrono::seconds(1), std::chrono::seconds(1), inherited)
                  .candidate_deadline == inherited,
          "inherited earlier candidate deadline preserved");
}
}
int main(int argc, char **argv)
{
    reservation_tests();
    if (!cb::available())
    {
        std::printf("CoBRA disabled; reservation checks only\n");
        return failures != 0;
    }
    for (Profile profile : {Profile::Normal, Profile::Deep})
    {
        for (const auto &fixture : fixtures::make())
        {
            if (argc > 1 && std::strcmp(argv[1], fixture.id) != 0)
                continue;
            auto options = profile == Profile::Deep ? Options::deep() : Options{};
            options.backend = Backend::Cobra;
            options.max_invariants = 0;
            const auto &original = fixture.program.blocks[0].statements[0].value;
            Analysis analysis(fixture.program, options);
            const auto proposals = analysis.run();
            Term candidate = proposals.empty() ? Term{} : proposals.front().replacement;
            const bool attributed = !proposals.empty() && proposals.front().proof &&
                                    proposals.front().proof->from_cobra();
            const auto statistics = analysis.statistics().cobra;
            bool passed = candidate && attributed && cost(candidate) < cost(original) &&
                          nodes(candidate) <= fixture.max_nodes;
            if (fixture.inner_width)
                passed = passed &&
                         (statistics.proved_widths & (UINT64_C(1) << (fixture.inner_width / 8))) &&
                         (statistics.proved_widths & (UINT64_C(1) << (original->bits / 8)));
            if (fixture.half_cost && candidate)
                passed = passed && 2 * cost(candidate) <= cost(original);
            if (fixture.empty_support && candidate)
                passed = passed && candidate->op == Op::Constant && variables(candidate).empty();
            std::printf(
                "{\"fixture\":\"%s\",\"profile\":\"%s\",\"boundary\":\"candidate_only\",\"passed\":%s,\"attributed\":%s,\"input_cost\":%zu,\"output_cost\":%zu,\"nodes\":%zu,\"generation_ns\":%llu,\"scratch_peak_bytes\":%zu,\"cobra_proved\":%zu}\n",
                fixture.id, profile == Profile::Deep ? "Deep" : "Normal", passed ? "true" : "false",
                attributed ? "true" : "false", cost(original), candidate ? cost(candidate) : 0,
                candidate ? nodes(candidate) : 0,
                static_cast<unsigned long long>(statistics.generation_ns),
                statistics.scratch_peak_bytes, statistics.proved);
            std::fflush(stdout);
            if (!passed)
                ++failures;
        }
    }
    cb::Request timed;
    auto ticks = cb::Clock::time_point{};
    timed.now = [&]
    {
        const auto value = ticks;
        ticks += std::chrono::nanoseconds(1);
        return value;
    };
    timed.deadline = ticks + std::chrono::seconds(10);
    const auto timing =
        cb::generate(fixtures::make().front().program.blocks[0].statements[0].value, timed);
    check(timing.timings_complete && timing.extraction_ns + timing.invocation_ns +
                                             timing.reconstruction_ns + timing.cleanup_ns ==
                                         timing.elapsed_ns,
          "complete phase intervals exactly partition candidate elapsed nanoseconds");
    cb::Request exhausted;
    exhausted.deadline = cb::Clock::now() - std::chrono::milliseconds(1);
    check(cb::generate(expression(Op::Add, variable(0, 32), constant(0, 32)), exhausted).status ==
              cb::Status::Exhausted,
          "expired generation rejects");
    std::printf("CoBRA candidate-only failures: %d\n", failures);
    return failures != 0;
}
