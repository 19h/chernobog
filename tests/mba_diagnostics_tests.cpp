#include "deobf/analysis/mba_diagnostics.hpp"

#include <iostream>
#include <numeric>
#include <stdexcept>
#include <thread>

namespace
{
using namespace chernobog::mba_diagnostics;
size_t checks = 0;

void require(bool value, const char *message)
{
    ++checks;
    if (!value)
        throw std::runtime_error(message);
}

void account(const Snapshot &value)
{
    uint64_t sampled = 0;
    std::array<uint64_t, outcome_count> by_outcome{};
    for (const auto &sample : value.samples)
    {
        require(sample.count > 0 && sample.detail.size() <= detail_byte_limit &&
                    sample.rule.size() <= rule_byte_limit,
                "retained sample bounds");
        sampled += sample.count;
        by_outcome[size_t(sample.outcome)] += sample.count;
    }
    require(value.samples.size() <= sample_limit, "sample quota");
    require(sampled + value.unrecorded == value.events, "complete event accounting");
    require(std::accumulate(value.counts.begin(), value.counts.end(), uint64_t(0)) == value.events,
            "complete outcome accounting");
    for (size_t i = 0; i < outcome_count; ++i)
        require(by_outcome[i] <= value.counts[i], "outcome sample accounting");
}
} // namespace

int main()
{
    try
    {
        require(constant_failure_detail({}) == "constant_check_failed;numeric=;omitted=0",
                "empty numeric bindings remain explicit");
        require(
            constant_failure_detail({{"c_minus_1", 1, UINT64_MAX}, {"0", 4, 42}}) ==
                "constant_check_failed;numeric=c_minus_1:1:0xffffffffffffffff,0:4:0x2a;omitted=0",
            "raw values, names and widths are preserved without masking");
        const std::string longest(binding_name_byte_limit, 'x');
        std::vector<NumericBinding> bounded;
        for (size_t i = 0; i < binding_limit + 1; ++i)
            bounded.push_back({longest, UINT16_MAX, UINT64_MAX});
        const auto detail = constant_failure_detail(bounded);
        require(detail.size() <= detail_byte_limit &&
                    detail.find(";omitted=1") != std::string::npos,
                "four maximal bindings fit the recorder byte cap and account for excess");
        require(constant_failure_detail({{"", 1, 0},
                                         {"bad:name", 1, 0},
                                         {"identifier_too_long_for_capture", 1, 0},
                                         {"ok", 8, 7}}) ==
                    "constant_check_failed;numeric=ok:8:0x7;omitted=3",
                "invalid or oversized identifiers are omitted without partial labels");
        reset();
        Site site{0x1000, 0x1010, 3, 1, 9, 4};
        for (size_t i = 0; i < outcome_count; ++i)
            record(Outcome(i), site, 10, 3, 1, 1, "quoted \"reason\"\n", "rule");
        auto first = snapshot();
        require(first.events == outcome_count && first.samples.size() == outcome_count,
                "all outcome distinctions retained");
        account(first);
        record(Outcome::Count, site, 0, 0, 0, 0);
        require(snapshot().events == first.events, "invalid outcome does not create an event");
        for (size_t i = outcome_count; i < sample_limit; ++i)
        {
            site.source = 0x2000 + i;
            record(Outcome::StructuralMismatch, site, 1, 0, 0, 0, std::string(1000, 'd'),
                   std::string(1000, 'r'));
        }
        auto full = snapshot();
        require(full.samples.size() == sample_limit && full.unrecorded == 0, "exact quota");
        site.source = 0x3000;
        record(Outcome::NoIndexedPattern, site, 0, 0, 0, 0);
        require(snapshot().unrecorded == 1, "one beyond quota is accounted");
        record(first.samples[0].outcome, first.samples[0].site, 10, 3, 1, 1, "quoted \"reason\"\n",
               "rule");
        require(snapshot().samples[0].count == 2, "existing key increments after quota");
        account(snapshot());
        reset();
        require(snapshot().events == 0 && snapshot().samples.empty(),
                "reset clears live inventory");
        require(first.samples.size() == outcome_count && first.samples[0].count == 1,
                "snapshot owns its data across updates/reset");
        std::vector<std::thread> writers;
        for (int worker = 0; worker < 4; ++worker)
            writers.emplace_back(
                [worker]
                {
                    const Site current{0x4000, uint64_t(0x4100 + worker), 5, 2, 10, 8};
                    for (int i = 0; i < 1000; ++i)
                        record(Outcome::StructuralMismatch, current, 2, 0, 0, 0);
                });
        for (auto &writer : writers)
            writer.join();
        auto concurrent = snapshot();
        require(concurrent.events == 4000 && concurrent.samples.size() == 4 &&
                    concurrent.unrecorded == 0,
                "concurrent records are not lost");
        for (const auto &sample : concurrent.samples)
            require(sample.count == 1000, "per-site concurrent accounting");
        account(concurrent);
        reset();
        account(snapshot());
        std::cout << "[mba-diagnostics] PASS checks=" << checks << '\n';
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
