#include "mba_diagnostics.hpp"

#include <algorithm>
#include <mutex>
#include <sstream>

namespace chernobog::mba_diagnostics
{
namespace
{
std::mutex counters_mutex;
Snapshot counters;

bool same_site(const Site &a, const Site &b)
{
    return a.entry == b.entry && a.source == b.source && a.maturity == b.maturity &&
           a.block == b.block && a.opcode == b.opcode && a.width_bytes == b.width_bytes;
}
} // namespace

const char *outcome_name(Outcome outcome)
{
    static constexpr const char *names[] = {
        "no_ast",
        "no_indexed_pattern",
        "structural_mismatch",
        "candidate_constraint",
        "constant_constraint",
        "replacement_unavailable",
        "instance_disproved",
        "instance_unsupported",
        "instance_unknown",
        "catalog_applied",
    };
    const auto index = static_cast<size_t>(outcome);
    return index < outcome_count ? names[index] : "invalid";
}

std::string constant_failure_detail(const std::vector<NumericBinding> &bindings)
{
    std::ostringstream out;
    out << "constant_check_failed;numeric=";
    size_t retained = 0, omitted = 0;
    for (const auto &binding : bindings)
    {
        const bool identifier =
            !binding.name.empty() && binding.name.size() <= binding_name_byte_limit &&
            std::all_of(binding.name.begin(), binding.name.end(),
                        [](char c)
                        {
                            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                   (c >= '0' && c <= '9') || c == '_';
                        });
        if (!identifier || retained == binding_limit)
        {
            ++omitted;
            continue;
        }
        if (retained++)
            out << ',';
        out << binding.name << ':' << std::dec << binding.width_bytes << ":0x" << std::hex
            << binding.value;
    }
    out << ";omitted=" << std::dec << omitted;
    return out.str();
}

void record(Outcome outcome, Site site, uint64_t indexed_patterns, uint64_t structural_matches,
            uint64_t candidate_rejections, uint64_t constant_rejections, std::string_view detail,
            std::string_view rule)
{
    const auto index = static_cast<size_t>(outcome);
    if (index >= outcome_count)
        return;
    detail = detail.substr(0, detail_byte_limit);
    rule = rule.substr(0, rule_byte_limit);
    std::lock_guard<std::mutex> lock(counters_mutex);
    ++counters.events;
    ++counters.counts[index];
    for (auto &sample : counters.samples)
    {
        if (sample.outcome == outcome && same_site(sample.site, site) &&
            sample.indexed_patterns == indexed_patterns &&
            sample.structural_matches == structural_matches &&
            sample.candidate_rejections == candidate_rejections &&
            sample.constant_rejections == constant_rejections && sample.detail == detail &&
            sample.rule == rule)
        {
            ++sample.count;
            return;
        }
    }
    if (counters.samples.size() == sample_limit)
    {
        ++counters.unrecorded;
        return;
    }
    counters.samples.push_back({site, outcome, indexed_patterns, structural_matches,
                                candidate_rejections, constant_rejections, std::string(detail),
                                std::string(rule), 1});
}

Snapshot snapshot()
{
    std::lock_guard<std::mutex> lock(counters_mutex);
    return counters;
}

void reset()
{
    std::lock_guard<std::mutex> lock(counters_mutex);
    counters = {};
}
} // namespace chernobog::mba_diagnostics
