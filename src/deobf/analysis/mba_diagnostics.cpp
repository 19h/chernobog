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

const char *capture_status_name(CaptureStatus status)
{
    static constexpr const char *names[] = {
        "complete", "no_ast", "depth_limit", "visit_limit", "byte_limit", "malformed", "cycle",
    };
    const auto index = static_cast<size_t>(status);
    return index < capture_status_count ? names[index] : "invalid";
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
            std::string_view rule, const CapturedInput *input)
{
    const auto index = static_cast<size_t>(outcome);
    if (index >= outcome_count)
        return;
    detail = detail.substr(0, detail_byte_limit);
    rule = rule.substr(0, rule_byte_limit);
    std::lock_guard<std::mutex> lock(counters_mutex);
    ++counters.events;
    ++counters.counts[index];
    if (input)
    {
        const auto capture_index = static_cast<size_t>(input->status);
        const bool valid = capture_index < capture_status_count &&
                           input->payload.size() <= input_byte_limit &&
                           ((input->status == CaptureStatus::Complete) == !input->payload.empty());
        const CapturedInput rejected{CaptureStatus::Malformed, {}};
        const auto &captured = valid ? *input : rejected;
        ++counters.input_events;
        ++counters.input_counts[static_cast<size_t>(captured.status)];
        bool found = false;
        for (auto &sample : counters.inputs)
        {
            const auto &event = sample.event;
            if (event.outcome == outcome && same_site(event.site, site) &&
                event.indexed_patterns == indexed_patterns &&
                event.structural_matches == structural_matches &&
                event.candidate_rejections == candidate_rejections &&
                event.constant_rejections == constant_rejections && event.detail == detail &&
                event.rule == rule && sample.input.status == captured.status &&
                sample.input.payload == captured.payload)
            {
                ++sample.event.count;
                found = true;
                break;
            }
        }
        if (!found)
        {
            if (counters.inputs.size() == sample_limit)
                ++counters.input_unrecorded;
            else
                counters.inputs.push_back(
                    {{site, outcome, indexed_patterns, structural_matches, candidate_rejections,
                      constant_rejections, std::string(detail), std::string(rule), 1},
                     captured});
        }
    }
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

Snapshot snapshot(bool include_inputs)
{
    std::lock_guard<std::mutex> lock(counters_mutex);
    Snapshot result;
    result.counts = counters.counts;
    result.events = counters.events;
    result.unrecorded = counters.unrecorded;
    result.samples = counters.samples;
    if (include_inputs)
    {
        result.input_counts = counters.input_counts;
        result.input_events = counters.input_events;
        result.input_unrecorded = counters.input_unrecorded;
        result.inputs = counters.inputs;
    }
    return result;
}

void reset()
{
    std::lock_guard<std::mutex> lock(counters_mutex);
    counters = {};
}
} // namespace chernobog::mba_diagnostics
