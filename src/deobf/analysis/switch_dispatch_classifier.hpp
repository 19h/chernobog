#pragma once

#include <cstddef>
#include <cstdint>

namespace pattern_match {

// IDA-independent evidence for a switch-dispatch control-flow-flattening
// candidate. Keeping the policy separate from microcode extraction makes the
// false-positive boundary directly testable without an IDA process.
struct switch_dispatch_features_t {
    std::size_t case_count = 0;
    std::size_t unique_target_count = 0;
    std::size_t returning_target_count = 0;
    std::size_t direct_return_target_count = 0;
    std::size_t return_frontier_count = 0;
    std::size_t dispatcher_predecessor_count = 0;
    std::size_t dispatcher_chain_blocks = 0;
    std::size_t selector_instruction_count = 0;
    std::size_t selector_transform_count = 0;
    std::size_t state_assignment_count = 0;
    std::size_t max_return_distance = 0;
    bool has_indirect_jump = false;
    bool cfg_complete = false;
};

enum switch_dispatch_signal_t : std::uint32_t {
    SDS_INDIRECT_DISPATCH = 1U << 0,
    SDS_ENOUGH_CASES      = 1U << 1,
    SDS_DIVERSE_TARGETS   = 1U << 2,
    SDS_RECURRENT_TARGETS = 1U << 3,
    SDS_DISTRIBUTED_LOOP  = 1U << 4,
    SDS_DIRECT_RETURNS    = 1U << 5,
    SDS_SELECTOR_LOGIC    = 1U << 6,
    SDS_DISPATCH_CHAIN    = 1U << 7,
    SDS_COMPLETE_CFG      = 1U << 8,
    SDS_ENCODED_SELECTOR  = 1U << 9,
    SDS_STATE_ASSIGNMENTS = 1U << 10,
};

struct switch_dispatch_assessment_t {
    bool accepted = false;
    unsigned score = 0;
    unsigned target_diversity_percent = 0;
    unsigned recurrence_percent = 0;
    unsigned direct_return_percent = 0;
    unsigned frontier_percent = 0;
    std::uint32_t signals = 0;
};

namespace switch_dispatch_detail {

// Compute ceil(denominator * percent / 100) without overflowing size_t.
constexpr std::size_t percentage_threshold(
    std::size_t denominator, unsigned percent)
{
    return (denominator / 100U) * percent
         + ((denominator % 100U) * percent + 99U) / 100U;
}

constexpr bool ratio_at_least(
    std::size_t numerator, std::size_t denominator, unsigned percent)
{
    return denominator != 0
        && numerator >= percentage_threshold(denominator, percent);
}

inline unsigned bounded_percent(
    std::size_t numerator, std::size_t denominator)
{
    if ( denominator == 0 )
        return 0;
    if ( numerator >= denominator )
        return 100;
    for ( unsigned percent = 100; percent != 0; --percent ) {
        if ( ratio_at_least(numerator, denominator, percent) )
            return percent;
    }
    return 0;
}

} // namespace switch_dispatch_detail

inline switch_dispatch_assessment_t assess_switch_dispatch(
    const switch_dispatch_features_t &features)
{
    using switch_dispatch_detail::bounded_percent;
    using switch_dispatch_detail::ratio_at_least;

    switch_dispatch_assessment_t result;
    result.target_diversity_percent = bounded_percent(
        features.unique_target_count, features.case_count);
    result.recurrence_percent = bounded_percent(
        features.returning_target_count, features.unique_target_count);
    result.direct_return_percent = bounded_percent(
        features.direct_return_target_count,
        features.returning_target_count);
    result.frontier_percent = bounded_percent(
        features.return_frontier_count,
        features.returning_target_count);

    const bool enough_cases = features.case_count >= 8
                           && features.unique_target_count >= 6;
    const bool diverse_targets = ratio_at_least(
        features.unique_target_count, features.case_count, 50);
    const bool recurrent_targets = ratio_at_least(
        features.returning_target_count,
        features.unique_target_count,
        60);
    // A normal switch nested in a loop often has 100% eventual recurrence,
    // but normally converges through one common latch. Flattening instead has
    // state-transition paths distributed across several dispatcher backedges.
    const bool distributed_loop = features.return_frontier_count >= 3
                               && ratio_at_least(
                                      features.return_frontier_count,
                                      features.returning_target_count,
                                      10);
    // Distributed switch loops exist in ordinary interpreters and event
    // pumps. Require either a nontrivial encoded selector or the legacy
    // signature of repeated direct state-index assignments.
    const bool state_evidence = features.selector_transform_count >= 3
                             || features.state_assignment_count >= 5;

    if ( features.has_indirect_jump ) {
        result.signals |= SDS_INDIRECT_DISPATCH;
        result.score += 10;
    }
    if ( features.cfg_complete ) {
        result.signals |= SDS_COMPLETE_CFG;
        result.score += 5;
    }
    if ( enough_cases ) {
        result.signals |= SDS_ENOUGH_CASES;
        result.score += 10;
        if ( features.case_count >= 20 )
            result.score += 5;
        if ( features.case_count >= 64 )
            result.score += 5;
    }
    if ( diverse_targets ) {
        result.signals |= SDS_DIVERSE_TARGETS;
        result.score += ratio_at_least(
            features.unique_target_count, features.case_count, 80) ? 10 : 5;
    }
    if ( recurrent_targets ) {
        result.signals |= SDS_RECURRENT_TARGETS;
        result.score += 20;
        if ( ratio_at_least(features.returning_target_count,
                            features.unique_target_count, 80) )
            result.score += 10;
        if ( ratio_at_least(features.returning_target_count,
                            features.unique_target_count, 95) )
            result.score += 10;
    }
    if ( distributed_loop ) {
        result.signals |= SDS_DISTRIBUTED_LOOP;
        result.score += 15;
        if ( ratio_at_least(features.return_frontier_count,
                            features.returning_target_count, 25) )
            result.score += 5;
    }
    if ( ratio_at_least(features.direct_return_target_count,
                        features.returning_target_count, 25) ) {
        result.signals |= SDS_DIRECT_RETURNS;
        result.score += 5;
    }
    if ( features.selector_instruction_count >= 4 ) {
        result.signals |= SDS_SELECTOR_LOGIC;
        result.score += 5;
    }
    if ( features.selector_transform_count >= 3 ) {
        result.signals |= SDS_ENCODED_SELECTOR;
        result.score += 10;
    }
    if ( features.state_assignment_count >= 5 ) {
        result.signals |= SDS_STATE_ASSIGNMENTS;
        result.score += 10;
    }
    if ( features.dispatcher_chain_blocks >= 2 ) {
        result.signals |= SDS_DISPATCH_CHAIN;
        result.score += 5;
    }
    if ( result.score > 100 )
        result.score = 100;

    result.accepted = features.has_indirect_jump
                   && features.cfg_complete
                   && enough_cases
                   && diverse_targets
                   && recurrent_targets
                   && distributed_loop
                   && state_evidence
                   && features.dispatcher_predecessor_count >= 3
                   && result.score >= 65;
    return result;
}

} // namespace pattern_match
