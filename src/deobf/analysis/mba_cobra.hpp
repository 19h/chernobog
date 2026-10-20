#pragma once

#include "mba_smt.hpp"
#include <chrono>
#include <functional>

namespace chernobog::mba_smt::cobra_backend
{
using Clock = std::chrono::steady_clock;
enum class Status
{
    Candidate,
    Unchanged,
    Unsupported,
    Exhausted,
    Failure
};
enum class Reason
{
    None,
    PreFlight,
    Deadline,
    Cancellation,
    Allocation,
    Callback,
    Shape,
    Mapping,
    Cost,
    Upstream
};
struct SiteBudget
{
    Clock::time_point site_deadline;
    Clock::time_point candidate_deadline;
    bool admitted = false;
};
SiteBudget reserve_site(Clock::time_point now, Clock::time_point phase_deadline,
                        std::chrono::nanoseconds expression_limit,
                        Clock::time_point inherited = Clock::time_point::max()) noexcept;
struct Request
{
    Clock::time_point deadline;
    Profile profile = Profile::Normal;
    SnapshotToken snapshot;
    std::function<bool()> cancelled;
    std::function<Clock::time_point()> now;
    size_t scratch_bytes = 0;
};
struct Outcome
{
    Status status = Status::Unchanged;
    Reason reason = Reason::None;
    Term candidate;
    size_t raw_leaves = 0;
    size_t input_nodes = 0;
    size_t output_nodes = 0;
    size_t raw_support = 0;
    std::array<unsigned, 12> raw_indices{};
    size_t canonical_support = 0;
    size_t scratch_peak_bytes = 0;
    uint64_t elapsed_ns = 0;
    uint64_t overshoot_ns = 0;
    bool spot_check = false;
};
uint64_t process_peak_rss_bytes() noexcept;
bool available() noexcept;
Outcome generate(const Term &original, const Request &request);
} // namespace chernobog::mba_smt::cobra_backend
