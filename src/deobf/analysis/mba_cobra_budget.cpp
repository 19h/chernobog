#include "mba_cobra.hpp"
#include <algorithm>

namespace chernobog::mba_smt::cobra_backend
{
SiteBudget reserve_site(Clock::time_point now, Clock::time_point phase_deadline,
                        std::chrono::nanoseconds expression_limit,
                        Clock::time_point inherited) noexcept
{
    SiteBudget result{now, now, false};
    if (now >= phase_deadline || expression_limit.count() < 10000000)
        return result;
    const auto remaining =
        std::chrono::duration_cast<std::chrono::nanoseconds>(phase_deadline - now);
    const auto site = std::min(remaining, expression_limit);
    if (site.count() < 10000000)
        return result;
    const auto candidate = std::min(site / 2, site - std::chrono::nanoseconds(5000000));
    // site <= phase_deadline - now, so neither addition can exceed that endpoint.
    result.site_deadline = now + site;
    result.candidate_deadline = std::min({now + candidate, inherited, result.site_deadline});
    result.admitted = now < result.candidate_deadline;
    return result;
}
} // namespace chernobog::mba_smt::cobra_backend
