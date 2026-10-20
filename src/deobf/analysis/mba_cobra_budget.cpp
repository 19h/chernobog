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
    const auto requested = std::chrono::duration_cast<Clock::duration>(expression_limit);
    const auto expression_deadline = now.time_since_epoch() > Clock::duration::max() - requested
                                         ? Clock::time_point::max()
                                         : now + requested;
    result.site_deadline = std::min(phase_deadline, expression_deadline);
    const auto site =
        std::chrono::duration_cast<std::chrono::nanoseconds>(result.site_deadline - now);
    if (site.count() < 10000000)
        return result;
    const auto candidate = std::min(site / 2, site - std::chrono::nanoseconds(5000000));
    // site <= phase_deadline - now, so neither addition can exceed that endpoint.

    result.candidate_deadline = std::min({now + candidate, inherited, result.site_deadline});
    result.admitted = now < result.candidate_deadline;
    return result;
}
} // namespace chernobog::mba_smt::cobra_backend
