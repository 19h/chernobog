#pragma once
// Private fault injection seam. Product configuration never populates this.
#include <cobra/core/SimplifyOutcome.h>
#include <functional>
namespace chernobog::mba_smt::detail
{
struct CobraTestHooks
{
    std::function<void(cobra::SimplifyOutcome &)> generated;
    std::function<void()> after_cleanup;
};
inline thread_local CobraTestHooks *cobra_test_hooks = nullptr;
}
