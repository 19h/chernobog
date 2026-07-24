#pragma once

#include <cstdint>
#include <set>

namespace chernobog::deobf {

// Per-database authorization for mutation passes installed in Hex-Rays.
// Keeping the handlers installed preserves the explicit deobfuscation action;
// the policy decides whether a particular decompilation may use them.
class execution_policy_t
{
public:
    void configure_automatic(bool enabled)
    {
        automatic_ = enabled;
    }

    bool automatic() const
    {
        return automatic_;
    }

    void request(uint64_t function_ea)
    {
        explicitly_requested_.insert(function_ea);
    }

    bool allows(uint64_t function_ea) const
    {
        return automatic_
            || explicitly_requested_.find(function_ea)
                != explicitly_requested_.end();
    }

    void clear_requests()
    {
        explicitly_requested_.clear();
    }

private:
    bool automatic_ = false;
    std::set<uint64_t> explicitly_requested_;
};

} // namespace chernobog::deobf
