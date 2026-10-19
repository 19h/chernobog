#pragma once

#include "mba_smt.hpp"

namespace chernobog::mba_smt::detail
{
struct KnownBits
{
    uint64_t zero = 0;
    uint64_t one = 0;
};

// Conservative certificates: unknown bits appear in neither mask.
KnownBits known_bits(const Term &term);
} // namespace chernobog::mba_smt::detail
