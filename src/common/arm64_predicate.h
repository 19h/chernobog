#pragma once

#include "bitvector.h"

#include <cstdint>
#include <optional>

namespace chernobog {
namespace arm64_predicate {

// AArch64 encodes NZCV as N:bit3, Z:bit2, C:bit1, V:bit0. Conditions
// 0x0..0xD are the ordinary invertible predicates; AL/NV are deliberately
// excluded from constant-conditional-branch proofs.
struct nzcv_t
{
    bool negative = false;
    bool zero = false;
    bool carry = false;
    bool overflow = false;
};

inline uint64_t width_mask(int bytes)
{
    return bitvector::valid_byte_width(bytes)
        ? bitvector::mask(bytes) : uint64_t{0};
}

inline nzcv_t add_flags(uint64_t left, uint64_t right, int bytes)
{
    const uint64_t mask = width_mask(bytes);
    if ( mask == 0 )
        return {};
    left &= mask;
    right &= mask;
    const uint64_t result = (left + right) & mask;
    const uint64_t sign = uint64_t{1} << (bytes * 8 - 1);
    return {
        (result & sign) != 0,
        result == 0,
        left > mask - right,
        ((~(left ^ right) & (left ^ result) & sign) != 0),
    };
}

inline nzcv_t sub_flags(uint64_t left, uint64_t right, int bytes)
{
    const uint64_t mask = width_mask(bytes);
    if ( mask == 0 )
        return {};
    left &= mask;
    right &= mask;
    const uint64_t result = (left - right) & mask;
    const uint64_t sign = uint64_t{1} << (bytes * 8 - 1);
    return {
        (result & sign) != 0,
        result == 0,
        left >= right,
        (((left ^ right) & (left ^ result) & sign) != 0),
    };
}

inline std::optional<bool> evaluate(uint8_t condition, const nzcv_t &flags)
{
    bool result = false;
    switch ( condition >> 1 )
    {
        case 0: result = flags.zero; break;                         // EQ/NE
        case 1: result = flags.carry; break;                        // CS/CC
        case 2: result = flags.negative; break;                     // MI/PL
        case 3: result = flags.overflow; break;                     // VS/VC
        case 4: result = flags.carry && !flags.zero; break;         // HI/LS
        case 5: result = flags.negative == flags.overflow; break;   // GE/LT
        case 6:                                                     // GT/LE
            result = !flags.zero && flags.negative == flags.overflow;
            break;
        default:
            return std::nullopt;                                   // AL/NV
    }
    if ( (condition & 1U) != 0 )
        result = !result;
    return result;
}

} // namespace arm64_predicate
} // namespace chernobog
