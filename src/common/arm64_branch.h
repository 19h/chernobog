#pragma once

#include <cstdint>
#include <optional>

namespace chernobog {
namespace arm64_branch {

// Encode AArch64 B <target>. The signed imm26 is measured in 4-byte words,
// giving a byte displacement interval of [-2^27, 2^27 - 4].
inline std::optional<uint32_t> encode_b(uint64_t source, uint64_t target)
{
    if ( (source & 3U) != 0 || (target & 3U) != 0 )
        return std::nullopt;

    uint32_t immediate = 0;
    if ( target >= source )
    {
        const uint64_t distance = target - source;
        if ( distance > ((uint64_t{1} << 27) - 4) )
            return std::nullopt;
        immediate = static_cast<uint32_t>(distance >> 2);
    }
    else
    {
        const uint64_t distance = source - target;
        if ( distance > (uint64_t{1} << 27) )
            return std::nullopt;
        const int64_t words = -static_cast<int64_t>(distance >> 2);
        immediate = static_cast<uint32_t>(words) & 0x03FFFFFFU;
    }

    return 0x14000000U | (immediate & 0x03FFFFFFU);
}

// Encode AArch64 B.<cond> <target>. Conditions 0x0..0xD are the ordinary
// predicates; 0xE/0xF are deliberately rejected. The signed imm19 is measured
// in 4-byte words, giving [-2^20, 2^20 - 4] bytes.
inline std::optional<uint32_t> encode_b_cond(
    uint64_t source, uint64_t target, uint8_t condition)
{
    if ( (source & 3U) != 0 || (target & 3U) != 0 || condition > 0xDU )
        return std::nullopt;

    uint32_t immediate = 0;
    if ( target >= source )
    {
        const uint64_t distance = target - source;
        if ( distance > ((uint64_t{1} << 20) - 4) )
            return std::nullopt;
        immediate = static_cast<uint32_t>(distance >> 2);
    }
    else
    {
        const uint64_t distance = source - target;
        if ( distance > (uint64_t{1} << 20) )
            return std::nullopt;
        const int64_t words = -static_cast<int64_t>(distance >> 2);
        immediate = static_cast<uint32_t>(words) & 0x0007FFFFU;
    }

    return 0x54000000U
         | ((immediate & 0x0007FFFFU) << 5)
         | static_cast<uint32_t>(condition);
}

} // namespace arm64_branch
} // namespace chernobog
