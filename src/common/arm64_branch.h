#pragma once

#include <cstdint>
#include <optional>

namespace chernobog
{
namespace arm64_branch
{

struct IndirectBranch
{
    bool call = false;
    bool authenticated = false;
    unsigned target_register = 0;
    unsigned modifier_register = 0;
};

// IDA uses ARM_br/ARM_blr for both plain and authenticated forms. Decode
// authentication from the instruction word, independently of SDK enum names.
inline std::optional<IndirectBranch> decode_indirect(uint32_t word)
{
    if ((word & 0xFFDFFC1FU) == 0xD61F0000U)
        return IndirectBranch{(word & 0x00200000U) != 0, false, (word >> 5) & 31U, 0};
    if ((word & 0xFEDFF800U) != 0xD61F0800U)
        return std::nullopt;
    const bool register_modifier = (word & 0x01000000U) != 0;
    if (!register_modifier && (word & 31U) != 31U)
        return std::nullopt;
    return IndirectBranch{(word & 0x00200000U) != 0, true, (word >> 5) & 31U,
                          register_modifier ? word & 31U : 32U};
}

// Encode AArch64 B <target>. The signed imm26 is measured in 4-byte words,
// giving a byte displacement interval of [-2^27, 2^27 - 4].
inline std::optional<uint32_t> encode_b(uint64_t source, uint64_t target)
{
    if ((source & 3U) != 0 || (target & 3U) != 0)
        return std::nullopt;

    uint32_t immediate = 0;
    if (target >= source)
    {
        const uint64_t distance = target - source;
        if (distance > ((uint64_t{1} << 27) - 4))
            return std::nullopt;
        immediate = static_cast<uint32_t>(distance >> 2);
    }
    else
    {
        const uint64_t distance = source - target;
        if (distance > (uint64_t{1} << 27))
            return std::nullopt;
        const int64_t words = -static_cast<int64_t>(distance >> 2);
        immediate = static_cast<uint32_t>(words) & 0x03FFFFFFU;
    }

    return 0x14000000U | (immediate & 0x03FFFFFFU);
}

// Encode AArch64 B.<cond> <target>. Conditions 0x0..0xD are the ordinary
// predicates; 0xE/0xF are deliberately rejected. The signed imm19 is measured
// in 4-byte words, giving [-2^20, 2^20 - 4] bytes.
inline std::optional<uint32_t> encode_b_cond(uint64_t source, uint64_t target, uint8_t condition)
{
    if ((source & 3U) != 0 || (target & 3U) != 0 || condition > 0xDU)
        return std::nullopt;

    uint32_t immediate = 0;
    if (target >= source)
    {
        const uint64_t distance = target - source;
        if (distance > ((uint64_t{1} << 20) - 4))
            return std::nullopt;
        immediate = static_cast<uint32_t>(distance >> 2);
    }
    else
    {
        const uint64_t distance = source - target;
        if (distance > (uint64_t{1} << 20))
            return std::nullopt;
        const int64_t words = -static_cast<int64_t>(distance >> 2);
        immediate = static_cast<uint32_t>(words) & 0x0007FFFFU;
    }

    return 0x54000000U | ((immediate & 0x0007FFFFU) << 5) | static_cast<uint32_t>(condition);
}

} // namespace arm64_branch
} // namespace chernobog
