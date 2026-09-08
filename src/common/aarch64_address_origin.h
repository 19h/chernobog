#pragma once

#include <cstdint>
#include <optional>

namespace chernobog {
namespace aarch64_address_origin {

// Decode only ADRP Xr; ADD Xr, Xr, #imm12; STR Xr, [Xn, #imm12*8].
// The caller supplies little-endian instruction words and checks the current
// function/chunk and IDA-visible entries. This describes address construction,
// not memory contents or a universal control-flow proof. O(1) time and space.
inline std::optional<uint64_t> decode_adrp_add_str_address(
    uint64_t adrp_ea, uint32_t adrp, uint32_t add, uint32_t store)
{
    if ( (adrp_ea & 3U) != 0
      || (adrp & 0x9F000000U) != 0x90000000U
      || (add & 0xFFC00000U) != 0x91000000U
      || (store & 0xFFC00000U) != 0xF9000000U )
    {
        return std::nullopt;
    }
    const uint32_t reg = adrp & 31U;
    if ( reg == 31U || (add & 31U) != reg
      || ((add >> 5) & 31U) != reg || (store & 31U) != reg )
    {
        return std::nullopt;
    }

    const uint32_t imm21 = ((adrp >> 29) & 3U)
        | (((adrp >> 5) & 0x7FFFFU) << 2);
    const int64_t signed_pages = (imm21 & 0x100000U) != 0
        ? int64_t(imm21) - 0x200000LL : int64_t(imm21);
    // Signed multiplication is bounded to [-2^32, 2^32-4096]. Address
    // addition then uses architectural modulo-2^64 arithmetic, without a
    // left shift of a negative signed value or signed overflow.
    const uint64_t page = (adrp_ea & ~uint64_t(0xFFF))
        + uint64_t(signed_pages * 4096);
    return page + uint64_t((add >> 10) & 0xFFFU);
}

} // namespace aarch64_address_origin
} // namespace chernobog
