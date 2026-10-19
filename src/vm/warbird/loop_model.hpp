#pragma once
#include <array>
#include <cstdint>

namespace chernobog::warbird
{
// MOVUPS [RCX],XMM0; ADD RCX,16; DEC R9; JNZ back. This witness admits
// only a contiguous forward store loop, with no intervening reads or calls.
inline constexpr std::array<uint8_t, 12> store_loop_bytes = {0x0f, 0x11, 0x01, 0x48, 0x83, 0xc1,
                                                             0x10, 0x49, 0xff, 0xc9, 0x75, 0xf4};
inline constexpr std::array<unsigned, 4> store_loop_offsets = {0, 3, 7, 10};
inline constexpr uint64_t store_loop_limit = 4096;
}
