#pragma once

// The IDA 9.4 / 9.5 decompiler differences one Chernobog build has to bridge.
//
// Release builds compile against the IDA 9.4 SDK, the oldest IDA this plugin
// loads in. Kernel exports from that SDK exist in 9.5. The decompiler does not
// keep that promise. IDA 9.5 changed two things a compiled plugin observes:
//
//   - cexpr_t::m widened from uint32 to uint64. It holds a bit offset when
//     EXFL_BITFIELD (0x0400) is set, which 9.5 sets on bitfield member accesses.
//   - The handshake magic init_hexrays_plugin() sends moved from
//     0x00DEC0DE00000005 to 0x00DEC0DE00000006. The decompiler answers only an
//     exact match, so a 9.4-compiled plugin is refused by a released 9.5
//     decompiler.
//
// get_hexdsp() and the hexcall_t numbering did not change: 9.5 appended its new
// calls after the 9.4 ones. 9.5.0-beta.1 already uses the 9.5 data layout and
// still answers the 9.4 magic, so the layout depends on the kernel version as
// well as on which magic was accepted.
//
// MERR_LOOP is not one of those two. Hex-Rays moved it from -36 to -37 on
// 2026-06-30, while the 9.4 decompiler still answered magic 5. That decision
// stays in hexrays_compat.h, keyed by get_hexrays_version().
//
// Pure: no IDA headers, so the decisions are testable without a database.

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace chernobog::hexrays_abi
{

// Handshake magic of the IDA 9.4 decompiler, and of 9.5 builds made before 9.5
// bumped it (9.5.0-beta.1).
inline constexpr std::int64_t hexrays_magic_94 = 0x00DEC0DE00000005LL;

// Handshake magic of the IDA 9.5 decompiler once its ABI change was declared.
inline constexpr std::int64_t hexrays_magic_95 = 0x00DEC0DE00000006LL;

// IDA 9.5's EXFL_BITFIELD. cexpr_t::m is a bit offset when this is set.
// IDA 9.4 never sets the bit.
inline constexpr std::uint32_t exfl_bitfield_95 = 0x0400;

enum class decompiler_layout_t : std::uint8_t
{
    unknown, // No handshake was accepted.
    v94,
    v95,
};

struct kernel_version_t
{
    int major = 0;
    int minor = 0;
};

// What the decompiler answers to an accepted handshake. Both magics share it,
// so the reply alone cannot tell them apart.
[[nodiscard]] inline int handshake_reply(std::int64_t magic)
{
    return static_cast<int>(magic >> 32);
}

// The major.minor prefix of get_kernel_version() ("9.4", "9.5", "9.4.260915").
[[nodiscard]] inline std::optional<kernel_version_t> parse_kernel_version(std::string_view text)
{
    auto parse_number = [&text](int &out)
    {
        std::size_t digits = 0;
        int value = 0;
        while (digits < text.size() && digits < 4 && text[digits] >= '0' && text[digits] <= '9')
        {
            value = value * 10 + (text[digits] - '0');
            ++digits;
        }
        text.remove_prefix(digits);
        out = value;
        return digits > 0;
    };

    kernel_version_t version;
    if (!parse_number(version.major) || text.empty() || text.front() != '.')
        return std::nullopt;
    text.remove_prefix(1);
    if (!parse_number(version.minor))
        return std::nullopt;
    return version;
}

[[nodiscard]] inline bool is_95_or_later(std::optional<kernel_version_t> kernel)
{
    return kernel.has_value() && (kernel->major > 9 || (kernel->major == 9 && kernel->minor >= 5));
}

// The magics to offer. The one the running kernel most likely answers comes
// first, so a released 9.4 or 9.5 needs one broadcast. Both are always offered:
// the kernel version cannot tell a 9.5 build from before the magic bump. A
// decompiler that rejects both speaks an ABI this build does not know.
[[nodiscard]] inline std::array<std::int64_t, 2>
handshake_order(std::optional<kernel_version_t> kernel)
{
    if (is_95_or_later(kernel))
        return {hexrays_magic_95, hexrays_magic_94};
    return {hexrays_magic_94, hexrays_magic_95};
}

// The layout behind an accepted handshake. Magic 6 always means the 9.5 layout.
// Magic 5 means the 9.4 layout unless the kernel says 9.5 or later: those builds
// predate the magic bump and already carry the 9.5 layout.
[[nodiscard]] inline decompiler_layout_t
layout_for_handshake(std::int64_t accepted_magic, std::optional<kernel_version_t> kernel)
{
    if (accepted_magic == hexrays_magic_95)
        return decompiler_layout_t::v95;
    if (accepted_magic != hexrays_magic_94)
        return decompiler_layout_t::unknown;
    return is_95_or_later(kernel) ? decompiler_layout_t::v95 : decompiler_layout_t::v94;
}

[[nodiscard]] inline const char *layout_name(decompiler_layout_t layout)
{
    switch (layout)
    {
    case decompiler_layout_t::v94:
        return "9.4";
    case decompiler_layout_t::v95:
        return "9.5";
    case decompiler_layout_t::unknown:
        return "unknown";
    }
    return "unknown";
}

// cexpr_t::m of a cot_memref/cot_memptr, as a byte offset into the structure.
// raw_m is the field as this build's SDK declares it. Under the 9.4 layout only
// the low 32 bits are the field: the rest of the 8-byte slot is shared with the
// y/a pointers of the same union and is not cleared when m is written.
[[nodiscard]] inline std::uint64_t member_byte_offset(std::uint64_t raw_m, std::uint32_t exflags,
                                                      decompiler_layout_t layout)
{
    if (layout == decompiler_layout_t::v95)
        return (exflags & exfl_bitfield_95) != 0 ? raw_m / 8 : raw_m;
    return raw_m & 0xFFFFFFFFu;
}

} // namespace chernobog::hexrays_abi
