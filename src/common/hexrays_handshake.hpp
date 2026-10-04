#pragma once

// Reaching the Hex-Rays decompiler of IDA 9.4 and 9.5 from one build.
//
// init_hexrays_plugin() offers only the magic of the SDK this binary was
// compiled with. A released 9.5 decompiler answers only its own magic, so that
// call fails for a 9.4-compiled plugin (and the reverse fails for a binary
// compiled against the 9.5 headers). handshake() offers both magics and records
// which layout answered. Values whose meaning differs are read through the
// accessors below. See hexrays_abi.hpp.

#include "hexrays_abi.hpp"
#include "warn_off.h"

#include <hexrays.hpp>

#include "warn_on.h"

#include <atomic>
#include <cstdint>
#include <optional>

namespace chernobog::hexrays
{

// The SDK this build compiles against must be one whose decompiler ABI
// hexrays_abi.hpp describes. A newer magic means a new ABI to teach it first.
static_assert(HEXRAYS_API_MAGIC == hexrays_abi::hexrays_magic_94 ||
                  HEXRAYS_API_MAGIC == hexrays_abi::hexrays_magic_95,
              "Hex-Rays SDK with an unknown decompiler ABI: extend hexrays_abi.hpp");
#ifdef EXFL_BITFIELD
static_assert(EXFL_BITFIELD == hexrays_abi::exfl_bitfield_95, "EXFL_BITFIELD moved");
#endif

namespace detail
{

inline std::atomic<hexrays_abi::decompiler_layout_t> accepted_layout{
    hexrays_abi::decompiler_layout_t::unknown};
inline std::atomic<bool> incompatibility_reported{false};

} // namespace detail

// Whether the decompiler is usable, for either IDA 9.4 or 9.5. Same
// ui_broadcast as init_hexrays_plugin(), offered at most twice.
[[nodiscard]] inline bool handshake(int flags = 0)
{
    char kernel_text[32] = {};
    const ssize_t kernel_length = get_kernel_version(kernel_text, sizeof(kernel_text));
    const std::optional<hexrays_abi::kernel_version_t> kernel =
        kernel_length > 0 ? hexrays_abi::parse_kernel_version(kernel_text) : std::nullopt;

    for (const std::int64_t magic : hexrays_abi::handshake_order(kernel))
    {
        hexdsp_t *unused = nullptr;
        if (callui(ui_broadcast, magic, &unused, flags).i == hexrays_abi::handshake_reply(magic))
        {
            detail::accepted_layout.store(hexrays_abi::layout_for_handshake(magic, kernel),
                                          std::memory_order_relaxed);
            return true;
        }
    }

    detail::accepted_layout.store(hexrays_abi::decompiler_layout_t::unknown,
                                  std::memory_order_relaxed);
    // A decompiler is installed for this database but answered neither magic.
    // Say so once rather than let every decompiler feature go quiet.
    if (get_hexdsp() != nullptr && !detail::incompatibility_reported.exchange(true))
    {
        const char *shown = kernel_text[0] != '\0' ? kernel_text : "unknown";
        msg("[chernobog] The Hex-Rays decompiler of IDA %s uses an API this build does "
            "not support\n",
            shown);
    }
    return false;
}

// The decompiler layout behind the last accepted handshake().
[[nodiscard]] inline hexrays_abi::decompiler_layout_t layout()
{
    return detail::accepted_layout.load(std::memory_order_relaxed);
}

// The structure offset a cot_memref/cot_memptr expression accesses, in bytes.
[[nodiscard]] inline std::uint64_t member_byte_offset(const cexpr_t &expr)
{
    return hexrays_abi::member_byte_offset(static_cast<std::uint64_t>(expr.m), expr.exflags,
                                           layout());
}

} // namespace chernobog::hexrays
