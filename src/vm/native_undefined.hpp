#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <set>
#include <vector>

namespace chernobog::vm
{
// Dependence descriptors for a deliberately bounded, straight-line slice.
// An undefined GPR value may influence private register/flag intermediates,
// but never an address, memory write, control decision or surviving output.
struct NativeUndefinedEffect
{
    uint64_t address = 0, next = 0;
    std::vector<uint8_t> bytes;
    uint16_t reads = 0, writes = 0, replaces = 0;
    uint16_t undefined_registers = 0;
    uint16_t nondeterministic_registers = 0;
    uint16_t addresses = 0, observable = 0;
    uint8_t flag_reads = 0, flag_writes = 0, flag_constants = 0, flag_undefined = 0;
    bool conditional = false, may_preserve_flags = false;
};
struct NativeUndefinedStep
{
    NativeUndefinedEffect effect;
    uint16_t unknown_registers = 0;
    uint8_t unknown_flags = 0;
};
struct NativeUndefinedSlice
{
    uint64_t entry = 0, end = 0;
    uint16_t destination = 0;
    std::vector<NativeUndefinedStep> steps;
};
using NativeUndefinedEffects = std::function<bool(uint64_t, NativeUndefinedEffect &)>;
using NativeUndefinedOracle = std::function<const NativeUndefinedSlice *(uint64_t)>;

// The first instruction is one exact BSWAP16 encoding. The supplied decoder
// must describe every subsequent effect completely and reject control choices,
// traps and unrepresented state. Full 32-bit writes also replace a GPR in long
// mode; partial and conditional writes never remove the old dependence.
// O(D log D) time and O(D) space, D <= 64, fixed register/flag sets.
inline NativeUndefinedSlice certify_native_undefined_slice(uint64_t entry, uint16_t destination,
                                                           const NativeUndefinedEffects &decode,
                                                           size_t maximum = 64)
{
    NativeUndefinedSlice result;
    if (!decode || !destination || (destination & (destination - 1)) ||
        (destination & (uint16_t(1) << 4)) || !maximum || maximum > 64)
        return result;
    result.entry = entry;
    result.destination = destination;
    uint16_t registers = 0;
    uint8_t flags = 0;
    uint64_t pc = entry;
    std::set<uint64_t> visited;
    for (size_t index = 0; index < maximum; ++index)
    {
        NativeUndefinedEffect effect;
        if (!visited.insert(pc).second || !decode(pc, effect) || effect.address != pc ||
            effect.bytes.empty() || effect.bytes.size() > 15 || !effect.next ||
            (effect.replaces & ~effect.writes) || (effect.flag_constants & ~effect.flag_writes) ||
            (effect.nondeterministic_registers & ~effect.writes) ||
            (effect.flag_undefined & ~effect.flag_writes) ||
            ((effect.flag_reads | effect.flag_writes) & ~uint8_t(0x3f)))
            return {};
        result.steps.push_back({effect, registers, flags});
        if (!index || effect.undefined_registers)
        {
            // Operand-size override, optionally one non-W REX prefix, 0F C8+rd.
            const auto &b = effect.bytes;
            const bool plain =
                b.size() == 3 && b[0] == 0x66 && b[1] == 0x0f && (b[2] & 0xf8) == 0xc8;
            const bool rex = b.size() == 4 && b[0] == 0x66 && (b[1] & 0xf8) == 0x40 &&
                             b[2] == 0x0f && (b[3] & 0xf8) == 0xc8;
            const unsigned reg = plain ? b[2] & 7 : rex ? (b[3] & 7) + ((b[1] & 1) ? 8 : 0) : 16;
            const uint16_t unknown = reg == 16 ? 0 : uint16_t(1u << reg);
            if (!unknown || (unknown & (uint16_t(1) << 4)) || (!index && destination != unknown) ||
                effect.undefined_registers != unknown || effect.next != pc + b.size() ||
                effect.writes != unknown || effect.reads || effect.replaces || effect.addresses ||
                effect.observable || effect.flag_reads || effect.flag_writes ||
                effect.nondeterministic_registers || effect.conditional ||
                effect.may_preserve_flags)
                return {};
            registers |= unknown;
        }
        else
        {
            if ((registers & (effect.addresses | effect.observable)) ||
                (registers & (uint16_t(1) << 4)))
                return {};
            const bool dependent = (registers & effect.reads) || (flags & effect.flag_reads);
            const uint16_t replaced = effect.conditional ? 0 : effect.replaces;
            registers &= uint16_t(~replaced);
            if (dependent)
                registers |= effect.writes;
            registers |= effect.nondeterministic_registers;
            uint8_t written = dependent ? effect.flag_writes : 0;
            written &= uint8_t(~effect.flag_constants);
            written |= effect.flag_undefined;
            if (effect.may_preserve_flags)
                written |= flags & effect.flag_writes;
            flags = uint8_t((flags & ~effect.flag_writes) | written);
            if (!registers && !flags)
            {
                result.end = effect.next;
                return result;
            }
        }
        pc = effect.next;
    }
    return {};
}
} // namespace chernobog::vm
