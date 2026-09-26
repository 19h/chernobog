#pragma once

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <utility>

namespace chernobog::x86_abstract
{

// Compact analysis bits, deliberately distinct from architectural EFLAGS bits.
enum Flag : uint8_t
{
    CF = 1,
    PF = 2,
    AF = 4,
    ZF = 8,
    SF = 16,
    OF = 32,
    ALL = 63
};

struct Flags
{
    uint8_t known = 0;
    uint8_t value = 0;

    void join(const Flags &other)
    {
        known &= uint8_t(other.known & uint8_t(~(value ^ other.value)));
        value &= known;
    }

    void forget(uint8_t mask = ALL)
    {
        known &= uint8_t(~mask);
        value &= known;
    }
    void set(uint8_t mask, bool one)
    {
        known |= mask;
        value = uint8_t((value & uint8_t(~mask)) | (one ? mask : 0));
    }
    std::optional<bool> get(uint8_t mask) const
    {
        if ((known & mask) != mask)
            return std::nullopt;
        return (value & mask) != 0;
    }
};

// Ordered as the sixteen architectural condition codes, not IDA opcodes.
enum class Condition : uint8_t
{
    overflow,
    not_overflow,
    below,
    above_equal,
    equal,
    not_equal,
    below_equal,
    above,
    sign,
    not_sign,
    parity,
    not_parity,
    less,
    greater_equal,
    less_equal,
    greater,
};

inline bool evaluate_complete(Condition condition, uint8_t flags)
{
    const bool c = (flags & CF) != 0, p = (flags & PF) != 0;
    const bool z = (flags & ZF) != 0, s = (flags & SF) != 0;
    const bool o = (flags & OF) != 0;
    switch (condition)
    {
    case Condition::overflow:
        return o;
    case Condition::not_overflow:
        return !o;
    case Condition::below:
        return c;
    case Condition::above_equal:
        return !c;
    case Condition::equal:
        return z;
    case Condition::not_equal:
        return !z;
    case Condition::below_equal:
        return c || z;
    case Condition::above:
        return !c && !z;
    case Condition::sign:
        return s;
    case Condition::not_sign:
        return !s;
    case Condition::parity:
        return p;
    case Condition::not_parity:
        return !p;
    case Condition::less:
        return s != o;
    case Condition::greater_equal:
        return s == o;
    case Condition::less_equal:
        return z || s != o;
    case Condition::greater:
        return !z && s == o;
    }
    return false;
}

inline std::optional<bool> evaluate(Condition condition, Flags flags)
{
    if (unsigned(condition) >= 16)
        return std::nullopt;
    std::optional<bool> result;
    for (unsigned bits = 0; bits <= ALL; ++bits)
    {
        if ((bits & flags.known) != (flags.value & flags.known))
            continue;
        const bool outcome = evaluate_complete(condition, uint8_t(bits));
        if (result && *result != outcome)
            return std::nullopt;
        result = outcome;
    }
    return result;
}

inline bool valid_width(unsigned bits)
{
    return bits == 8 || bits == 16 || bits == 32 || bits == 64;
}

inline uint64_t mask(unsigned bits)
{
    return bits == 64 ? UINT64_MAX : bits == 0 || bits > 64 ? 0 : (uint64_t{1} << bits) - 1;
}

// Known bits support AH/AL and other partial writes without equating aliases.
struct Word
{
    uint64_t known = 0;
    uint64_t value = 0;

    void join(const Word &other)
    {
        known &= other.known & ~(value ^ other.value);
        value &= known;
    }

    std::optional<uint64_t> read(unsigned bits, unsigned offset = 0) const
    {
        if (!valid_width(bits) || offset > 64 - bits)
            return std::nullopt;
        const uint64_t m = mask(bits);
        if (((known >> offset) & m) != m)
            return std::nullopt;
        return (value >> offset) & m;
    }

    void write(unsigned bits, unsigned offset, std::optional<uint64_t> v, bool zero_extend_32)
    {
        if (!valid_width(bits) || offset > 64 - bits)
        {
            *this = {};
            return;
        }
        const uint64_t m = mask(bits) << offset;
        known &= ~m;
        value &= ~m;
        if (v)
        {
            known |= m;
            value |= (*v << offset) & m;
        }
        if (zero_extend_32 && bits == 32 && offset == 0)
        {
            known |= UINT64_C(0xffffffff00000000);
            value &= UINT64_C(0xffffffff);
        }
    }
};

// Copy a sign extension without requiring every source bit to be known. The
// implicit accumulator forms either retain the low source bits or write only
// the high half into DX/EDX/RDX. Cache the source for the aliased AX/EAX/RAX case.
inline void sign_extend_accumulator(Word &destination, const Word &source, unsigned source_bits,
                                    bool high_half, bool mode64)
{
    if (high_half ? (source_bits != 16 && source_bits != 32 && source_bits != 64)
                  : (source_bits != 8 && source_bits != 16 && source_bits != 32))
    {
        destination = {};
        return;
    }
    const Word input = source;
    const unsigned destination_bits = high_half ? source_bits : source_bits * 2;
    const uint64_t written = mask(destination_bits);
    const uint64_t copied = high_half ? 0 : mask(source_bits);
    const uint64_t extended = written & ~copied;
    const uint64_t sign = uint64_t{1} << (source_bits - 1);
    destination.known = (destination.known & ~written) | (input.known & copied);
    destination.value = (destination.value & ~written) | (input.value & input.known & copied);
    if (input.known & sign)
    {
        destination.known |= extended;
        if (input.value & sign)
            destination.value |= extended;
    }
    if (mode64 && destination_bits == 32)
    {
        destination.known |= UINT64_C(0xffffffff00000000);
        destination.value &= UINT64_C(0xffffffff);
    }
}

// LAHF and SAHF exchange the five low status flags with AH. OF is neither
// encoded in AH nor changed by SAHF. Preserve knowledge of each bit separately.
inline void load_status_into_ah(Word &accumulator, const Flags &flags)
{
    constexpr uint64_t ah = UINT64_C(0xff00);
    accumulator.known = (accumulator.known & ~ah) | UINT64_C(0x2a00);
    accumulator.value = (accumulator.value & ~ah) | UINT64_C(0x0200);
    for (const auto [flag, bit] :
         {std::pair<uint8_t, unsigned>{CF, 0}, {PF, 2}, {AF, 4}, {ZF, 6}, {SF, 7}})
    {
        if (const auto value = flags.get(flag))
        {
            const uint64_t mask = uint64_t{1} << (bit + 8);
            accumulator.known |= mask;
            if (*value)
                accumulator.value |= mask;
        }
    }
}

inline void store_ah_into_status(Flags &flags, const Word &accumulator)
{
    for (const auto [flag, bit] :
         {std::pair<uint8_t, unsigned>{CF, 0}, {PF, 2}, {AF, 4}, {ZF, 6}, {SF, 7}})
    {
        const uint64_t mask = uint64_t{1} << (bit + 8);
        if (accumulator.known & mask)
            flags.set(flag, (accumulator.value & mask) != 0);
        else
            flags.forget(flag);
    }
}

enum class Operation : uint8_t
{
    unknown,
    add,
    adc,
    sub,
    sbb,
    compare,
    increment,
    decrement,
    negate,
    bit_and,
    bit_or,
    bit_xor,
    test,
    bit_not,
    shift_left,
    shift_right,
    arithmetic_right,
    rotate_left,
    rotate_right,
    carry_left,
    carry_right,
    clear_carry,
    set_carry,
    complement_carry,
};

inline void result_flags(Flags &flags, uint64_t result, unsigned width)
{
    flags.set(ZF, result == 0);
    flags.set(SF, (result & (uint64_t{1} << (width - 1))) != 0);
    unsigned parity = 0;
    for (unsigned i = 0; i < 8; ++i)
        parity ^= unsigned((result >> i) & 1);
    flags.set(PF, parity == 0);
}

inline bool rotate_operation(Operation op)
{
    return op == Operation::rotate_left || op == Operation::rotate_right ||
           op == Operation::carry_left || op == Operation::carry_right;
}

// Pure bitvector transfer, O(1) time/space. Missing values do not supply zero.
// same_operand is valid only for equal immutable values/register slices at this
// instruction; it must not be inferred from two memory addresses across writes.
inline std::optional<uint64_t> transfer(Operation op, unsigned width, std::optional<uint64_t> left,
                                        std::optional<uint64_t> right, bool same_operand,
                                        Flags &flags)
{
    if (op == Operation::clear_carry || op == Operation::set_carry)
    {
        flags.set(CF, op == Operation::set_carry);
        return std::nullopt;
    }
    if (op == Operation::complement_carry)
    {
        if (flags.known & CF)
            flags.value ^= CF;
        return std::nullopt;
    }
    if (!valid_width(width) || op == Operation::unknown)
    {
        flags.forget();
        return std::nullopt;
    }
    const uint64_t m = mask(width), sign = uint64_t{1} << (width - 1);
    if (left)
        *left &= m;
    if (right && op != Operation::shift_left && op != Operation::shift_right &&
        op != Operation::arithmetic_right)
        *right &= m;
    if (op == Operation::bit_not)
        return left ? std::optional<uint64_t>((~*left) & m) : std::nullopt;

    if (rotate_operation(op))
    {
        const bool through = op == Operation::carry_left || op == Operation::carry_right;
        const bool to_left = op == Operation::rotate_left || op == Operation::carry_left;
        const auto incoming_carry = flags.get(CF);
        if (!right)
        {
            // Every rotate preserves SF/ZF/AF/PF, including a variable count.
            // Constant all-zero/all-one words are invariant under plain rotates;
            // a carry rotate also needs a matching known incoming carry.
            flags.forget(CF | OF);
            if (left && (*left == 0 || *left == m) &&
                (!through || (incoming_carry && *incoming_carry == (*left != 0))))
            {
                if (incoming_carry && *incoming_carry == (*left != 0))
                    flags.set(CF, *incoming_carry);
                return left;
            }
            return std::nullopt;
        }
        const unsigned count = unsigned(*right & (width == 64 ? 63 : 31));
        if (count == 0)
            return left;
        const unsigned steps = through ? (width < 32 ? count % (width + 1) : count) : count % width;
        // A complete carry-ring cycle preserves its input and carry. OF is
        // left unknown for a nonzero masked count, including these cycles.
        if (through && steps == 0)
        {
            flags.forget(OF);
            return left;
        }
        flags.forget(CF | OF);
        if (!left)
            return std::nullopt;
        const uint64_t a = *left;
        if (!through)
        {
            const uint64_t result = steps == 0 ? a
                                    : to_left  ? ((a << steps) | (a >> (width - steps))) & m
                                               : ((a >> steps) | (a << (width - steps))) & m;
            flags.set(CF, to_left ? (result & 1) != 0 : (result & sign) != 0);
            if (count == 1)
                flags.set(OF, to_left ? ((result & sign) != 0) != ((result & 1) != 0)
                                      : ((result >> (width - 1)) ^ (result >> (width - 2))) & 1);
            return result;
        }
        // For admitted counts the outgoing carry is a source-word bit, even
        // when the incoming carry makes the destination value unknown.
        flags.set(CF, ((a >> (to_left ? width - steps : steps - 1)) & 1) != 0);
        if (count == 1)
        {
            if (to_left)
                flags.set(OF, ((a >> (width - 1)) ^ (a >> (width - 2))) & 1);
            else if (incoming_carry)
                flags.set(OF, ((a & sign) != 0) != *incoming_carry);
        }
        if (!incoming_carry)
            return std::nullopt;
        // Avoid a 64-bit shift by 64 in the one-step wraparound terms.
        const uint64_t result =
            to_left ? (a << steps) | (uint64_t(*incoming_carry) << (steps - 1)) |
                          (steps > 1 ? a >> (width + 1 - steps) : 0)
                    : (a >> steps) | (uint64_t(*incoming_carry) << (width - steps)) |
                          (steps > 1 ? a << (width + 1 - steps) : 0);
        return result & m;
    }

    if (op == Operation::shift_left || op == Operation::shift_right ||
        op == Operation::arithmetic_right)
    {
        // Count zero preserves *all* flags. An unknown count must not claim
        // even flags that would be defined for every nonzero count.
        if (!right)
        {
            flags.forget();
            return std::nullopt;
        }
        const unsigned count = unsigned(*right & (width == 64 ? 63 : 31));
        if (count == 0)
            return left;
        flags.forget();
        if (!left)
            return std::nullopt;
        const uint64_t a = *left;
        uint64_t result = 0;
        if (op == Operation::shift_left)
            result = count >= width ? 0 : (a << count) & m;
        else if (op == Operation::shift_right)
            result = count >= width ? 0 : a >> count;
        else
        {
            result = count >= width ? ((a & sign) ? m : 0) : a >> count;
            if (count < width && (a & sign))
                result |= m ^ (m >> count);
        }
        result_flags(flags, result, width);
        if (count < width || op == Operation::arithmetic_right)
        {
            const bool carry = op == Operation::shift_left
                                   ? ((a >> (width - count)) & 1) != 0
                                   : ((a >> (count >= width ? width - 1 : count - 1)) & 1) != 0;
            flags.set(CF, carry);
        }
        if (count == 1)
        {
            const bool overflow = op == Operation::shift_left
                                      ? ((result & sign) != 0) != ((a & sign) != 0)
                                      : op == Operation::shift_right && (a & sign) != 0;
            flags.set(OF, overflow);
        }
        return result;
    }

    if (op == Operation::bit_and || op == Operation::bit_or || op == Operation::bit_xor ||
        op == Operation::test)
    {
        flags.forget();
        flags.set(CF | OF, false);
        std::optional<uint64_t> result;
        if (same_operand && op == Operation::bit_xor)
            result = 0;
        else if (left && right)
        {
            if (op == Operation::bit_or)
                result = *left | *right;
            else if (op == Operation::bit_xor)
                result = *left ^ *right;
            else
                result = *left & *right;
        }
        else if ((op == Operation::bit_and || op == Operation::test) &&
                 ((left && *left == 0) || (right && *right == 0)))
            result = 0;
        else if (op == Operation::bit_or && ((left && *left == m) || (right && *right == m)))
            result = m;
        if (result)
            result_flags(flags, *result, width);
        return result;
    }

    const auto old_carry = flags.get(CF);
    const bool preserve_carry = op == Operation::increment || op == Operation::decrement;
    const bool with_carry = op == Operation::adc || op == Operation::sbb;
    flags.forget();
    if (op == Operation::increment || op == Operation::decrement)
        right = 1;
    if (op == Operation::negate)
    {
        right = left;
        left = 0;
    }
    if (same_operand && (op == Operation::sub || op == Operation::compare))
        left = right = 0;
    if (preserve_carry && old_carry)
        flags.set(CF, *old_carry);
    if (!left || !right || (with_carry && !old_carry))
        return std::nullopt;
    const uint64_t a = *left, b = *right;
    const uint64_t carry = with_carry && *old_carry ? 1 : 0;
    const bool subtract = op == Operation::sub || op == Operation::sbb ||
                          op == Operation::compare || op == Operation::decrement ||
                          op == Operation::negate;
    uint64_t result;
    bool cf, of;
    if (subtract)
    {
        result = (a - b - carry) & m;
        cf = a < b || (carry != 0 && a == b);
        of = ((a ^ b) & (a ^ result) & sign) != 0;
    }
    else
    {
        const uint64_t sum = (a + b) & m;
        result = (sum + carry) & m;
        cf = b > m - a || carry > m - sum;
        of = ((~(a ^ b)) & (a ^ result) & sign) != 0;
    }
    if (!preserve_carry)
        flags.set(CF, cf);
    flags.set(OF, of);
    flags.set(AF, ((a ^ b ^ result) & 16) != 0);
    result_flags(flags, result, width);
    return result;
}

} // namespace chernobog::x86_abstract
