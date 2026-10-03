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

template <class Range, class FlagsAt>
inline std::optional<bool> evaluate_alternatives(Condition condition, const Range &inputs,
                                                 FlagsAt flags_at)
{
    std::optional<bool> result;
    for (const auto &input : inputs)
    {
        const auto outcome = evaluate(condition, flags_at(input));
        if (!outcome || (result && *outcome != *result))
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

    void write_partial(unsigned bits, unsigned offset, const Word &source, bool zero_extend_32)
    {
        if (!valid_width(bits) || offset > 64 - bits)
        {
            *this = {};
            return;
        }
        const uint64_t known_bits = source.known & mask(bits);
        const uint64_t value_bits = source.value & known_bits;
        write(bits, offset, std::nullopt, zero_extend_32);
        known |= known_bits << offset;
        value |= value_bits << offset;
    }
};

// Immediate AND fixes every masked-out bit even when the register is partial.
inline void and_constant(Word &destination, unsigned bits, unsigned offset, uint64_t immediate,
                         bool zero_extend_32)
{
    if (!valid_width(bits) || offset > 64 - bits)
    {
        destination = {};
        return;
    }
    const uint64_t m = mask(bits), operand = immediate & m;
    const uint64_t known = ((destination.known >> offset) | ~operand) & m;
    const uint64_t value = (destination.value >> offset) & operand & known;
    destination.write(bits, offset, std::nullopt, zero_extend_32);
    destination.known |= known << offset;
    destination.value |= value << offset;
}

// Immediate OR fixes every set bit; immediate XOR preserves which bits are
// known while toggling their values. Both retain unaffected register slices.
inline void or_constant(Word &destination, unsigned bits, unsigned offset, uint64_t immediate,
                        bool zero_extend_32)
{
    if (!valid_width(bits) || offset > 64 - bits)
    {
        destination = {};
        return;
    }
    const uint64_t m = mask(bits), operand = immediate & m;
    const uint64_t known = ((destination.known >> offset) | operand) & m;
    const uint64_t value = ((destination.value >> offset) | operand) & known;
    destination.write(bits, offset, std::nullopt, zero_extend_32);
    destination.known |= known << offset;
    destination.value |= value << offset;
}

inline void xor_constant(Word &destination, unsigned bits, unsigned offset, uint64_t immediate,
                         bool zero_extend_32)
{
    if (!valid_width(bits) || offset > 64 - bits)
    {
        destination = {};
        return;
    }
    const uint64_t m = mask(bits), operand = immediate & m;
    const uint64_t known = (destination.known >> offset) & m;
    const uint64_t value = ((destination.value >> offset) ^ operand) & known;
    destination.write(bits, offset, std::nullopt, zero_extend_32);
    destination.known |= known << offset;
    destination.value |= value << offset;
}

struct Product
{
    std::optional<uint64_t> low, high;
};

// Full 2w-bit product represented by two w-bit halves, without signed host
// overflow or a compiler-specific 128-bit integer. All six incoming flags are
// irrelevant: CF/OF describe overflow and the other four are undefined.
inline Product multiply(unsigned width, bool is_signed, std::optional<uint64_t> left,
                        std::optional<uint64_t> right, Flags &flags)
{
    flags.forget();
    if (!valid_width(width))
        return {};
    const uint64_t m = mask(width), sign = uint64_t{1} << (width - 1);
    if (left)
        *left &= m;
    if (right)
        *right &= m;
    if ((left && *left == 0) || (right && *right == 0))
    {
        flags.set(CF | OF, false);
        return {0, 0};
    }
    if (!left || !right)
    {
        if ((left && *left == 1) || (right && *right == 1))
        {
            flags.set(CF | OF, false);
            return {std::nullopt, is_signed ? std::nullopt : std::optional<uint64_t>{0}};
        }
        return {};
    }
    const uint64_t a = *left, b = *right;
    const uint64_t low = (a * b) & m;
    uint64_t high;
    if (width < 64)
        high = (a * b) >> width;
    else
    {
        const uint64_t a0 = uint32_t(a), b0 = uint32_t(b);
        const uint64_t p00 = a0 * b0, p01 = a0 * (b >> 32), p10 = (a >> 32) * b0;
        const uint64_t middle = (p00 >> 32) + uint32_t(p01) + uint32_t(p10);
        high = (a >> 32) * (b >> 32) + (p01 >> 32) + (p10 >> 32) + (middle >> 32);
    }
    if (is_signed)
        high = (high - ((a & sign) ? b : 0) - ((b & sign) ? a : 0)) & m;
    const bool overflow = is_signed ? high != ((low & sign) ? m : 0) : high != 0;
    flags.set(CF | OF, overflow);
    return {low, high};
}

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

// Two register slices have independent unknown bits except when they are the
// exact same slice. Return a result aligned to bit zero; the caller handles
// destination aliasing and x86-64 zero extension after both inputs are read.
inline std::optional<Word> bitwise_register_result(Operation op, unsigned bits, const Word &left,
                                                   unsigned left_offset, const Word &right,
                                                   unsigned right_offset, bool same_operand)
{
    if (!valid_width(bits) || left_offset > 64 - bits || right_offset > 64 - bits ||
        (op != Operation::bit_and && op != Operation::bit_or && op != Operation::bit_xor &&
         op != Operation::test))
        return std::nullopt;
    const uint64_t m = mask(bits);
    const uint64_t a_known = (left.known >> left_offset) & m;
    const uint64_t b_known = (right.known >> right_offset) & m;
    const uint64_t a_value = (left.value >> left_offset) & a_known;
    const uint64_t b_value = (right.value >> right_offset) & b_known;
    if (same_operand && op == Operation::bit_xor)
        return Word{m, 0};
    uint64_t known, value;
    if (op == Operation::bit_and || op == Operation::test)
    {
        const uint64_t one = a_value & b_value;
        const uint64_t zero = (a_known & ~a_value) | (b_known & ~b_value);
        known = one | zero;
        value = one;
    }
    else if (op == Operation::bit_or)
    {
        const uint64_t one = a_value | b_value;
        const uint64_t zero = a_known & b_known & ~(a_value | b_value);
        known = one | zero;
        value = one;
    }
    else
    {
        known = a_known & b_known;
        value = (a_value ^ b_value) & known;
    }
    return Word{known & m, value & m};
}

inline void result_flags(Flags &flags, uint64_t result, unsigned width)
{
    flags.set(ZF, result == 0);
    flags.set(SF, (result & (uint64_t{1} << (width - 1))) != 0);
    unsigned parity = 0;
    for (unsigned i = 0; i < 8; ++i)
        parity ^= unsigned((result >> i) & 1);
    flags.set(PF, parity == 0);
}

// Derive only status bits fixed by every concrete completion of a partial
// result. This does not define CF/OF or the architecturally undefined AF.
inline void partial_result_flags(Flags &flags, const Word &result, unsigned width,
                                 unsigned offset = 0)
{
    flags.forget(ZF | SF | PF);
    if (!valid_width(width) || offset > 64 - width)
        return;
    const uint64_t m = mask(width), known = (result.known >> offset) & m;
    const uint64_t value = (result.value >> offset) & known;
    if (value)
        flags.set(ZF, false);
    else if (known == m)
        flags.set(ZF, true);
    const uint64_t sign = uint64_t{1} << (width - 1);
    if (known & sign)
        flags.set(SF, (value & sign) != 0);
    if ((known & 255) == 255)
    {
        unsigned parity = 0;
        for (unsigned i = 0; i < 8; ++i)
            parity ^= unsigned((value >> i) & 1);
        flags.set(PF, parity == 0);
    }
}

// Carry known source bits through a shift with an exact masked count. Bits
// shifted in by SHL/SHR are zero; SAR copies the old sign bit. The caller
// handles register aliasing and 32-bit zero extension after reading the input.
inline Word partial_shift(Operation op, unsigned width, Word input, uint64_t raw_count,
                          Flags &flags)
{
    if (!valid_width(width) || (op != Operation::shift_left && op != Operation::shift_right &&
                                op != Operation::arithmetic_right))
    {
        flags.forget();
        return {};
    }
    const uint64_t m = mask(width), sign = uint64_t{1} << (width - 1);
    input.known &= m;
    input.value &= input.known;
    const unsigned count = unsigned(raw_count & (width == 64 ? 63 : 31));
    if (count == 0)
        return input;

    flags.forget();
    Word result;
    if (op == Operation::shift_left)
    {
        result.known = count >= width ? m : ((input.known << count) | mask(count)) & m;
        result.value = count >= width ? 0 : (input.value << count) & m;
    }
    else if (op == Operation::shift_right)
    {
        result.known = count >= width ? m : (input.known >> count) | (m ^ (m >> count));
        result.value = count >= width ? 0 : input.value >> count;
    }
    else
    {
        const unsigned steps = count >= width ? width : count;
        const uint64_t fill = steps == width ? m : m ^ (m >> steps);
        result.known = steps == width ? 0 : input.known >> steps;
        result.value = steps == width ? 0 : input.value >> steps;
        if (input.known & sign)
        {
            result.known |= fill;
            if (input.value & sign)
                result.value |= fill;
        }
    }
    result.known &= m;
    result.value &= result.known;
    if (count < width || op == Operation::arithmetic_right)
    {
        const unsigned carry_bit = op == Operation::shift_left ? width - count
                                   : count >= width            ? width - 1
                                                               : count - 1;
        const uint64_t bit = uint64_t{1} << carry_bit;
        if (input.known & bit)
            flags.set(CF, (input.value & bit) != 0);
    }
    if (count == 1)
    {
        if (op == Operation::arithmetic_right)
            flags.set(OF, false);
        else if (op == Operation::shift_right && (input.known & sign))
            flags.set(OF, (input.value & sign) != 0);
        else if (op == Operation::shift_left && (input.known & sign) && (result.known & sign))
            flags.set(OF, ((input.value ^ result.value) & sign) != 0);
    }
    partial_result_flags(flags, result, width);
    return result;
}

// BSWAP permutes bytes without changing status flags. A known bit remains
// known at its new byte position even when the rest of the register is unknown.
// The architecturally undefined 16-bit form is deliberately excluded.
inline Word byte_swap(unsigned width, Word input)
{
    if (width != 32 && width != 64)
        return {};
    input.known &= mask(width);
    input.value &= input.known;
    Word result;
    for (unsigned byte = 0; byte < width / 8; ++byte)
    {
        const unsigned source = byte * 8;
        const unsigned destination = width - 8 - source;
        result.known |= ((input.known >> source) & 255) << destination;
        result.value |= ((input.value >> source) & 255) << destination;
    }
    return result;
}

// SHLD/SHRD read both operands before writing the destination. An unknown
// count can include zero, so the caller must join the unchanged and written
// register states when applying an unknown result to a 32-bit destination.
inline Word double_shift(bool left, unsigned width, Word destination, Word source,
                         std::optional<uint64_t> raw_count, Flags &flags)
{
    if ((width != 16 && width != 32 && width != 64) || !raw_count)
    {
        flags.forget();
        return {};
    }
    const unsigned count = unsigned(*raw_count & (width == 64 ? 63 : 31));
    const uint64_t m = mask(width);
    destination.known &= m;
    destination.value &= destination.known;
    source.known &= m;
    source.value &= source.known;
    if (count == 0)
        return destination;
    flags.forget();
    // Intel leaves both the destination and all status flags undefined when a
    // 16-bit operand has a masked count greater than its width.
    if (count > width)
        return {};

    const uint64_t old_sign = uint64_t{1} << (width - 1);
    const unsigned carry_bit = left ? width - count : count - 1;
    if (destination.known & (uint64_t{1} << carry_bit))
        flags.set(CF, (destination.value & (uint64_t{1} << carry_bit)) != 0);
    Word result;
    if (count == width)
        result = source;
    else if (left)
    {
        result.known = ((destination.known << count) | (source.known >> (width - count))) & m;
        result.value = ((destination.value << count) | (source.value >> (width - count))) & m;
    }
    else
    {
        result.known = (destination.known >> count) | ((source.known << (width - count)) & m);
        result.value = (destination.value >> count) | ((source.value << (width - count)) & m);
    }
    result.value &= result.known;
    if (count == 1 && (destination.known & old_sign) && (result.known & old_sign))
        flags.set(OF, ((destination.value ^ result.value) & old_sign) != 0);
    partial_result_flags(flags, result, width);
    return result;
}

enum class BitAction : uint8_t
{
    test,
    complement,
    reset,
    set,
};

// The register-index form addresses a signed bit string in memory. Return the
// containing operand-word displacement modulo 2^64 without signed overflow.
// Immediate high bits do not advance the memory word.
inline std::optional<uint64_t> bit_string_word_delta(unsigned width, uint64_t index, bool immediate)
{
    if (width != 16 && width != 32 && width != 64)
        return std::nullopt;
    if (immediate)
        return uint64_t{0};
    const unsigned shift = width == 16 ? 4 : width == 32 ? 5 : 6;
    const uint64_t bits = index & mask(width);
    uint64_t quotient = bits >> shift;
    if (bits & (uint64_t{1} << (width - 1)))
        quotient |= ~mask(width - shift);
    return quotient * (width / 8);
}

// Register bit offsets wrap within the operand. Enumerating an unknown offset
// joins at most 64 concrete bit positions and retains only invariant facts.
inline Word bit_test_register(BitAction action, unsigned width, Word base,
                              std::optional<uint64_t> offset, Flags &flags)
{
    if (width != 16 && width != 32 && width != 64)
    {
        flags.forget();
        return {};
    }
    const uint64_t m = mask(width);
    base.known &= m;
    base.value &= base.known;
    flags.forget(CF | OF | SF | AF | PF);
    Word joined;
    bool first = true, carry_known = true, carry_value = false;
    const unsigned choices = offset ? 1 : width;
    for (unsigned choice = 0; choice < choices; ++choice)
    {
        const unsigned bit = offset ? unsigned(*offset % width) : choice;
        const uint64_t selected = uint64_t{1} << bit;
        if (!(base.known & selected))
            carry_known = false;
        else if (first)
            carry_value = (base.value & selected) != 0;
        else if (carry_value != ((base.value & selected) != 0))
            carry_known = false;
        Word candidate = base;
        if (action == BitAction::complement)
            candidate.value ^= selected & candidate.known;
        else if (action == BitAction::set)
        {
            candidate.known |= selected;
            candidate.value |= selected;
        }
        else if (action == BitAction::reset)
        {
            candidate.known |= selected;
            candidate.value &= ~selected;
        }
        if (first)
            joined = candidate;
        else
            joined.join(candidate);
        first = false;
    }
    if (carry_known)
        flags.set(CF, carry_value);
    return joined;
}

struct BitScanResult
{
    Word destination;
    bool nonzero_guaranteed = false;
};

// BSF/BSR define only ZF. A zero source makes the destination undefined;
// retaining an old destination value or assuming a 32-bit write is unsound.
// For a partial nonzero source, an index is exact only when every preceding
// bit in the scan direction is known zero.
inline BitScanResult bit_scan(bool reverse, unsigned width, Word source, Flags &flags)
{
    flags.forget();
    if (width != 16 && width != 32 && width != 64)
        return {};
    const uint64_t m = mask(width);
    source.known &= m;
    source.value &= source.known;
    const bool nonzero = source.value != 0;
    if (nonzero)
        flags.set(ZF, false);
    else if (source.known == m)
        flags.set(ZF, true);
    BitScanResult result;
    result.nonzero_guaranteed = nonzero;
    if (!nonzero)
        return result;
    bool preceding_clear = true;
    for (unsigned i = 0; i < width; ++i)
    {
        const unsigned index = reverse ? width - 1 - i : i;
        const uint64_t bit = uint64_t{1} << index;
        if (!(source.known & bit))
            preceding_clear = false;
        else if (source.value & bit)
        {
            if (preceding_clear)
                result.destination = Word{m, index};
            break;
        }
    }
    return result;
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

struct CompareRepeatStop
{
    uint64_t remaining = 0;
    Flags flags;
};

struct CompareOperands
{
    std::optional<uint64_t> left, right;
    bool same_operand = false;
};

// REPE continues after a comparison only while ZF=1; REPNE continues only
// while ZF=0. When the first comparison proves the opposite, one iteration
// has completed even if the initial count exceeds one. The caller establishes
// the architectural count width and exact single-iteration operand identity.
inline std::optional<CompareRepeatStop> first_compare_early_stop(unsigned width, uint64_t count,
                                                                 bool repeat_while_equal,
                                                                 std::optional<uint64_t> left,
                                                                 std::optional<uint64_t> right,
                                                                 bool same_operand, Flags before)
{
    if (count < 2 || !valid_width(width))
        return std::nullopt;
    transfer(Operation::compare, width, left, right, same_operand, before);
    const auto equal = before.get(ZF);
    if (!equal || *equal == repeat_while_equal)
        return std::nullopt;
    return CompareRepeatStop{count - 1, before};
}

// Replay only comparisons whose operands are available at their use. A
// missing comparison before the last iteration cannot establish whether the
// repeat continues. Once the exact count is exhausted, its value is zero
// even if the last comparison leaves flags unknown. Both possible DF paths
// must agree on the remaining count when direction is not known.
template <class OperandsAt>
inline std::optional<CompareRepeatStop>
bounded_compare_repeat(unsigned width, uint64_t count, bool repeat_while_equal,
                       std::optional<bool> reverse, Flags before, OperandsAt operands_at)
{
    constexpr uint64_t max_iterations = 128;
    if (count < 2 || !valid_width(width))
        return std::nullopt;
    const auto replay = [&](bool descending) -> std::optional<CompareRepeatStop>
    {
        Flags flags = before;
        for (uint64_t iteration = 0; iteration < count && iteration < max_iterations; ++iteration)
        {
            const auto operands = operands_at(iteration, descending);
            if (!operands)
                return std::nullopt;
            if (iteration == 0)
                if (const auto stop =
                        first_compare_early_stop(width, count, repeat_while_equal, operands->left,
                                                 operands->right, operands->same_operand, flags))
                    return stop;
            transfer(Operation::compare, width, operands->left, operands->right,
                     operands->same_operand, flags);
            const uint64_t remaining = count - iteration - 1;
            if (remaining == 0)
                return CompareRepeatStop{0, flags};
            const auto equal = flags.get(ZF);
            if (!equal)
                return std::nullopt;
            if (*equal != repeat_while_equal)
                return CompareRepeatStop{remaining, flags};
        }
        return std::nullopt;
    };
    if (reverse)
        return replay(*reverse);
    auto forward = replay(false), backward = replay(true);
    if (!forward || !backward || forward->remaining != backward->remaining)
        return std::nullopt;
    forward->flags.join(backward->flags);
    return forward;
}

} // namespace chernobog::x86_abstract
