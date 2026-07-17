#pragma once

#include <cstdint>
#include <limits>

namespace chernobog {
namespace bitvector {

constexpr bool valid_byte_width(int bytes)
{
    return bytes >= 1 && bytes <= 8;
}

constexpr unsigned bit_width(int bytes)
{
    return valid_byte_width(bytes) ? static_cast<unsigned>(bytes * 8) : 64U;
}

constexpr uint64_t mask(int bytes)
{
    if ( !valid_byte_width(bytes) || bytes == 8 )
        return std::numeric_limits<uint64_t>::max();
    return (uint64_t{1} << static_cast<unsigned>(bytes * 8)) - 1;
}

constexpr uint64_t truncate(uint64_t value, int bytes)
{
    return value & mask(bytes);
}

constexpr uint64_t logical_not(uint64_t value)
{
    return value == 0 ? 1 : 0;
}

constexpr uint64_t negate(uint64_t value, int bytes)
{
    return truncate(uint64_t{0} - value, bytes);
}

// Interpret the low `bytes * 8` bits as a two's-complement signed integer.
// The negative path uses a representable positive magnitude, avoiding an
// implementation-defined unsigned-to-signed conversion.
constexpr int64_t sign_extend(uint64_t value, int bytes)
{
    const unsigned bits = bit_width(bytes);
    const uint64_t width_mask = mask(bytes);
    const uint64_t narrowed = value & width_mask;
    const uint64_t sign_bit = uint64_t{1} << (bits - 1);
    if ( (narrowed & sign_bit) == 0 )
        return static_cast<int64_t>(narrowed);

    const uint64_t magnitude = ((~narrowed) & width_mask) + 1;
    if ( magnitude == (uint64_t{1} << 63) )
        return std::numeric_limits<int64_t>::min();
    return -static_cast<int64_t>(magnitude);
}

constexpr uint64_t shift_left(uint64_t value, uint64_t shift, int bytes)
{
    const unsigned bits = bit_width(bytes);
    return shift >= bits ? 0 : truncate(truncate(value, bytes) << shift, bytes);
}

constexpr uint64_t shift_right_logical(uint64_t value, uint64_t shift, int bytes)
{
    const unsigned bits = bit_width(bytes);
    return shift >= bits ? 0 : truncate(value, bytes) >> shift;
}

constexpr uint64_t shift_right_arithmetic(uint64_t value, uint64_t shift, int bytes)
{
    const unsigned bits = bit_width(bytes);
    const uint64_t width_mask = mask(bytes);
    const uint64_t narrowed = value & width_mask;
    const bool negative = (narrowed & (uint64_t{1} << (bits - 1))) != 0;

    if ( shift >= bits )
        return negative ? width_mask : 0;
    if ( shift == 0 )
        return narrowed;

    uint64_t result = narrowed >> shift;
    if ( negative )
        result |= width_mask ^ ((uint64_t{1} << (bits - shift)) - 1);
    return result & width_mask;
}

constexpr int64_t signed_min(int bytes)
{
    const unsigned bits = bit_width(bytes);
    return bits == 64
        ? std::numeric_limits<int64_t>::min()
        : -(int64_t{1} << (bits - 1));
}

// Decode 1..8 target bytes without depending on the host byte order.
constexpr uint64_t decode_bytes(const uint8_t* data, int bytes, bool big_endian)
{
    if ( data == nullptr || !valid_byte_width(bytes) )
        return 0;

    uint64_t value = 0;
    if ( big_endian ) {
        for ( int i = 0; i < bytes; ++i )
            value = (value << 8U) | data[i];
    } else {
        for ( int i = 0; i < bytes; ++i )
            value |= uint64_t{data[i]} << static_cast<unsigned>(i * 8);
    }
    return value;
}

} // namespace bitvector
} // namespace chernobog
