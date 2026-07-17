#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace chernobog::string_recovery {

enum class text_encoding_t {
    utf8,
    utf16_le,
    utf16_be,
    utf32_le,
    utf32_be,
};

struct recovered_text_t {
    std::string utf8;
    size_t payload_bytes = 0;
    size_t characters = 0;
    bool explicitly_terminated = false;
    text_encoding_t encoding = text_encoding_t::utf8;
};

inline bool admissible_text_codepoint(uint32_t codepoint)
{
    if ( codepoint == '\t' || codepoint == '\n' || codepoint == '\r' )
        return true;
    if ( codepoint < 0x20 || (codepoint >= 0x7F && codepoint <= 0x9F) )
        return false;
    return codepoint <= 0x10FFFF
        && !(codepoint >= 0xD800 && codepoint <= 0xDFFF);
}

inline void append_utf8(uint32_t codepoint, std::string *output)
{
    if ( codepoint <= 0x7F )
        output->push_back(static_cast<char>(codepoint));
    else if ( codepoint <= 0x7FF )
    {
        output->push_back(static_cast<char>(0xC0U | (codepoint >> 6U)));
        output->push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
    }
    else if ( codepoint <= 0xFFFF )
    {
        output->push_back(static_cast<char>(0xE0U | (codepoint >> 12U)));
        output->push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3FU)));
        output->push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
    }
    else
    {
        output->push_back(static_cast<char>(0xF0U | (codepoint >> 18U)));
        output->push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3FU)));
        output->push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3FU)));
        output->push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
    }
}

inline bool decode_utf8_payload(const std::vector<uint8_t>& bytes,
                                size_t payload_bytes,
                                recovered_text_t *result)
{
    if ( !result || payload_bytes == 0 || payload_bytes > bytes.size() )
        return false;

    size_t characters = 0;
    std::string output;
    output.reserve(payload_bytes);
    for ( size_t offset = 0; offset < payload_bytes; )
    {
        const uint8_t lead = bytes[offset];
        uint32_t codepoint = 0;
        size_t length = 0;
        if ( lead <= 0x7F )
        {
            codepoint = lead;
            length = 1;
        }
        else if ( lead >= 0xC2 && lead <= 0xDF )
        {
            codepoint = lead & 0x1FU;
            length = 2;
        }
        else if ( lead >= 0xE0 && lead <= 0xEF )
        {
            codepoint = lead & 0x0FU;
            length = 3;
        }
        else if ( lead >= 0xF0 && lead <= 0xF4 )
        {
            codepoint = lead & 0x07U;
            length = 4;
        }
        else
            return false;

        if ( length > payload_bytes - offset )
            return false;
        for ( size_t i = 1; i < length; ++i )
        {
            const uint8_t continuation = bytes[offset + i];
            if ( (continuation & 0xC0U) != 0x80U )
                return false;
            codepoint = (codepoint << 6U) | (continuation & 0x3FU);
        }

        const uint32_t minimum = length == 1 ? 0U
            : length == 2 ? 0x80U
            : length == 3 ? 0x800U : 0x10000U;
        if ( codepoint < minimum || !admissible_text_codepoint(codepoint) )
            return false;
        output.append(reinterpret_cast<const char *>(bytes.data() + offset), length);
        offset += length;
        ++characters;
    }

    result->utf8 = std::move(output);
    result->characters = characters;
    result->payload_bytes = payload_bytes;
    result->encoding = text_encoding_t::utf8;
    return true;
}

inline uint32_t decode_unit(const uint8_t *bytes, size_t width, bool big_endian)
{
    uint32_t value = 0;
    if ( big_endian )
    {
        for ( size_t i = 0; i < width; ++i )
            value = (value << 8U) | bytes[i];
    }
    else
    {
        for ( size_t i = 0; i < width; ++i )
            value |= uint32_t{bytes[i]} << static_cast<unsigned>(i * 8U);
    }
    return value;
}

inline bool decode_wide_payload(const std::vector<uint8_t>& bytes,
                                size_t payload_bytes,
                                size_t unit_width,
                                bool big_endian,
                                recovered_text_t *result)
{
    if ( !result || (unit_width != 2 && unit_width != 4)
      || payload_bytes == 0 || payload_bytes > bytes.size()
      || payload_bytes % unit_width != 0 )
    {
        return false;
    }

    std::string output;
    size_t characters = 0;
    for ( size_t offset = 0; offset < payload_bytes; offset += unit_width )
    {
        uint32_t codepoint = decode_unit(bytes.data() + offset,
                                         unit_width, big_endian);
        if ( unit_width == 2 && codepoint >= 0xD800 && codepoint <= 0xDBFF )
        {
            if ( payload_bytes - offset < 4 )
                return false;
            const uint32_t low = decode_unit(bytes.data() + offset + 2,
                                             2, big_endian);
            if ( low < 0xDC00 || low > 0xDFFF )
                return false;
            codepoint = 0x10000U + ((codepoint - 0xD800U) << 10U)
                      + (low - 0xDC00U);
            offset += 2;
        }
        if ( !admissible_text_codepoint(codepoint) )
            return false;
        append_utf8(codepoint, &output);
        ++characters;
    }

    result->utf8 = std::move(output);
    result->characters = characters;
    result->payload_bytes = payload_bytes;
    result->encoding = unit_width == 2
        ? (big_endian ? text_encoding_t::utf16_be : text_encoding_t::utf16_le)
        : (big_endian ? text_encoding_t::utf32_be : text_encoding_t::utf32_le);
    return true;
}

// Decode the exact byte stream produced by a contiguous static initializer.
// An explicit all-zero final code unit is consumed as a terminator.  When
// allow_unterminated is true, length-delimited strings are also admitted.
inline std::optional<recovered_text_t> recover_static_text(
    const std::vector<uint8_t>& bytes,
    size_t write_width,
    bool target_big_endian,
    bool allow_unterminated)
{
    if ( bytes.empty() )
        return std::nullopt;

    // UTF-8 is attempted first because it includes ordinary ASCII and packed
    // byte strings emitted through wider integer stores.
    size_t utf8_payload = bytes.size();
    bool utf8_terminated = false;
    const auto first_zero = std::find(bytes.begin(), bytes.end(), uint8_t{0});
    if ( first_zero != bytes.end() )
    {
        utf8_payload = static_cast<size_t>(first_zero - bytes.begin());
        utf8_terminated = utf8_payload + 1 == bytes.size();
    }
    recovered_text_t result;
    if ( (utf8_terminated || (first_zero == bytes.end() && allow_unterminated))
      && decode_utf8_payload(bytes, utf8_payload, &result) )
    {
        result.explicitly_terminated = utf8_terminated;
        return result;
    }

    if ( write_width != 2 && write_width != 4 )
        return std::nullopt;
    if ( bytes.size() % write_width != 0 )
        return std::nullopt;

    size_t wide_payload = bytes.size();
    bool wide_terminated = false;
    if ( decode_unit(bytes.data() + bytes.size() - write_width,
                     write_width, target_big_endian) == 0 )
    {
        wide_payload -= write_width;
        wide_terminated = true;
    }
    if ( !wide_terminated && !allow_unterminated )
        return std::nullopt;
    if ( !decode_wide_payload(bytes, wide_payload, write_width,
                              target_big_endian, &result) )
    {
        return std::nullopt;
    }
    result.explicitly_terminated = wide_terminated;
    return result;
}

inline std::string recover_hikari_xor_ascii(
    const std::vector<uint8_t>& encrypted_data,
    const std::vector<uint8_t>& xor_keys)
{
    if ( encrypted_data.empty() || xor_keys.empty() )
        return {};

    const size_t length = std::min(encrypted_data.size(), xor_keys.size());
    std::string result;
    result.reserve(length);

    for ( size_t i = 0; i < length; ++i )
    {
        const uint8_t decrypted = encrypted_data[i] ^ xor_keys[i];
        if ( decrypted == 0 )
            return result;
        if ( (decrypted < 32 || decrypted >= 127)
          && decrypted != '\n' && decrypted != '\t' && decrypted != '\r' )
        {
            return {};
        }
        result.push_back(static_cast<char>(decrypted));
    }

    // Hikari can append the destination terminator with a separate store.
    // In that form, the named source object has an explicit unencrypted zero
    // immediately after the complete contiguous XOR-key prefix.
    if ( length < encrypted_data.size() && encrypted_data[length] == 0 )
        return result;
    return {};
}

} // namespace chernobog::string_recovery
