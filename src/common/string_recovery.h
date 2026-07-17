#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace chernobog::string_recovery {

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
