#pragma once

#include "bitvector.h"
#include <bytes.hpp>
#include <ida.hpp>
#include <limits>
#include <optional>

namespace chernobog {
namespace ida_memory {

inline bool read_exact(void *buffer, size_t bytes, ea_t address)
{
    if ( address == BADADDR || (bytes != 0 && buffer == nullptr)
      || bytes > static_cast<size_t>(std::numeric_limits<ssize_t>::max()) )
    {
        return false;
    }
    if ( bytes == 0 )
        return true;
    return get_bytes(buffer, bytes, address) == static_cast<ssize_t>(bytes);
}

inline std::optional<uint64_t> read_integer(ea_t address, int bytes)
{
    if ( address == BADADDR || !bitvector::valid_byte_width(bytes) )
        return std::nullopt;

    uint8_t raw[8] = {};
    if ( !read_exact(raw, static_cast<size_t>(bytes), address) )
        return std::nullopt;
    return bitvector::decode_bytes(raw, bytes, inf_is_be());
}

} // namespace ida_memory
} // namespace chernobog
