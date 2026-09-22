/* Bounded, architecture-independent metadata ownership receipt codec. */
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace chernobog::ida_analysis::proof_receipt
{

// Addresses are IDA node identities supplied by the adapter, not raw EAs.
struct Edge
{
    uint64_t target_node = 0;
    uint8_t type = 0;
    bool user = false;
};

struct Receipt
{
    uint64_t source_node = 0;
    uint64_t site_node = 0;
    std::vector<Edge> edges;
    std::string comment;
};

constexpr size_t maximum_edges = 8;
constexpr size_t maximum_comment = 512;
constexpr size_t maximum_size = 4 + 8 + 8 + 1 + maximum_edges * 10 + 2 + maximum_comment;

inline bool valid_comment(const std::string &comment)
{
    return comment.size() <= maximum_comment &&
           comment.find_first_of(std::string("\0\n\r", 3)) == std::string::npos;
}

inline std::optional<std::vector<uint8_t>> encode(const Receipt &receipt)
{
    if (receipt.edges.size() > maximum_edges || !valid_comment(receipt.comment))
        return std::nullopt;
    std::vector<uint8_t> result{'N', 'P', 'R', 1};
    const auto put = [&](uint64_t value, unsigned size)
    {
        for (unsigned i = 0; i < size; ++i)
            result.push_back(uint8_t(value >> (i * 8)));
    };
    put(receipt.source_node, 8);
    put(receipt.site_node, 8);
    put(receipt.edges.size(), 1);
    for (const auto &edge : receipt.edges)
    {
        if (edge.type > 31)
            return std::nullopt;
        put(edge.target_node, 8);
        put(edge.type, 1);
        put(edge.user ? 1 : 0, 1);
    }
    put(receipt.comment.size(), 2);
    result.insert(result.end(), receipt.comment.begin(), receipt.comment.end());
    return result;
}

inline std::optional<Receipt> decode(const uint8_t *bytes, size_t size)
{
    if (bytes == nullptr || size < 23 || size > maximum_size || bytes[0] != 'N' ||
        bytes[1] != 'P' || bytes[2] != 'R' || bytes[3] != 1)
        return std::nullopt;
    size_t cursor = 4;
    const auto get = [&](unsigned count)
    {
        uint64_t value = 0;
        for (unsigned i = 0; i < count; ++i)
            value |= uint64_t(bytes[cursor++]) << (i * 8);
        return value;
    };
    Receipt result;
    result.source_node = get(8);
    result.site_node = get(8);
    const size_t count = size_t(get(1));
    if (count > maximum_edges || size < 23 + count * 10)
        return std::nullopt;
    for (size_t i = 0; i < count; ++i)
    {
        Edge edge;
        edge.target_node = get(8);
        edge.type = uint8_t(get(1));
        const auto user = get(1);
        if (edge.type > 31 || user > 1)
            return std::nullopt;
        edge.user = user != 0;
        result.edges.push_back(edge);
    }
    const size_t length = size_t(get(2));
    if (length > maximum_comment || size - cursor != length)
        return std::nullopt;
    result.comment.assign(reinterpret_cast<const char *>(bytes + cursor), length);
    if (!valid_comment(result.comment))
        return std::nullopt;
    return result;
}

} // namespace chernobog::ida_analysis::proof_receipt
