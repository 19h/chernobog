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

struct DonorFunction
{
    struct StackPoint
    {
        uint16_t offset = 0;
        int16_t sp = 0;
    };
    uint64_t owner_node = 0;
    uint64_t start_node = 0;
    uint64_t entry_end_node = 0;
    uint32_t length = 0;
    uint32_t flags = 0;
    uint8_t word_bytes = 0;
    std::vector<StackPoint> stack_points;
};

struct Receipt
{
    uint64_t source_node = 0;
    uint64_t site_node = 0;
    std::vector<Edge> edges;
    std::string comment;
    std::optional<uint64_t> noreturn_function_node;
    std::optional<DonorFunction> donor_function;
};

constexpr size_t maximum_edges = 8;
constexpr size_t maximum_comment = 512;
constexpr uint32_t maximum_donor_length = 4096;
constexpr size_t maximum_donor_stack_points = 32;
constexpr size_t maximum_size =
    4 + 8 + 8 + 1 + maximum_edges * 10 + 2 + maximum_comment + 43 + maximum_donor_stack_points * 4;

inline bool valid_donor(const DonorFunction &donor)
{
    if (donor.length == 0 || donor.length > maximum_donor_length ||
        (donor.word_bytes != 4 && donor.word_bytes != 8) || donor.stack_points.empty() ||
        donor.stack_points.size() > maximum_donor_stack_points ||
        donor.stack_points.front().offset != 0)
        return false;
    uint16_t previous = 0;
    for (size_t i = 0; i < donor.stack_points.size(); ++i)
    {
        const auto &point = donor.stack_points[i];
        if (point.offset >= donor.length || (i != 0 && point.offset <= previous) ||
            point.sp < -4096 || point.sp > 4096)
            return false;
        previous = point.offset;
    }
    return true;
}

inline bool valid_comment(const std::string &comment)
{
    return comment.size() <= maximum_comment &&
           comment.find_first_of(std::string("\0\n\r", 3)) == std::string::npos;
}

inline std::optional<std::vector<uint8_t>> encode(const Receipt &receipt)
{
    if (receipt.edges.size() > maximum_edges || !valid_comment(receipt.comment) ||
        (receipt.donor_function && !valid_donor(*receipt.donor_function)))
        return std::nullopt;
    std::vector<uint8_t> result{'N', 'P', 'R',
                                uint8_t(receipt.donor_function           ? 3
                                        : receipt.noreturn_function_node ? 2
                                                                         : 1)};
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
    if (receipt.donor_function)
    {
        put(receipt.noreturn_function_node ? 1 : 0, 1);
        put(receipt.noreturn_function_node.value_or(0), 8);
        put(receipt.donor_function->owner_node, 8);
        put(receipt.donor_function->start_node, 8);
        put(receipt.donor_function->entry_end_node, 8);
        put(receipt.donor_function->length, 4);
        put(receipt.donor_function->flags, 4);
        put(receipt.donor_function->word_bytes, 1);
        put(receipt.donor_function->stack_points.size(), 1);
        for (const auto &point : receipt.donor_function->stack_points)
        {
            put(point.offset, 2);
            put(uint16_t(point.sp), 2);
        }
    }
    else if (receipt.noreturn_function_node)
        put(*receipt.noreturn_function_node, 8);
    return result;
}

inline std::optional<Receipt> decode(const uint8_t *bytes, size_t size)
{
    if (bytes == nullptr || size < 23 || size > maximum_size || bytes[0] != 'N' ||
        bytes[1] != 'P' || bytes[2] != 'R' || (bytes[3] != 1 && bytes[3] != 2 && bytes[3] != 3))
        return std::nullopt;
    const bool noreturn_receipt = bytes[3] == 2;
    const bool donor_receipt = bytes[3] == 3;
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
    if (length > maximum_comment ||
        (donor_receipt ? size - cursor < length + 43
                       : size - cursor != length + (noreturn_receipt ? 8 : 0)))
        return std::nullopt;
    result.comment.assign(reinterpret_cast<const char *>(bytes + cursor), length);
    if (!valid_comment(result.comment))
        return std::nullopt;
    cursor += length;
    if (noreturn_receipt)
        result.noreturn_function_node = get(8);
    else if (donor_receipt)
    {
        const uint64_t has_noreturn = get(1);
        const uint64_t noreturn_node = get(8);
        DonorFunction donor;
        donor.owner_node = get(8);
        donor.start_node = get(8);
        donor.entry_end_node = get(8);
        donor.length = uint32_t(get(4));
        donor.flags = uint32_t(get(4));
        donor.word_bytes = uint8_t(get(1));
        const size_t point_count = size_t(get(1));
        if (point_count > maximum_donor_stack_points || size - cursor != point_count * 4)
            return std::nullopt;
        for (size_t i = 0; i < point_count; ++i)
            donor.stack_points.push_back({uint16_t(get(2)), int16_t(uint16_t(get(2)))});
        if (has_noreturn > 1 || (!has_noreturn && noreturn_node != 0) || !valid_donor(donor))
            return std::nullopt;
        if (has_noreturn)
            result.noreturn_function_node = noreturn_node;
        result.donor_function = donor;
    }
    return result;
}

} // namespace chernobog::ida_analysis::proof_receipt
