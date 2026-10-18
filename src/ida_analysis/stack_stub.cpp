#include "stack_stub.hpp"

#include <algorithm>
#include <initializer_list>

namespace chernobog::ida_analysis::classifier
{
namespace
{
struct Parser
{
    const uint8_t *bytes;
    size_t size, cursor = 0;
    stack_stub_t result;

    bool match(std::initializer_list<uint8_t> expected) const
    {
        return cursor <= size && expected.size() <= size - cursor &&
               std::equal(expected.begin(), expected.end(), bytes + cursor);
    }
    bool instruction(size_t length)
    {
        if (cursor > size || length > size - cursor ||
            result.instructions.size() >= stack_stub_maximum_instructions ||
            result.start + cursor + length > UINT32_MAX)
            return false;
        result.instructions.emplace_back(result.start + cursor, uint16_t(length));
        cursor += length;
        return true;
    }
    uint32_t word(size_t offset) const
    {
        uint32_t value = 0;
        for (unsigned i = 0; i < 4; ++i)
            value |= uint32_t(bytes[offset + i]) << (8 * i);
        return value;
    }
    void access(int64_t offset, stack_access_kind_t kind, std::optional<uint64_t> before,
                std::optional<uint64_t> after, bool locked = false)
    {
        result.stack_accesses.push_back(
            {result.instructions.back().first, offset, 32, kind, before, after, locked});
    }
    bool push(unsigned reg, int64_t offset, std::optional<uint64_t> value = std::nullopt)
    {
        if (match({uint8_t(0x50 + reg)}))
        {
            if (!instruction(1))
                return false;
        }
        else if (match({0x8d, 0x64, 0x24, 0xfc, 0x89, uint8_t(4 | reg << 3), 0x24}))
        {
            if (!instruction(4) || !instruction(3))
                return false;
        }
        else
            return false;
        access(offset, stack_access_kind_t::write, std::nullopt, value);
        return true;
    }
    bool address(unsigned reg, uint32_t &value)
    {
        if (!match({0x8d, uint8_t(5 | reg << 3)}) || size - cursor < 6)
            return false;
        value = word(cursor + 2);
        if (!instruction(6))
            return false;
        if (match({0x8d, uint8_t(0x40 | reg << 3 | reg)}) && size - cursor >= 3)
        {
            value += uint32_t(int32_t(int8_t(bytes[cursor + 2])));
            return instruction(3);
        }
        if (match({0x8d, uint8_t(0x80 | reg << 3 | reg)}) && size - cursor >= 6)
        {
            value += word(cursor + 2);
            return instruction(6);
        }
        return false;
    }
    bool parse(unsigned reg)
    {
        if (!push(reg, -4) || !push(reg, -8) || !address(reg, result.continuation) ||
            !match({0x89, uint8_t(0x44 | reg << 3), 0x24, 4}) || !instruction(4))
            return false;
        access(-4, stack_access_kind_t::write, std::nullopt, result.continuation);
        if (!address(reg, result.handler))
            return false;
        if (match({0x87, uint8_t(4 | reg << 3), 0x24, 0xc3}))
        {
            if (!instruction(3))
                return false;
            access(-8, stack_access_kind_t::read_modify_write, std::nullopt, result.handler, true);
            result.transfer = result.start + cursor;
            if (!instruction(1))
                return false;
            access(-8, stack_access_kind_t::read, result.handler, std::nullopt);
        }
        else
        {
            if (!push(reg, -12, result.handler) ||
                !match({0x8b, uint8_t(0x44 | reg << 3), 0x24, 4, 0xc2, 4, 0}) || !instruction(4))
                return false;
            access(-8, stack_access_kind_t::read, std::nullopt, std::nullopt);
            result.transfer = result.start + cursor;
            if (!instruction(3))
                return false;
            result.return_adjustment = 4;
            access(-12, stack_access_kind_t::read, result.handler, std::nullopt);
        }
        result.end = result.start + cursor;
        result.saved_register = uint8_t(reg);
        return true;
    }
};
} // namespace

std::optional<stack_stub_t> classify_stack_stub32(const uint8_t *bytes, size_t size, uint64_t start)
{
    if (bytes == nullptr || start > UINT32_MAX)
        return std::nullopt;
    size = std::min(size, stack_stub_maximum_bytes);
    for (unsigned reg : {0U, 1U, 2U, 3U, 5U, 6U, 7U})
    {
        Parser parser{bytes, size, 0, {}};
        parser.result.start = start;
        if (parser.parse(reg))
            return parser.result;
    }
    return std::nullopt;
}
} // namespace chernobog::ida_analysis::classifier
