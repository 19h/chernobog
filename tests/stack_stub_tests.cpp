#include "ida_analysis/stack_stub.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace chernobog::ida_analysis::classifier;

namespace
{
int failures = 0;
size_t cases = 0;
void check(bool value, const char *message)
{
    if (!value)
    {
        std::fprintf(stderr, "FAIL: %s\n", message);
        ++failures;
    }
}
void word(std::vector<uint8_t> &out, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i)
        out.push_back(uint8_t(value >> (i * 8)));
}
std::vector<uint8_t> fixture(unsigned reg, unsigned expanded, bool exchange,
                             uint32_t continuation = 0x12345678, uint32_t handler = 0x76543210,
                             bool wide_displacement = false, int32_t displacement = 0x30)
{
    std::vector<uint8_t> out;
    const auto push = [&](unsigned bit)
    {
        if (expanded & (1U << bit))
            out.insert(out.end(), {0x8d, 0x64, 0x24, 0xfc, 0x89, uint8_t(0x04 | reg << 3), 0x24});
        else
            out.push_back(uint8_t(0x50 + reg));
    };
    const auto address = [&](uint32_t target)
    {
        out.insert(out.end(), {0x8d, uint8_t(0x05 | reg << 3)});
        word(out, target - uint32_t(displacement));
        if (wide_displacement)
        {
            out.insert(out.end(), {0x8d, uint8_t(0x80 | reg << 3 | reg)});
            word(out, uint32_t(displacement));
        }
        else
            out.insert(out.end(), {0x8d, uint8_t(0x40 | reg << 3 | reg), uint8_t(displacement)});
    };
    push(0);
    push(1);
    address(continuation);
    out.insert(out.end(), {0x89, uint8_t(0x44 | reg << 3), 0x24, 4});
    address(handler);
    if (exchange)
        out.insert(out.end(), {0x87, uint8_t(0x04 | reg << 3), 0x24, 0xc3});
    else
    {
        push(2);
        out.insert(out.end(), {0x8b, uint8_t(0x44 | reg << 3), 0x24, 4, 0xc2, 4, 0});
    }
    return out;
}
}

int main()
{
    for (unsigned reg : {0U, 1U, 2U, 3U, 5U, 6U, 7U})
        for (bool exchange : {false, true})
            for (unsigned expanded = 0; expanded < (exchange ? 4U : 8U); ++expanded)
            {
                const auto bytes = fixture(reg, expanded, exchange);
                const auto result = classify_stack_stub32(bytes.data(), bytes.size(), 0x401000);
                ++cases;
                check(result.has_value(), "all saved registers and push substitutions admitted");
                if (!result)
                    continue;
                check(result->handler == 0x76543210 && result->continuation == 0x12345678,
                      "both independently materialized addresses recovered");
                check(result->saved_register == reg && result->stack_delta_bytes == -4 &&
                          result->return_adjustment == (exchange ? 0 : 4),
                      "handler-entry stack and restored register contract");
                check(result->end == 0x401000 + bytes.size(), "exact sequence end");
                size_t writes = 0, locked = 0;
                for (const auto &access : result->stack_accesses)
                {
                    writes += access.kind != stack_access_kind_t::read;
                    locked += access.implicit_lock;
                    check(access.width_bits == 32, "natural-width stack accesses");
                }
                check(writes == 4 && locked == unsigned(exchange),
                      "all writes and the atomic exchange survive the summary");
                for (size_t size = 0; size < bytes.size(); ++size)
                    check(!classify_stack_stub32(bytes.data(), size, 0x401000),
                          "every truncated prefix rejected");
                auto changed = bytes;
                changed.insert(changed.begin(), 0x66);
                check(!classify_stack_stub32(changed.data(), changed.size(), 0x401000),
                      "operand-size override rejected");
                changed = bytes;
                changed.back() ^= 1;
                check(!classify_stack_stub32(changed.data(), changed.size(), 0x401000),
                      "wrong return encoding rejected");
            }
    for (unsigned reg : {0U, 1U, 2U, 3U, 5U, 6U, 7U})
        for (bool exchange : {false, true})
            for (bool wide : {false, true})
                for (int32_t displacement : {-128, -1, 0, 127})
                {
                    const auto bytes =
                        fixture(reg, 0, exchange, 0x10, 0xfffffff0, wide, displacement);
                    const auto result = classify_stack_stub32(bytes.data(), bytes.size(), 0x401000);
                    check(result && result->continuation == 0x10 && result->handler == 0xfffffff0,
                          "signed disp8 and disp32 LEAs wrap at 32 bits");
                }
    for (bool exchange : {false, true})
    {
        const auto bytes = fixture(0, 0, exchange, 0x10, 0xfffffff0);
        const auto result = classify_stack_stub32(bytes.data(), bytes.size(), 0x401000);
        check(result && result->handler == 0xfffffff0 && result->continuation == 0x10,
              "address arithmetic wraps at 32 bits");
        check(!classify_stack_stub32(bytes.data(), bytes.size(), 0xfffffff0),
              "instruction range cannot wrap the address space");
        check(!classify_stack_stub32(nullptr, bytes.size(), 0x401000), "null bytes rejected");
        auto bad = fixture(4, 0, exchange);
        check(!classify_stack_stub32(bad.data(), bad.size(), 0x401000),
              "ESP cannot be saved register");
        bad = bytes;
        bad[1] = 0x51;
        check(!classify_stack_stub32(bad.data(), bad.size(), 0x401000),
              "different saved registers rejected");
        bad = bytes;
        bad.insert(bad.begin() + 2, 0x90);
        check(!classify_stack_stub32(bad.data(), bad.size(), 0x401000),
              "unmodeled instructions rejected");
    }
    uint32_t random = 0x8ac01937;
    std::array<uint8_t, 160> fuzz{};
    for (size_t trial = 0; trial < 10000; ++trial)
    {
        for (auto &byte : fuzz)
        {
            random = random * 1664525 + 1013904223;
            byte = uint8_t(random >> 24);
        }
        const auto result = classify_stack_stub32(fuzz.data(), trial % fuzz.size(), random);
        if (result)
            check(result->instructions.size() <= stack_stub_maximum_instructions &&
                      result->end - result->start <= stack_stub_maximum_bytes,
                  "random input never exceeds parsing budgets");
    }
    std::printf("stack stub cases=%zu failures=%d\n", cases, failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
