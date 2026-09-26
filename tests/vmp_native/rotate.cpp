#include "x86_abstract.h"
#include <cinttypes>
#include <cstdio>

using namespace chernobog::x86_abstract;

struct NativeResult
{
    uintptr_t value, before, after;
};
extern "C" void rt_execute(uint64_t, unsigned, unsigned, unsigned, unsigned, NativeResult *);
extern "C" int rt_rol_value(int), rt_ror_cf(int), rt_rcl_value(int), rt_rcr_value(int),
    rt_rcl_unknown_carry_cf(int), rt_rcl_unknown_carry_of(int), rt_rcr_unknown_carry_cf(int),
    rt_unknown_operand(int), rt_unknown_count(int), rt_zero_count(int), rt_cycle_count(int),
    rt_carry_cycle(int), rt_high_alias(int), rt_count_alias(int), rt_unknown_count_zero(int),
    rt_memory(int), rt_memory_ror(int), rt_memory_rcl(int), rt_memory_rcr(int), rt_target(int);
#if UINTPTR_MAX == UINT64_MAX
extern "C" int rt_zero_upper(int);
#endif

unsigned encode(unsigned bits)
{
    return (bits & CF ? 1 : 0) | (bits & PF ? 4 : 0) | (bits & AF ? 16 : 0) | (bits & ZF ? 64 : 0) |
           (bits & SF ? 128 : 0) | (bits & OF ? 2048 : 0) | 2;
}

unsigned decode(uintptr_t bits)
{
    return (bits & 1 ? CF : 0) | (bits & 4 ? PF : 0) | (bits & 16 ? AF : 0) | (bits & 64 ? ZF : 0) |
           (bits & 128 ? SF : 0) | (bits & 2048 ? OF : 0);
}

bool compare(unsigned operation, unsigned width, uint64_t input, unsigned count, unsigned profile)
{
    static constexpr Operation ops[] = {Operation::rotate_left, Operation::rotate_right,
                                        Operation::carry_left, Operation::carry_right};
    NativeResult actual;
    rt_execute(input, count, operation, width, encode(profile), &actual);
    Flags flags{ALL, uint8_t(profile)};
    const auto result = transfer(ops[operation], width, input, count, false, flags);
    if (!result)
        return false;
    Word destination{UINT64_MAX, uintptr_t(input)};
    destination.write(width, 0, result, sizeof(uintptr_t) == 8);
    const uintptr_t expected = uintptr_t(*destination.read(sizeof(uintptr_t) * 8));
    if (actual.value != expected || decode(actual.before) != profile ||
        (decode(actual.after) & flags.known) != flags.value)
    {
        std::fprintf(stderr, "rotate mismatch op=%u bits=%u a=%" PRIx64 " count=%u flags=%u\n",
                     operation, width, input, count, profile);
        return false;
    }
    return true;
}

int main()
{
    size_t byte_cases = 0, corner_cases = 0;
    for (unsigned operation = 0; operation < 4; ++operation)
        for (unsigned input = 0; input < 256; ++input)
            for (unsigned count = 0; count < 256; ++count)
                for (unsigned profile : {0u, unsigned(CF), unsigned(OF), unsigned(CF | OF)})
                {
                    if (!compare(operation, 8, input, count, profile))
                        return 1;
                    ++byte_cases;
                }
    const uint64_t inputs[] = {0,
                               1,
                               127,
                               128,
                               255,
                               32767,
                               32768,
                               65535,
                               UINT64_C(0x7fffffff),
                               UINT64_C(0x80000000),
                               UINT64_C(0xffffffff),
                               UINT64_C(0x7fffffffffffffff),
                               UINT64_C(0x8000000000000000),
                               UINT64_MAX,
                               UINT64_C(0x123456789abcdef0)};
    for (unsigned width : {8u, 16u, 32u, 64u})
    {
        if (width > sizeof(uintptr_t) * 8)
            continue;
        for (unsigned operation = 0; operation < 4; ++operation)
            for (uint64_t input : inputs)
                for (unsigned count :
                     {0u, 1u, 2u, 7u, 8u, 9u, 15u, 16u, 17u, 31u, 32u, 33u, 63u, 64u, 65u, 255u})
                    for (unsigned profile = 0; profile < 64; ++profile)
                    {
                        if (!compare(operation, width, input, count, profile))
                            return 2;
                        ++corner_cases;
                    }
    }
    for (int input = -256; input <= 255; ++input)
    {
        if (rt_rol_value(input) != 1 || rt_ror_cf(input) != 1 || rt_rcl_value(input) != 1 ||
            rt_rcr_value(input) != 1 || rt_rcl_unknown_carry_cf(input) != 1 ||
            rt_rcl_unknown_carry_of(input) != 1 || rt_rcr_unknown_carry_cf(input) != 1 ||
            rt_unknown_operand(input) != 1 || rt_unknown_count(input) != 1 ||
            rt_zero_count(input) != 1 || rt_cycle_count(input) != 0 || rt_carry_cycle(input) != 1 ||
            rt_high_alias(input) != 1 || rt_count_alias(input) != 1 ||
            rt_unknown_count_zero(input) != 1 || rt_memory(input) != 1 ||
            rt_memory_ror(input) != 1 || rt_memory_rcl(input) != 1 || rt_memory_rcr(input) != 1 ||
            rt_target(input) != 7)
            return 3;
#if UINTPTR_MAX == UINT64_MAX
        if (rt_zero_upper(input) != 1)
            return 4;
#endif
    }
    std::printf("{\"passed\":true,\"byte_cases\":%zu,\"corner_cases\":%zu,\"static_inputs\":512}\n",
                byte_cases, corner_cases);
    return 0;
}
