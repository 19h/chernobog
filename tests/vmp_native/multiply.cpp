#include "x86_abstract.h"
#include <cinttypes>
#include <cstdio>

using namespace chernobog::x86_abstract;

struct NativeResult
{
    uintptr_t low, high, before, after;
};
extern "C" void mp_execute(uint64_t, uint64_t, unsigned, unsigned, unsigned, NativeResult *);
extern "C" int mp_stack_source(int);
extern "C" int mp_imul_word_two(int), mp_imul_word_imm8(int), mp_imul_word_imm16(int),
    mp_imul_word_high(int);
extern "C" int mp_mul_byte_value(int), mp_mul_byte_cf(int), mp_imul_byte_value(int),
    mp_imul_byte_of(int), mp_mul_word_high(int), mp_word_slices(int), mp_word_low_slice(int),
    mp_mul_dword_high(int), mp_imul_dword_high(int), mp_imul_fits(int), mp_imul_two(int),
    mp_imul_imm8(int), mp_imul_imm32(int), mp_unknown_zero(int), mp_unknown_one_cf(int),
    mp_unknown_one_high(int), mp_signed_unknown_one(int), mp_high_source(int),
    mp_accumulator_source(int), mp_high_byte_source(int), mp_imul_aliased_immediate(int),
    mp_memory(int), mp_memory_signed(int), mp_memory_two(int), mp_memory_three(int),
    mp_memory_retained(int), mp_target(int);
#if UINTPTR_MAX == UINT64_MAX
extern "C" int mp_quad_two(int), mp_quad_imm8(int), mp_quad_full_extended(int);
extern "C" int mp_mul_quad_high(int), mp_imul_quad_high(int), mp_quad_imm32(int),
    mp_zero_upper_low(int), mp_zero_upper_high(int), mp_extended(int);
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

bool compare(unsigned form, unsigned width, uint64_t left, uint64_t right, unsigned profile)
{
    NativeResult actual;
    mp_execute(left, right, form, width, encode(profile), &actual);
    const uint64_t operand = form < 3      ? right
                             : form == 3   ? uint64_t(-7)
                             : width == 16 ? uint64_t(-32768)
                                           : uint64_t(-INT64_C(2147483648));
    Flags flags{ALL, uint8_t(profile)};
    const Product product = multiply(width, form != 0, form < 3 ? left : right, operand, flags);
    if (!product.low || !product.high)
        return false;
    const uint64_t sentinel =
        sizeof(uintptr_t) == 8 ? UINT64_C(0x12345678a5a55a5a) : UINT64_C(0xa5a55a5a);
    Word low{UINT64_MAX, uintptr_t(left)}, high{UINT64_MAX, sentinel};
    low.write(width, 0, product.low, sizeof(uintptr_t) == 8);
    if (form < 2)
    {
        if (width == 8)
            low.write(8, 8, product.high, sizeof(uintptr_t) == 8);
        else
            high.write(width, 0, product.high, sizeof(uintptr_t) == 8);
    }
    if (actual.low != uintptr_t(*low.read(sizeof(uintptr_t) * 8)) ||
        actual.high != uintptr_t(*high.read(sizeof(uintptr_t) * 8)) ||
        decode(actual.before) != profile || (decode(actual.after) & flags.known) != flags.value)
    {
        std::fprintf(stderr,
                     "multiply mismatch form=%u bits=%u a=%" PRIx64 " b=%" PRIx64 " flags=%u\n",
                     form, width, left, right, profile);
        return false;
    }
    return true;
}

int main()
{
    size_t byte_cases = 0, corner_cases = 0;
    for (unsigned form = 0; form < 2; ++form)
        for (unsigned left = 0; left < 256; ++left)
            for (unsigned right = 0; right < 256; ++right)
                for (unsigned profile : {0u, unsigned(CF), unsigned(OF), unsigned(CF | OF)})
                {
                    if (!compare(form, 8, left, right, profile))
                        return 1;
                    ++byte_cases;
                }
    const uint64_t values[] = {0,
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
        for (unsigned form = 0; form < (width == 8 ? 2u : 5u); ++form)
            for (uint64_t left : values)
                for (uint64_t right : values)
                    for (unsigned profile = 0; profile < 64; ++profile)
                    {
                        if (!compare(form, width, left, right, profile))
                            return 2;
                        ++corner_cases;
                    }
    }
    for (int input = -256; input <= 255; ++input)
    {
        if (mp_stack_source(input) != 1)
            return 7;
        if (mp_imul_word_two(input) != 1 || mp_imul_word_imm8(input) != 1 ||
            mp_imul_word_imm16(input) != 1 || mp_imul_word_high(input) != 1)
            return 5;
        if (mp_mul_byte_value(input) != 1 || mp_mul_byte_cf(input) != 1 ||
            mp_imul_byte_value(input) != 1 || mp_imul_byte_of(input) != 1 ||
            mp_mul_word_high(input) != 1 || mp_word_slices(input) != 1 ||
            mp_word_low_slice(input) != 1 || mp_mul_dword_high(input) != 1 ||
            mp_imul_dword_high(input) != 1 || mp_imul_fits(input) != 1 || mp_imul_two(input) != 1 ||
            mp_imul_imm8(input) != 1 || mp_imul_imm32(input) != 1 || mp_unknown_zero(input) != 1 ||
            mp_unknown_one_cf(input) != 1 || mp_unknown_one_high(input) != 1 ||
            mp_signed_unknown_one(input) != 1 || mp_high_source(input) != 1 ||
            mp_accumulator_source(input) != 1 || mp_high_byte_source(input) != 1 ||
            mp_imul_aliased_immediate(input) != 1 || mp_memory(input) != 1 ||
            mp_memory_signed(input) != 1 || mp_memory_two(input) != 1 ||
            mp_memory_three(input) != 1 || mp_memory_retained(input) != 1 || mp_target(input) != 7)
            return 3;
#if UINTPTR_MAX == UINT64_MAX
        if (mp_quad_two(input) != 1 || mp_quad_imm8(input) != 1 ||
            mp_quad_full_extended(input) != 1)
            return 6;
        if (mp_mul_quad_high(input) != 1 || mp_imul_quad_high(input) != 1 ||
            mp_quad_imm32(input) != 1 || mp_zero_upper_low(input) != 1 ||
            mp_zero_upper_high(input) != 1 || mp_extended(input) != 1)
            return 4;
#endif
    }
    std::printf("{\"passed\":true,\"byte_cases\":%zu,\"corner_cases\":%zu,\"static_inputs\":512}\n",
                byte_cases, corner_cases);
    return 0;
}
