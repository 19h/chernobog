#include <stdint.h>
#include <stdio.h>

__attribute__((noinline)) uint32_t mba_smt_semantic32(uint32_t x, uint32_t y)
{
    return 37U * (x ^ y) + 74U * (x & y) - 36U * (x + y);
}

__attribute__((noinline)) uint8_t mba_smt_quadratic(uint8_t x, unsigned count)
{
    uint8_t t = (uint8_t)(x * x);
    while (count-- != 0)
    {
        t = (uint8_t)(t + 2U * x + 1U);
        x = (uint8_t)(x + 1U);
    }
    return (uint8_t)(t - x * x);
}

__attribute__((noinline)) uint8_t mba_smt_alias(uint8_t *p, uint8_t *q, uint8_t x)
{
    *p = x;
    *q = (uint8_t)(x + 1U);
    return (uint8_t)(*p ^ x);
}

__attribute__((noinline)) uint8_t mba_transform_2(int8_t x, int8_t y)
{
    return (uint8_t)(x - 2 * (x & y) + y);
}

__attribute__((noinline)) uint8_t mba_transform_1(int8_t x, int8_t y, int8_t z)
{
    return (uint8_t)~((~x | z) & (x | y));
}

__attribute__((noinline)) uint32_t opaque_predicate_2(uint32_t x, uint32_t y)
{
    return (UINT32_C(0x5A75D737) * (((x ^ UINT32_C(0x393F5533)) | (y ^ UINT32_C(0x5E909F27))) +
                                    (x ^ UINT32_C(0xC6C0AACC))) +
            UINT32_C(0x5A75D737)) |
           UINT32_C(0x55588C79);
}

__attribute__((noinline)) uint64_t opaque_predicate_1(uint32_t x, uint32_t y)
{
    return ((((y ^ UINT32_C(0x3FA3EB91)) | (x ^ UINT32_C(0x29D81B96))) - UINT32_C(0x1F206DED)) |
            UINT32_C(0xAB597BD5)) /
           UINT64_C(0x52AC7B5E);
}

__attribute__((noinline)) uint32_t mba_call_xor_constants(void) { return mba_transform_2(19, 19); }

__attribute__((noinline)) uint32_t mba_call_selector_constants(void)
{
    return mba_transform_1(77, (int8_t)169, 86);
}

__attribute__((noinline)) uint64_t mba_call_quotient_constants(void)
{
    return opaque_predicate_1(UINT32_C(0xDEADBEEF), UINT32_C(0xCAFEBABE));
}

__attribute__((noinline)) uint32_t mba_call_product_constants(void)
{
    return opaque_predicate_2(UINT32_C(0x12345678), UINT32_C(0x9ABCDEF0));
}

__attribute__((noinline)) uint32_t mba_call_invariant_quotient(uint32_t x, uint32_t y)
{
    if (opaque_predicate_1(x, y) == UINT32_C(0x9E432F2E))
    {
        return 11;
    }
    return 42;
}

__attribute__((noinline)) uint32_t mba_call_invariant_nonzero(uint32_t x, uint32_t y)
{
    return opaque_predicate_2(x, y) != 0;
}

__attribute__((noinline)) uint64_t mba_call_varying(uint32_t x, uint32_t y)
{
    return opaque_predicate_1(x, y);
}

__attribute__((noinline)) uint32_t mba_call_shared_arguments(uint32_t x)
{
    return mba_transform_2((int8_t)x, (int8_t)x);
}

__attribute__((noinline)) uint8_t mba_call_narrow_helper(uint32_t x) { return (uint8_t)(x >> 12); }

__attribute__((noinline)) uint32_t mba_call_narrow_result(void)
{
    return mba_call_narrow_helper(UINT32_C(0x12345678));
}

volatile uint32_t mba_call_effects;

__attribute__((noinline)) uint32_t mba_call_impure_helper(void)
{
    ++mba_call_effects;
    return 7;
}

__attribute__((noinline)) uint32_t mba_call_impure(void) { return mba_call_impure_helper(); }

__attribute__((noinline)) uint32_t mba_call_load_helper(const uint32_t *value) { return *value; }

__attribute__((noinline)) uint32_t mba_call_memory(const uint32_t *value)
{
    return mba_call_load_helper(value);
}

__attribute__((noinline)) uint32_t mba_call_loop(uint32_t count)
{
    uint32_t value = 4;
    for (uint32_t index = 0; index < count; ++index)
    {
        value += 3;
    }
    return mba_transform_2((int8_t)value, 4);
}

__attribute__((noinline)) void mba_call_mutate_helper(uint32_t *value) { *value = 9; }

__attribute__((noinline)) uint32_t mba_call_address_escaped(void)
{
    uint32_t value = 4;
    mba_call_mutate_helper(&value);
    return mba_transform_2((int8_t)value, 4);
}

__attribute__((noinline)) void mba_context_observe(uint64_t value)
{
    mba_call_effects ^= (uint32_t)value;
}

__attribute__((noinline)) uint32_t mba_context_return_range(uint32_t x, uint32_t y)
{
    const uint64_t value = opaque_predicate_1(x, y);
    mba_context_observe(value);
    if (value == UINT32_C(0x9E432F2E))
    {
        return 11;
    }
    return 42;
}

__attribute__((noinline)) uint32_t mba_context_known_bits(uint32_t x, uint32_t y)
{
    const uint32_t value = opaque_predicate_2(x, y);
    mba_context_observe(value);
    return (value & UINT32_C(0x55588C79)) ^ UINT32_C(0x55588C79);
}

__attribute__((noinline)) uint32_t mba_context_empty_branch(uint32_t x, uint32_t y)
{
    for (uint32_t index = 0; index < (x & 3U); ++index)
    {
        if (opaque_predicate_2(x, y) == 0)
        {
            mba_context_observe(1);
        }
    }
    return 0;
}

__attribute__((noinline)) uint32_t mba_context_branch_equal(uint32_t x, uint32_t y)
{
    if (x == y)
    {
        return mba_transform_2((int8_t)x, (int8_t)y);
    }
    return 0;
}

__attribute__((noinline)) uint32_t mba_context_false_edge(uint32_t x, uint32_t y)
{
    if (x != y)
    {
        return 0;
    }
    return mba_transform_2((int8_t)x, (int8_t)y);
}

__attribute__((noinline)) uint32_t mba_context_join_equal(uint32_t x, uint32_t selector)
{
    uint32_t value;
    if (selector)
    {
        value = x ^ 0x56U;
        mba_context_observe(11);
    }
    else
    {
        value = x ^ 0x56U;
        mba_context_observe(42);
    }
    return mba_transform_2((int8_t)value, (int8_t)(x ^ 0x56U));
}

__attribute__((noinline)) uint32_t mba_context_join_different(uint32_t x, uint32_t selector)
{
    uint32_t value = x;
    if (selector)
    {
        value = x + 1;
    }
    mba_context_observe(value);
    return mba_transform_2((int8_t)value, (int8_t)x);
}

__attribute__((noinline)) uint32_t mba_context_overwrite(uint32_t x, uint32_t y)
{
    if (x == y)
    {
        x += 1;
        return mba_transform_2((int8_t)x, (int8_t)y);
    }
    return 0;
}

__attribute__((noinline)) uint32_t mba_context_old_value(uint32_t x)
{
    const uint32_t saved = x;
    x += 1;
    mba_context_observe(x);
    return mba_transform_2((int8_t)saved, (int8_t)x);
}

__attribute__((noinline)) uint32_t mba_context_symbolic_identity(uint32_t x)
{
    return mba_transform_2((int8_t)x, 0);
}

__attribute__((noinline)) uint32_t mba_context_symbolic_xor(uint32_t x, uint32_t y)
{
    return mba_transform_2((int8_t)x, (int8_t)y);
}

__attribute__((noinline)) uint32_t mba_context_symbolic_selector(uint32_t x)
{
    return mba_transform_1((int8_t)x, (int8_t)0xA9, 0x56);
}

__attribute__((noinline)) uint32_t mba_context_nested_calls(uint32_t x)
{
    return mba_transform_2((int8_t)mba_transform_1((int8_t)x, (int8_t)0xA9, 0x56), 0);
}

__attribute__((noinline)) uint32_t mba_context_symbolic_add(uint32_t x)
{
    return mba_smt_semantic32(x, 7);
}

__attribute__((noinline)) uint32_t mba_context_symbolic_shift(uint32_t x)
{
    return mba_call_narrow_helper(x);
}

__attribute__((noinline)) int64_t mba_context_signed_helper(int8_t value) { return value; }

__attribute__((noinline)) int64_t mba_context_symbolic_signed(uint32_t x)
{
    return mba_context_signed_helper((int8_t)x);
}

__attribute__((noinline)) uint8_t mba_context_byte_math_helper(uint8_t x, uint8_t y)
{
    return (uint8_t)(~x + y);
}

__attribute__((noinline)) uint64_t mba_context_symbolic_byte_math(uint32_t x, uint32_t y)
{
    return mba_context_byte_math_helper((uint8_t)x, (uint8_t)y);
}

__attribute__((noinline)) uint32_t mba_context_effectful_argument(uint32_t *value)
{
    return mba_transform_2((int8_t)(*value)++, 0);
}

__attribute__((noinline)) uint32_t mba_context_guard_overflow(uint32_t x)
{
    if (x == UINT32_MAX)
    {
        x += 1;
        return mba_transform_2((int8_t)x, 0);
    }
    return 0;
}

int main(void)
{
    unsigned comparisons = 0;
    for (unsigned x = 0; x < 256; ++x)
    {
        for (unsigned y = 0; y < 256; ++y)
        {
            if (mba_smt_semantic32(x * UINT32_C(0x01010101), y) != x * UINT32_C(0x01010101) + y)
            {
                return 1;
            }
            if (mba_smt_quadratic((uint8_t)x, y) != 0)
            {
                return 2;
            }
            uint8_t p = 0, q = 0;
            if (mba_smt_alias(&p, &q, (uint8_t)x) != 0 || p != x || q != (uint8_t)(x + 1U))
            {
                return 3;
            }
            if (mba_smt_alias(&p, &p, (uint8_t)x) != ((uint8_t)(x + 1U) ^ x) ||
                p != (uint8_t)(x + 1U))
            {
                return 4;
            }
            comparisons += 4;
            if (mba_transform_2((uint8_t)x, (uint8_t)y) != (uint8_t)(x ^ y))
            {
                return 5;
            }
            for (unsigned z = 0; z < 256; ++z)
            {
                const uint8_t selector = (uint8_t)~(y ^ (x & (y ^ z)));
                if (mba_transform_1((uint8_t)x, (uint8_t)y, (uint8_t)z) != selector)
                {
                    return 6;
                }
                ++comparisons;
            }
            ++comparisons;
        }
    }
    uint32_t state = UINT32_C(0xBAD5EED);
    for (unsigned index = 0; index < 100000; ++index)
    {
        state = state * UINT32_C(1664525) + UINT32_C(1013904223);
        const uint32_t x = state;
        state = state * UINT32_C(1664525) + UINT32_C(1013904223);
        const uint32_t y = state;
        const uint32_t reduced =
            (UINT32_C(0x5A75D737) * ((x ^ UINT32_C(0xC6C0AACC)) & (y ^ UINT32_C(0x5E909F27)))) |
            UINT32_C(0x55588C79);
        const uint32_t difference =
            ((y ^ UINT32_C(0x3FA3EB91)) | (x ^ UINT32_C(0x29D81B96))) - UINT32_C(0x1F206DED);
        if (opaque_predicate_2(x, y) != reduced || opaque_predicate_2(x, y) == 0)
        {
            return 7;
        }
        if (opaque_predicate_1(x, y) !=
            2 + ((difference & UINT32_C(0x50000000)) == UINT32_C(0x50000000)))
        {
            return 8;
        }
        comparisons += 2;
    }

    if (opaque_predicate_1(UINT32_C(0xE3A1F254), UINT32_C(0x3FA3EB91)) != 2 ||
        opaque_predicate_1(UINT32_C(0x36F8767A), UINT32_C(0x3FA3EB91)) != 3 ||
        opaque_predicate_2(UINT32_C(0xC6C0AACC), UINT32_C(0x5E909F27)) != UINT32_C(0x55588C79) ||
        opaque_predicate_2(UINT32_C(0xC5E2DBB5), UINT32_C(0x5DB2EE5E)) != UINT32_MAX)
    {
        return 9;
    }
    comparisons += 4;

    if (mba_call_xor_constants() != 0 || mba_call_selector_constants() != 27 ||
        mba_call_quotient_constants() != 3 ||
        mba_call_product_constants() != UINT32_C(0x75FAAFFD) || mba_call_narrow_result() != 0x45 ||
        mba_call_address_escaped() != 13)
    {
        return 10;
    }
    for (uint32_t index = 0; index < 256; ++index)
    {
        if (mba_call_invariant_quotient(index, ~index) != 42 ||
            mba_call_invariant_nonzero(index, ~index) != 1 ||
            mba_call_varying(index, ~index) != opaque_predicate_1(index, ~index) ||
            mba_call_memory(&index) != index ||
            mba_call_loop(index) != (uint8_t)((4 + 3 * index) ^ 4) ||
            mba_call_shared_arguments(index) != 0)
        {
            return 11;
        }
        const uint32_t effects_before = mba_call_effects;
        if (mba_call_impure() != 7 || mba_call_effects != effects_before + 1)
        {
            return 12;
        }
        comparisons += 7;

        for (uint32_t other = 0; other < 256; ++other)
        {
            const uint32_t expected_join = (uint8_t)((index + (other != 0)) ^ index);
            const uint32_t expected_overwrite = index == other ? (uint8_t)((index + 1) ^ other) : 0;
            if (mba_context_branch_equal(index, other) != 0 ||
                mba_context_false_edge(index, other) != 0 ||
                mba_context_join_equal(index, other) != 0 ||
                mba_context_join_different(index, other) != expected_join ||
                mba_context_overwrite(index, other) != expected_overwrite ||
                mba_context_symbolic_xor(index, other) != (uint8_t)(index ^ other) ||
                mba_context_symbolic_byte_math(index, other) != (uint8_t)(~index + other))
            {
                return 13;
            }
            comparisons += 7;
        }

        uint32_t mutable_value = index;
        const uint32_t previous_effects = mba_call_effects;
        if (mba_context_empty_branch(index, ~index) != 0 || mba_call_effects != previous_effects)
        {
            return 16;
        }
        ++comparisons;
        if (mba_context_return_range(index, ~index) != 42 ||
            mba_context_known_bits(index, ~index) != 0 ||
            mba_context_old_value(index) != (uint8_t)(index ^ (index + 1)) ||
            mba_context_symbolic_identity(index) != (uint8_t)index ||
            mba_context_symbolic_selector(index) != (uint8_t)(index ^ 0x56U) ||
            mba_context_nested_calls(index) != (uint8_t)(index ^ 0x56U) ||
            mba_context_symbolic_add(index) != index + 7 ||
            mba_context_symbolic_shift(index) != (uint8_t)(index >> 12) ||
            mba_context_symbolic_signed(index) != (int8_t)index ||
            mba_context_effectful_argument(&mutable_value) != index || mutable_value != index + 1 ||
            mba_context_guard_overflow(index) != 0)
        {
            return 14;
        }
        comparisons += 12;
    }
    comparisons += 6;

    if (mba_context_guard_overflow(UINT32_MAX) != 0 || mba_context_old_value(UINT32_MAX) != 0xFF ||
        mba_context_overwrite(UINT32_MAX, UINT32_MAX) != 0xFF)
    {
        return 15;
    }
    comparisons += 3;

    printf("MBA SMT native comparisons: %u\n", comparisons);
    return 0;
}
