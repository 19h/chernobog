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

    printf("MBA SMT native comparisons: %u\n", comparisons);
    return 0;
}
