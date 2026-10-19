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
        }
    }
    printf("MBA SMT native comparisons: %u\n", comparisons);
    return 0;
}
