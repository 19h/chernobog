#include <stdint.h>
#include <stdio.h>

typedef uint64_t (*mba_function)(uint32_t, uint32_t, uint32_t);

__attribute__((noinline)) uint64_t mba_nested_1(uint32_t x, uint32_t y, uint32_t z)
{
    (void)y;
    return (z | ~x) + z + 1U + (z & ~x);
}

__attribute__((noinline)) uint64_t mba_nested_2(uint32_t x, uint32_t y, uint32_t z)
{
    (void)z;
    return x + y + x;
}

__attribute__((noinline)) uint64_t mba_nested_3(uint32_t x, uint32_t y, uint32_t z)
{
    return (y & ~z) + y + x - (y | z);
}

__attribute__((noinline)) uint64_t mba_nested_combined(uint32_t x, uint32_t y, uint32_t z)
{
    return ((y | z) & ~z) + (x ^ (x + y)) + (z | ~x) + z + x + 1U + (z & ~((z | ~x) + x + 1U)) + y +
           2U * ((x + y) & x) - (y | z);
}

__attribute__((noinline)) uint64_t mba_nested_solve(uint32_t x, uint32_t y, uint32_t z)
{
    return 2U * (((y | z) & ~z) + (z | ~x) + x + z + 1U + y + ((y + x) ^ x) + (z & ~(x & z)) +
                 2U * ((y + x) & x) - (y | z));
}

__attribute__((noinline)) uint64_t mba_nested_caller(uint32_t x, uint32_t y, uint32_t z)
{
    return (uint32_t)(2U * mba_nested_combined(x, y, z));
}

// The same oracle checks native fixtures and compiled IDA pseudocode. Every
// expected value uses unsigned 32-bit arithmetic before the 64-bit return.
static int check_values(const mba_function *functions, uint32_t x, uint32_t y, uint32_t z)
{
    const uint32_t expected[] = {
        2U * z - x,
        2U * x + y,
        x + y - z,
        2U * (x + y) + z,
        2U * (2U * (x + y) + z),
        2U * (2U * (x + y) + z),
    };
    for (unsigned index = 0; index < sizeof(expected) / sizeof(expected[0]); ++index)
    {
        const uint64_t actual = functions[index](x, y, z);
        if (actual != expected[index])
        {
            fprintf(stderr, "MBA %u mismatch: x=%08x y=%08x z=%08x actual=%llx expected=%x\n",
                    index, x, y, z, (unsigned long long)actual, expected[index]);
            return 1;
        }
    }
    return 0;
}

static int verify_functions(const mba_function *functions)
{
    static const uint32_t boundaries[] = {
        0, 1, 2, 0x7F, 0x80, 0xFF, 0x100, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF,
    };
    unsigned long long comparisons = 0;
    for (unsigned x = 0; x < 11; ++x)
    {
        for (unsigned y = 0; y < 11; ++y)
        {
            for (unsigned z = 0; z < 11; ++z)
            {
                if (check_values(functions, boundaries[x], boundaries[y], boundaries[z]))
                {
                    return 1;
                }
                comparisons += 6;
            }
        }
    }

    uint32_t state = UINT32_C(0xF07C9331);
    for (unsigned index = 0; index < 100000; ++index)
    {
        state = state * UINT32_C(1664525) + UINT32_C(1013904223);
        const uint32_t x = state;
        state = state * UINT32_C(1664525) + UINT32_C(1013904223);
        const uint32_t y = state;
        state = state * UINT32_C(1664525) + UINT32_C(1013904223);
        if (check_values(functions, x, y, state))
        {
            return 1;
        }
        comparisons += 6;
    }
    printf("Nested MBA comparisons: %llu\n", comparisons);
    return 0;
}

int main(void)
{
    const mba_function functions[] = {mba_nested_1,        mba_nested_2,     mba_nested_3,
                                      mba_nested_combined, mba_nested_solve, mba_nested_caller};
    return verify_functions(functions);
}
