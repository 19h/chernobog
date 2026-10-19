#include <stdint.h>
#include <stdio.h>

volatile uint32_t mba_mask_effects;
uint32_t mba_mask_alias_target;

__attribute__((noinline)) void mba_mask_observe(int low, int high)
{
    mba_mask_effects += 1U + (uint32_t)low + 2U * (uint32_t)high;
    mba_mask_alias_target += UINT32_C(0xD0A75931);
}

__attribute__((noinline)) uint32_t mba_mask_value(uint32_t flags, int8_t input)
{
    const int high = (input & 0x11) == 0x11;
    return (uint32_t)(high << 6) |
           (((flags & UINT32_C(0xFFFFFFF7)) ^ (8U * (input & 1))) & UINT32_C(0xFFFFFFBF));
}

__attribute__((noinline)) uint32_t mba_mask_overlap(uint32_t flags, int8_t input)
{
    return ((flags & UINT32_C(0xFFFFFFF7)) ^ (8U * (input & 3))) & UINT32_C(0xFFFFFFBF);
}

__attribute__((noinline)) void mba_mask_store(uint32_t *flags, int8_t input)
{
    const int low = input & 1;
    const int high = (input & 0x11) == 0x11;
    const uint32_t previous = *flags;
    if (((previous & 8) != 0) != low || ((previous & 0x40) != 0) != high)
    {
        mba_mask_observe(low, high);
        *flags = (uint32_t)(high << 6) |
                 (((previous & UINT32_C(0xFFFFFFF7)) ^ (8U * (input & 1))) & UINT32_C(0xFFFFFFBF));
    }
}

__attribute__((noinline)) void mba_mask_volatile_store(volatile uint32_t *flags, int8_t input)
{
    const int low = input & 1;
    const int high = (input & 0x11) == 0x11;
    const uint32_t previous = *flags;
    if (((previous & 8) != 0) != low || ((previous & 0x40) != 0) != high)
    {
        mba_mask_observe(low, high);
        *flags = (uint32_t)(high << 6) |
                 (((previous & UINT32_C(0xFFFFFFF7)) ^ (8U * (input & 1))) & UINT32_C(0xFFFFFFBF));
    }
}

typedef uint32_t (*value_function)(uint32_t, int8_t);
typedef void (*store_function)(uint32_t *, int8_t);
typedef void (*volatile_store_function)(volatile uint32_t *, int8_t);

static int check_values(value_function value, value_function overlap, store_function store,
                        volatile_store_function volatile_store, uint32_t previous, int8_t input)
{
    const uint32_t low = (uint8_t)input & 1U;
    const uint32_t high = ((uint8_t)input & 0x11U) == 0x11U;
    const uint32_t inserted = (low << 3) | (high << 6);
    const uint32_t expected = (previous & ~UINT32_C(0x48)) | inserted;
    const uint32_t overlapping = (previous & ~UINT32_C(0x48)) ^ (((uint8_t)input & 3U) << 3);
    if (value(previous, input) != expected || overlap(previous, input) != overlapping)
    {
        return 1;
    }

    const uint32_t effects = previous ^ UINT32_C(0xB79DE37F);
    const uint32_t expected_effects = effects + (previous != expected ? 1U + low + 2U * high : 0);
    uint32_t destination = previous;
    mba_mask_effects = effects;
    store(&destination, input);
    if (destination != expected || mba_mask_effects != expected_effects)
    {
        return 2;
    }

    volatile uint32_t volatile_destination = previous;
    mba_mask_effects = effects;
    volatile_store(&volatile_destination, input);
    if (volatile_destination != expected || mba_mask_effects != expected_effects)
    {
        return 3;
    }

    // The observer can alias the destination. The store must still use the
    // snapshot loaded before that call, without introducing a second load.
    mba_mask_alias_target = previous;
    store(&mba_mask_alias_target, input);
    if (mba_mask_alias_target != expected)
    {
        return 4;
    }
    mba_mask_effects = previous;
    volatile_store(&mba_mask_effects, input);
    return mba_mask_effects == expected ? 0 : 5;
}

static int verify_functions(value_function value, value_function overlap, store_function store,
                            volatile_store_function volatile_store)
{
    unsigned long long comparisons = 0;
    for (uint32_t flags = 0; flags < 256; ++flags)
    {
        for (unsigned input = 0; input < 256; ++input)
        {
            if (check_values(value, overlap, store, volatile_store, flags, (int8_t)input))
            {
                fprintf(stderr, "Low-byte flag update mismatch: flags=%08x input=%02x\n", flags,
                        input);
                return 1;
            }
            comparisons += 6;
        }
    }

    static const uint32_t boundaries[] = {
        0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF,
    };
    for (unsigned index = 0; index < sizeof(boundaries) / sizeof(boundaries[0]); ++index)
    {
        for (unsigned input = 0; input < 256; ++input)
        {
            if (check_values(value, overlap, store, volatile_store, boundaries[index],
                             (int8_t)input))
            {
                return 2;
            }
            comparisons += 6;
        }
    }

    uint32_t state = UINT32_C(0xBC715EED);
    for (unsigned index = 0; index < 100000; ++index)
    {
        state = state * UINT32_C(1664525) + UINT32_C(1013904223);
        const uint32_t flags = state;
        state = state * UINT32_C(1664525) + UINT32_C(1013904223);
        if (check_values(value, overlap, store, volatile_store, flags, (int8_t)(state >> 24)))
        {
            return 3;
        }
        comparisons += 6;
    }
    printf("Mask update comparisons: %llu\n", comparisons);
    return 0;
}

int main(void)
{
    return verify_functions(mba_mask_value, mba_mask_overlap, mba_mask_store,
                            mba_mask_volatile_store);
}
