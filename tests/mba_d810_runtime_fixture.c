#include <stdint.h>

#ifdef _MSC_VER
#define D810_FN __declspec(dllexport) __declspec(noinline)
#else
#define D810_FN __attribute__((visibility("default"), noinline))
#endif

volatile uint32_t d810_effects;
volatile uint32_t d810_read_value;

D810_FN uint32_t test_chained_add(uint32_t *p)
{
    return p[2] + p[0] + 23u - (0u - 17u - (~p[2] + p[1] - p[0] + 12u) - p[1]);
}
// Keep ordinary-data tests independent of compiler literal-pool reads, which
// the native effect inventory deliberately refuses when absent from ctree.
#define D810_WORD(name, high, low)                                                                 \
    uint32_t name = high;                                                                          \
    name <<= 16;                                                                                   \
    name |= low

D810_FN uint32_t test_cst_simplification(uint32_t *p)
{
    D810_WORD(c1, 0x222Eu, 0x69C2u);
    D810_WORD(mask2, 0x5021u, 0x1120u);
    D810_WORD(c2, 0x5029u, 0x5930u);
    D810_WORD(c3, 0x8302u, 0x0001u);
    D810_WORD(mask3, 0x1050u, 0x0855u);
    D810_WORD(c4, 0x0200u, 0x9500u);
    D810_WORD(c5, 0x0520u, 0x4000u);
    D810_WORD(c6, 0x1548u, 0x2637u);
    const uint32_t v5 = ((p[0] & 1u) | c1) - ((p[0] & 1u) | 2u);
    p[1] = v5;
    const uint32_t v4 = ((p[1] & mask2) ^ c2) + ((p[1] & mask2) | c3);
    p[2] = v4;
    const uint32_t v3 = (((p[2] & mask3) | c4) + ((~p[2] & mask3) | c5)) ^ c6;
    p[3] = v3;
    const uint32_t v2 = (((p[3] + 4u - (v3 | 4u)) & 0x7FFFFCu) >> 2) | 0xA29u;
    p[4] = v2;
    return v2 + v3 + v4 + v5;
}
D810_FN uint64_t abc_f6_add_dispatch(int32_t input)
{
    uint32_t state = 1010001, value = 0;
    for (;;)
    {
        switch (state)
        {
        case 1010001:
            value = (uint32_t)input;
            ++state;
            continue;
        case 1010002:
            value *= 2u;
            ++state;
            continue;
        case 1010003:
            state = (int32_t)value <= 50 ? 1010020u : 1010010u;
            continue;
        case 1010010:
            return value;
        case 1010020:
            return 0u - value;
        default:
            ++d810_effects;
            return 0;
        }
    }
}
D810_FN uint32_t nested_simple(uint32_t input)
{
    uint32_t outer = 0, inner = 0;
    for (;;)
    {
        switch (outer)
        {
        case 0:
            input += 100u;
            outer = 1;
            inner = 0;
            break;
        case 1:
            if (inner == 0)
            {
                input *= 2u;
                inner = 1;
            }
            else if (inner == 1)
            {
                input -= 50u;
                inner = 2;
            }
            else
                outer = 2;
            break;
        case 2:
            input = (uint32_t)((int32_t)input / 2);
            outer = 3;
            break;
        case 3:
            return input;
        }
    }
}
D810_FN uint32_t single_iteration_simple(uint32_t input)
{
    for (uint32_t state = 4660; state == 4660; state = 22136)
        input += 10u;
    return input;
}
D810_FN uint32_t d810_read(void)
{
    ++d810_effects;
    return d810_read_value;
}
D810_FN uint64_t d810_rotate(uint64_t value, uint32_t count)
{
    return (value << count) | (value >> (64u - count));
}
D810_FN uint32_t while_switch_flattened(void)
{
    uint32_t state = 0, read = 0, result = 0;
    int32_t narrow = 0;
    uint64_t wide = 0;
    for (;;)
    {
        switch (state)
        {
        case 0:
            read = d810_read();
            state = 1;
            break;
        case 1:
            narrow = -1379894089;
            state = 2;
            break;
        case 2:
            wide = d810_rotate(((uint64_t)(int64_t)narrow ^ UINT64_C(0xCD455C2CD812A432)) -
                                   UINT64_C(0x789F447F89C06931),
                               21) +
                   UINT64_C(0x507AF58A6E5A51E3);
            state = 3;
            break;
        case 3:
            result = (uint32_t)d810_rotate(wide - UINT64_C(0xD3ADD64F8DFDFE0), 24);
            state = 4;
            break;
        case 4:
            return read == result;
        }
    }
}
D810_FN uint32_t d810_control_dynamic(uint32_t input)
{
    uint32_t value = 0;
    while (input--)
        value += input ^ 3u;
    return value;
}
D810_FN uint32_t d810_control_switch(uint32_t input)
{
    switch (input)
    {
    case 1:
        return 17;
    case 3:
        return 29;
    default:
        return 31;
    }
}
D810_FN uint32_t d810_control_volatile(uint32_t input)
{
    volatile uint32_t state = 0;
    while (state == 0)
    {
        input += 1;
        state = 1;
    }
    return input;
}
D810_FN uint32_t d810_control_cycle(uint32_t input)
{
    uint32_t state = 0;
    for (;;)
    {
        ++d810_effects;
        state ^= 1u;
        input += state;
    }
}
D810_FN void d810_mutate(uint32_t *state) { *state = d810_read_value; }
D810_FN uint32_t d810_control_escape(uint32_t input)
{
    uint32_t state = 0;
    while (state == 0)
    {
        d810_mutate(&state);
        input++;
    }
    return input;
}
int main(void)
{
    uint32_t p[5] = {1, 2, 3, 4, 5};
    if (test_chained_add(p) != 55u || test_cst_simplification(p) != 0xF792C87Cu ||
        p[1] != 573467072u || p[2] != 3542833457u || p[3] != 37288802u || p[4] != 2601u ||
        abc_f6_add_dispatch(30) != 60u || abc_f6_add_dispatch(10) != 0xFFFFFFECu ||
        nested_simple(7) != 82u || single_iteration_simple(7) != 17u)
        return 1;
    const uint64_t wide =
        d810_rotate(((uint64_t)(int64_t)(int32_t)0xADC07CB7u ^ UINT64_C(0xCD455C2CD812A432)) -
                        UINT64_C(0x789F447F89C06931),
                    21) +
        UINT64_C(0x507AF58A6E5A51E3);
    d810_read_value = (uint32_t)d810_rotate(wide - UINT64_C(0xD3ADD64F8DFDFE0), 24);
    d810_effects = 0;
    return while_switch_flattened() != 1 || d810_effects != 1;
}
