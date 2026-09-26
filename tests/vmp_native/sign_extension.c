#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

struct result
{
    uintptr_t accumulator, high, before, after;
};
extern void sx_execute(uint64_t, uint64_t, unsigned, struct result *);
extern int sx_cbw(void), sx_cwde(void), sx_cwd(void), sx_cdq(void), sx_cwd_partial(int),
    sx_cdq_unknown(int), sx_flags(void), sx_stack(void);
#if UINTPTR_MAX == UINT64_MAX
extern int sx_cdqe(void), sx_cqo(void);
#endif

static uintptr_t extended(uint64_t input, unsigned bits)
{
    const uint64_t range = UINT64_C(1) << bits;
    const int64_t signed_value = input & (range / 2) ? -(int64_t)(range - (input & (range - 1)))
                                                     : (int64_t)(input & (range - 1));
    return (uintptr_t)signed_value;
}

int main(void)
{
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
    const uintptr_t sentinel = (uintptr_t)UINT64_C(0x123456789abcdef0);
    unsigned checks = 0;
    for (unsigned operation = 0; operation < (sizeof(uintptr_t) == 8 ? 6u : 4u); ++operation)
        for (unsigned profile = 0; profile < 64; ++profile)
            for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
            {
                struct result actual;
                const unsigned flags = (profile & 1) | ((profile & 2) << 1) | ((profile & 4) << 2) |
                                       ((profile & 8) << 3) | ((profile & 16) << 3) |
                                       ((profile & 32) << 6);
                sx_execute(values[i], sentinel, (flags << 8) | operation, &actual);
                uintptr_t accumulator = (uintptr_t)values[i], high = sentinel;
                switch (operation)
                {
                case 0:
                    accumulator =
                        (accumulator & ~(uintptr_t)UINT16_MAX) | (uint16_t)extended(values[i], 8);
                    break;
                case 1:
                    accumulator = (uint32_t)extended(values[i], 16);
                    break;
                case 2:
                    high = (high & ~(uintptr_t)UINT16_MAX) |
                           (values[i] & UINT64_C(0x8000) ? UINT16_MAX : 0);
                    break;
                case 3:
                    high = values[i] & UINT64_C(0x80000000) ? UINT32_MAX : 0;
                    break;
                case 4:
                    accumulator = extended(values[i], 32);
                    break;
                case 5:
                    high = values[i] & UINT64_C(0x8000000000000000) ? UINTPTR_MAX : 0;
                    break;
                }
                ++checks;
                if (actual.accumulator != accumulator || actual.high != high ||
                    (actual.before & 0x8d5) != flags || actual.before != actual.after)
                {
                    fprintf(stderr, "oracle mismatch operation=%u input=%" PRIx64 "\n", operation,
                            values[i]);
                    return 1;
                }
            }
    for (int input = -256; input <= 255; ++input)
    {
        ++checks;
        if (sx_cbw() != 1 || sx_cwde() != 1 || sx_cwd() != 1 || sx_cdq() != 1 ||
            sx_cwd_partial(input) != 1 || sx_cdq_unknown(input) != (input < 0) || sx_flags() != 1 ||
            sx_stack() != 7)
            return 2;
#if UINTPTR_MAX == UINT64_MAX
        if (sx_cdqe() != 1 || sx_cqo() != 1)
            return 3;
#endif
    }
    printf("{\"passed\":true,\"checks\":%u,\"oracle_cases\":%u,\"static_inputs\":512}\n", checks,
           sizeof(uintptr_t) == 8 ? 5760u : 3840u);
    return 0;
}
