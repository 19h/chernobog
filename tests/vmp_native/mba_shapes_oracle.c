#include <stdint.h>
#include <stdio.h>

extern uint32_t mba_demorgan32(uint32_t, uint32_t);
extern uint32_t mba_carry32(uint32_t, uint32_t);
extern uint64_t mba_carry64(uint64_t, uint64_t);
extern uint32_t mba_stack32(uint32_t, uint32_t);
extern uint32_t mba_truncate8(uint32_t, uint32_t);
extern uint32_t mba_extend_not(uint32_t);
extern uint32_t mba_not_extend(uint32_t);
extern uint32_t mba_alias_write(uint32_t *, uint32_t);
extern uint32_t mba_alias_partial(uint32_t *, uint32_t);
extern uint32_t mba_order32(uint32_t, uint32_t, uint32_t);

static uint64_t next(uint64_t *state)
{
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    return *state;
}

int main(void)
{
    const uint64_t seeds[] = {UINT64_C(0x390fe14891), UINT64_C(0x9827136ab5)};
    unsigned comparisons = 0;
    for (unsigned seed = 0; seed < 2; ++seed)
    {
        uint64_t state = seeds[seed];
        for (unsigned trial = 0; trial < 256; ++trial)
        {
            const uint64_t x = trial == 0 ? 0 : trial == 1 ? UINT64_MAX : next(&state);
            const uint64_t y = trial == 0 ? UINT64_MAX : trial == 1 ? 1 : next(&state);
            const uint32_t a = (uint32_t)x, b = (uint32_t)y;
            if (mba_demorgan32(a, b) != (a & b))
                return 1;
            if (mba_carry32(a, b) != a + b)
                return 2;
            if (mba_carry64(x, y) != x + y)
                return 3;
            if (mba_stack32(a, b) != a + b)
                return 4;
            if (mba_truncate8(a, b) != (uint8_t)(a + b))
                return 5;
            if (mba_extend_not(a) != (uint8_t)~a)
                return 6;
            if (mba_not_extend(a) != ~(uint32_t)(uint8_t)a)
                return 7;
            uint32_t cell = a;
            if (mba_alias_write(&cell, b) != (a ^ b) || cell != b)
                return 8;
            cell = a;
            const uint32_t written = (a & UINT32_C(0xffff0000)) | (b & 65535);
            if (mba_alias_partial(&cell, b) != (a ^ written) || cell != written)
                return 9;
            if (mba_order32(a, b, (uint32_t)next(&state)) != a + b)
                return 10;
            comparisons += 10;
        }
    }
    for (unsigned x = 0; x < 256; ++x)
        for (unsigned y = 0; y < 256; ++y)
        {
            if (mba_truncate8(x, y) != (uint8_t)(x + y))
                return 11;
            ++comparisons;
        }
    printf("native MBA oracle passed; comparisons=%u; seeds=0x390fe14891,0x9827136ab5\n",
           comparisons);
    return 0;
}
