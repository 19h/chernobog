#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef uint32_t (*Transform)(uint32_t, uint32_t, uint32_t *);
extern uint32_t corpus_transform(uint32_t, uint32_t, uint32_t *);
extern uint32_t corpus_branch(uint32_t, uint32_t, uint32_t *);
struct Observation
{
    uint64_t result, flags;
    int64_t stack_delta;
};
extern void corpus_capture(Transform, uint32_t, uint32_t, uint32_t *, struct Observation *);
_Static_assert(offsetof(struct Observation, flags) == 8, "flags offset");
_Static_assert(offsetof(struct Observation, stack_delta) == 16, "stack offset");

static uint32_t next(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return *state = x;
}

static void sample(unsigned id, uint32_t x, uint32_t y, uint32_t initial)
{
    Transform functions[] = {corpus_transform, corpus_branch};
    for (unsigned function = 0; function < 2; ++function)
    {
        uint32_t memory[] = {UINT32_C(0xA5A5A5A5), initial, UINT32_C(0x5A5A5A5A)};
        struct Observation observed = {0, 0, INT64_MAX};
        corpus_capture(functions[function], x, y, &memory[1], &observed);
        printf("%u %u %08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %016" PRIx64 " %04" PRIx64
               " %" PRId64 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32 "\n",
               id, function, x, y, initial, observed.result, observed.flags & UINT64_C(0x8D5),
               observed.stack_delta, memory[0], memory[1], memory[2]);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    char *end = 0;
    unsigned long parsed = strtoul(argv[1], &end, 0);
    if (!end || *end || !parsed || parsed > UINT32_MAX)
        return 2;
    uint32_t seed = (uint32_t)parsed;
    const uint32_t corners[] = {
        0, 1, UINT32_C(0x7FFFFFFF), UINT32_C(0x80000000), UINT32_C(0xFFFFFFFE), UINT32_MAX};
    unsigned id = 0;
    for (unsigned i = 0; i < 6; ++i)
        for (unsigned j = 0; j < 6; ++j)
            for (unsigned k = 0; k < 6; ++k)
                sample(id++, corners[i], corners[j], corners[k]);
    for (unsigned i = 0; i < 64; ++i)
    {
        const uint32_t x = next(&seed), y = next(&seed), memory = next(&seed);
        sample(id++, x, y, memory);
    }
    return 0;
}
