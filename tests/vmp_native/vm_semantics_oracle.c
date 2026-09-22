#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
struct capture
{
    uint64_t encoded, key, delta, table, vip_before, base_before, sp_before;
    uint64_t vip_after, value_after, key_after, base_after, sp_after, flags, stack_word, reached;
};
_Static_assert(offsetof(struct capture, reached) == 112, "assembly capture layout");
extern void vm_semantic_run(struct capture *, uint64_t, uint64_t);
extern const char vm_semantic_capture[];
static uint64_t table[256];
static uint64_t seed = UINT64_C(0xd1b54a32d192ed03);
static uint64_t random_word(void)
{
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    return seed;
}
static void run(unsigned scenario, uint32_t encoded, uint64_t key)
{
    const uint32_t x = encoded ^ (uint32_t)key;
    const uint32_t decoded = ((x << 3) | (x >> 29)) + 7;
    struct capture out = {0};
    out.encoded = encoded;
    out.key = key;
    out.delta =
        (decoded & UINT32_C(0x80000000)) ? (uint64_t)decoded - UINT64_C(0x100000000) : decoded;
    out.table = (uint64_t)(uintptr_t)table;
    vm_semantic_run(&out, 0, scenario);
    printf("%x %x %llx", scenario, encoded, (unsigned long long)key);
    uint64_t words[11];
    memcpy(words, &out.vip_before, sizeof(words));
    for (unsigned i = 0; i < 11; ++i)
        printf(" %llx", (unsigned long long)words[i]);
    putchar('\n');
}
int main(void)
{
    for (unsigned i = 0; i < 256; ++i)
        table[i] = (uint64_t)(uintptr_t)vm_semantic_capture;
    const uint32_t values[] = {0, 1, 127, 128, 255, 0x7fffffff, 0x80000000, 0xffffffff};
    const uint64_t keys[] = {0, 1, 255, UINT64_C(0xffffffff), UINT64_C(0xfedcba9812345678)};
    for (unsigned scenario = 0; scenario < 4; ++scenario)
    {
        for (unsigned i = 0; i < 8; ++i)
            for (unsigned j = 0; j < 5; ++j)
                run(scenario, values[i], keys[j]);
        for (unsigned i = 0; i < 64; ++i)
        {
            uint32_t value = (uint32_t)random_word();
            run(scenario, value, random_word());
        }
    }
    return 0;
}
