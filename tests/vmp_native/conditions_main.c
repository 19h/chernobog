/* Independent execution evidence for the generated instruction fixtures. */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#define CONDITIONS(X) \
 X(vc_o) X(vc_no) X(vc_b) X(vc_ae) X(vc_e) X(vc_ne) X(vc_be) X(vc_a) \
 X(vc_s) X(vc_ns) X(vc_p) X(vc_np) X(vc_l) X(vc_ge) X(vc_le) X(vc_g) \
 X(vc_cm_o) X(vc_cm_no) X(vc_cm_b) X(vc_cm_ae) X(vc_cm_e) X(vc_cm_ne) \
 X(vc_cm_be) X(vc_cm_a) X(vc_cm_s) X(vc_cm_ns) X(vc_cm_p) X(vc_cm_np) \
 X(vc_cm_l) X(vc_cm_ge) X(vc_cm_le) X(vc_cm_g) \
 X(vc_ah_true) X(vc_ah_false) X(vc_mem_true) X(vc_mem_false) \
 X(vc_cm16_true) X(vc_cm16_false) X(vc_cm32_true) X(vc_cm32_false) \
 X(vc_cm_mem_true) X(vc_cm_mem_false) X(vc_cm_mem16_true) X(vc_cm_mem16_false) \
 X(vc_cm_mem32_true) X(vc_cm_mem32_false) X(vc_cm_order_true) X(vc_cm_order_false) \
 X(vc_unknown) X(vc_depth) X(vc_alternate)
typedef uintptr_t word_t;
typedef word_t (*function_t)(word_t, word_t, uint64_t *);
#define DECLARE(n) extern word_t n(word_t, word_t, uint64_t *);
CONDITIONS(DECLARE)
#define ROW(n) {#n, n},
static const struct { const char *name; function_t f; } cases[] = {CONDITIONS(ROW)};
extern word_t vc_invoke(function_t, word_t, word_t, uint64_t *, uint64_t *);

int main(void)
{
    static const uint64_t edges[] = {0, UINT64_MAX, UINT64_C(0x8000000000000000),
        UINT64_C(0xFFFFFFFF), UINT64_C(0x100000000), 1, UINT64_C(0xFF00), UINT64_C(0xFFFF)};
    for (unsigned seed = 0; seed < 128; ++seed)
    {
        uint64_t destination = UINT64_C(0xFEDCBA9876543210) ^
            (UINT64_C(0x9E3779B97F4A7C15) * seed);
        uint64_t source = seed == 0 ? 0 : UINT64_C(0x1020304050607080) ^
            (UINT64_C(0xD1342543DE82EF95) * seed);
        if (seed < sizeof(edges) / sizeof(edges[0]))
        {
            destination = edges[seed];
            source = edges[sizeof(edges) / sizeof(edges[0]) - 1 - seed];
        }
        destination = (word_t)destination;
        source = (word_t)source;
        for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        {
            uint64_t before = UINT64_C(0x11223344556677AA) ^ (uint64_t)seed << 32;
            uint64_t memory = before, flags = 0;
            uint64_t result = vc_invoke(cases[i].f, destination, source, &memory, &flags);
            printf("{\"name\":\"%s\",\"seed\":%u,\"destination\":%" PRIu64
                   ",\"source\":%" PRIu64 ",\"memory_before\":%" PRIu64
                   ",\"result\":%" PRIu64 ",\"memory_after\":%" PRIu64
                   ",\"flags\":%" PRIu64 "}\n",
                   cases[i].name, seed, destination, source, before, result, memory,
                   flags & UINT64_C(0x8C5));
        }
    }
    return 0;
}
