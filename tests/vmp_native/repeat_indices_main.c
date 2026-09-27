#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern unsigned char repeat_index_source[64], repeat_index_dest[64];
#define ROUTINE(name) extern unsigned name(uint64_t, const unsigned char *);
ROUTINE(repeat_movsb_di)
ROUTINE(repeat_movsw_di)
ROUTINE(repeat_movsd_di)
ROUTINE(repeat_movsq_di)
ROUTINE(repeat_stosb_di)
ROUTINE(repeat_stosw_di)
ROUTINE(repeat_stosd_di)
ROUTINE(repeat_stosq_di)
ROUTINE(repeat_movsb_si)
ROUTINE(repeat_movsq_si)
ROUTINE(repeat_unknown_df_masked)
ROUTINE(repeat_partial_count_masked)
ROUTINE(repeat_both_masked)
ROUTINE(repeat_movs_si_masked)
ROUTINE(repeat_unknown_df_unmasked)
ROUTINE(repeat_partial_count_unmasked)
ROUTINE(repeat_count_nine)
ROUTINE(repeat_unknown_source)
ROUTINE(repeat_stos_preserves_si)
ROUTINE(repeat_zero_index)

static unsigned invoke(unsigned (*fn)(uint64_t, const unsigned char *), uint64_t input,
                       unsigned reverse)
{
    unsigned result;
    const unsigned char *source = repeat_index_source + 24;
    __asm__ volatile("test %[reverse], %[reverse]\n\t"
                     "jz 1f\n\tstd\n\tjmp 2f\n1:\tcld\n2:\tcall *%[fn]\n\tcld"
                     : "=a"(result), "+D"(input), "+S"(source)
                     : [reverse] "r"(reverse), [fn] "r"(fn)
                     : "rcx", "rdx", "r8", "r9", "r10", "r11", "cc", "memory");
    return result;
}

int main(void)
{
    struct fixture
    {
        unsigned (*fn)(uint64_t, const unsigned char *);
        unsigned bytes, move, direction, count, target;
        /* direction 2 inherits DF; count 10 selects argument & 3. */
    } fixtures[] = {
        {repeat_movsb_di, 1, 1, 0, 2, 1},
        {repeat_movsw_di, 2, 1, 1, 2, 1},
        {repeat_movsd_di, 4, 1, 0, 2, 1},
        {repeat_movsq_di, 8, 1, 1, 2, 1},
        {repeat_stosb_di, 1, 0, 1, 2, 1},
        {repeat_stosw_di, 2, 0, 0, 2, 1},
        {repeat_stosd_di, 4, 0, 1, 2, 1},
        {repeat_stosq_di, 8, 0, 0, 2, 1},
        {repeat_movsb_si, 1, 1, 0, 2, 1},
        {repeat_movsq_si, 8, 1, 1, 2, 1},
        {repeat_unknown_df_masked, 1, 0, 2, 2, 1},
        {repeat_partial_count_masked, 1, 0, 0, 10, 1},
        {repeat_both_masked, 1, 0, 2, 10, 1},
        {repeat_movs_si_masked, 1, 1, 2, 10, 1},
        {repeat_unknown_df_unmasked, 1, 0, 2, 2, 0},
        {repeat_partial_count_unmasked, 1, 0, 0, 10, 0},
        {repeat_count_nine, 1, 0, 0, 9, 0},
        {repeat_unknown_source, 1, 1, 0, 2, 0},
        {repeat_stos_preserves_si, 8, 0, 1, 2, 0},
        {repeat_zero_index, 8, 1, 2, 0, 0},
    };
    unsigned cases = 0, failures = 0;
    for (unsigned repetition = 0; repetition < 16; ++repetition)
        for (unsigned incoming = 0; incoming < 2; ++incoming)
            for (unsigned argument = 0; argument < 8; ++argument)
                for (unsigned f = 0; f < sizeof(fixtures) / sizeof(fixtures[0]); ++f)
                {
                    const struct fixture *test = &fixtures[f];
                    const unsigned reverse = test->direction == 2 ? incoming : test->direction;
                    const unsigned count = test->count == 10 ? argument & 3 : test->count;
                    unsigned char source[64], expected[64];
                    for (unsigned i = 0; i < 64; ++i)
                        source[i] = (unsigned char)((i & 7) + 1);
                    memset(expected, 0x99, sizeof(expected));
                    for (unsigned i = 0; i < count; ++i)
                    {
                        const unsigned index =
                            reverse ? 24 - i * test->bytes : 24 + i * test->bytes;
                        for (unsigned j = 0; j < test->bytes; ++j)
                            expected[index + j] = test->move ? source[index + j] : 0x99;
                    }
                    const unsigned result = invoke(test->fn, argument, incoming);
                    const unsigned truth = test->target ? 73
                                           : f == 14    ? !reverse
                                           : f == 15    ? count == 2
                                                        : 1;
                    const unsigned failed = result != truth ||
                                            memcmp(repeat_index_source, source, 64) ||
                                            memcmp(repeat_index_dest, expected, 64);
                    if (failed)
                        fprintf(stderr,
                                "fixture=%u argument=%u incoming=%u result=%u expected=%u\n", f,
                                argument, incoming, result, truth);
                    failures += failed;
                    ++cases;
                }
    printf("{\"passed\":%s,\"cases\":%u,\"failures\":%u}\n", failures ? "false" : "true", cases,
           failures);
    return failures ? 1 : 0;
}
