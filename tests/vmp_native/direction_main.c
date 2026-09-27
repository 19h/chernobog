#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern unsigned char direction_source[16], direction_dest[16];
#define ROUTINE(name) extern unsigned name(uint64_t);
ROUTINE(direction_forward)
ROUTINE(direction_reverse)
ROUTINE(direction_saved_forward)
ROUTINE(direction_saved_reverse)
ROUTINE(direction_literal_reverse)
ROUTINE(direction_unknown_pop)
ROUTINE(direction_unknown)
ROUTINE(direction_prefixed)
ROUTINE(direction_join_equal)
ROUTINE(direction_join_conflict)
ROUTINE(direction_stos_forward)
ROUTINE(direction_stos_reverse)

/* Establish the incoming DF outside the selected routine's static root. */
static unsigned invoke(unsigned (*fn)(uint64_t), uint64_t input, unsigned reverse)
{
    unsigned result;
    __asm__ volatile("test %[reverse], %[reverse]\n\t"
                     "jz 1f\n\tstd\n\tjmp 2f\n1:\tcld\n2:\tcall *%[fn]\n\tcld"
                     : "=a"(result), "+D"(input)
                     : [reverse] "r"(reverse), [fn] "r"(fn)
                     : "rcx", "rdx", "rsi", "r8", "r9", "r10", "r11", "cc", "memory");
    return result;
}

int main(void)
{
    struct fixture
    {
        unsigned (*fn)(uint64_t);
        unsigned mode; /* 0 forward, 1 reverse, 2 incoming, 3 argument, 4 branch */
        unsigned stos;
    } fixtures[] = {{direction_forward, 0, 0},         {direction_reverse, 1, 0},
                    {direction_saved_forward, 0, 0},   {direction_saved_reverse, 1, 0},
                    {direction_literal_reverse, 1, 0}, {direction_unknown_pop, 3, 0},
                    {direction_unknown, 2, 0},         {direction_prefixed, 0, 0},
                    {direction_join_equal, 0, 0},      {direction_join_conflict, 4, 0},
                    {direction_stos_forward, 0, 1},    {direction_stos_reverse, 1, 1}};
    unsigned cases = 0, failures = 0;
    for (unsigned repetition = 0; repetition < 64; ++repetition)
        for (unsigned incoming = 0; incoming < 2; ++incoming)
            for (unsigned argument = 0; argument < 2; ++argument)
                for (unsigned f = 0; f < sizeof(fixtures) / sizeof(fixtures[0]); ++f)
                {
                    const struct fixture *test = &fixtures[f];
                    const uint64_t input = test->mode == 3 ? (uint64_t)argument << 10 : argument;
                    const unsigned reverse = test->mode == 2   ? incoming
                                             : test->mode == 3 ? argument
                                             : test->mode == 4 ? !argument
                                                               : test->mode;
                    unsigned char source[16], expected[16];
                    for (unsigned i = 0; i < 16; ++i)
                        source[i] = (unsigned char)((i < 8 ? 0x11 : 0x19) + i);
                    memset(expected, 0x99, sizeof(expected));
                    for (unsigned i = 0; i < 2; ++i)
                    {
                        unsigned index = reverse ? 8 - i : 8 + i;
                        expected[index] = test->stos ? 0x5a : source[index];
                    }
                    const unsigned result = invoke(test->fn, input, incoming);
                    const unsigned truth = expected[9] == (test->stos ? 0x5a : 0x22);
                    failures += result != truth || memcmp(direction_source, source, 16) ||
                                memcmp(direction_dest, expected, 16);
                    ++cases;
                }
    printf("{\"passed\":%s,\"cases\":%u,\"failures\":%u}\n", failures ? "false" : "true", cases,
           failures);
    return failures ? 1 : 0;
}
