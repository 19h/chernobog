#include <stdint.h>
#include <stdio.h>

extern int pl_or_chain(int value);
extern int pl_xor_chain(int value);
extern int pl_or_flags(int value);
extern int pl_or_unknown(int value);
extern int pl_xor_unknown(int value);

int main(void)
{
    for (int value = 0; value < 256; ++value)
    {
        const int expected_bit = value & 1;
        if (pl_or_chain(value) != 1 || pl_xor_chain(value) != 1 || pl_or_flags(value) != 1 ||
            pl_or_unknown(value) != expected_bit || pl_xor_unknown(value) != expected_bit)
        {
            fprintf(stderr, "partial logic mismatch at %d\n", value);
            return 1;
        }
    }
    puts("partial logic native PASS: 1280 results");
    return 0;
}
