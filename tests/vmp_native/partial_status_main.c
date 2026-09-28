#include <stdio.h>

extern int ps_or_nonzero(int value);
extern int ps_or_sign(int value);
extern int ps_or_parity(int value);
extern int ps_xor_sign(int value);
extern int ps_and_sign(int value);
extern int ps_test_zero(int value);
extern int ps_test_nonzero(int value);
extern int ps_test_same_sign(int value);
extern int ps_or_unknown(int value);
extern int ps_test_unknown(int value);

int main(void)
{
    for (int value = 0; value < 256; ++value)
    {
        const int bit = value & 1;
        if (ps_or_nonzero(value) != 1 || ps_or_sign(value) != 1 || ps_or_parity(value) != 1 ||
            ps_xor_sign(value) != 1 || ps_and_sign(value) != 1 || ps_test_zero(value) != 1 ||
            ps_test_nonzero(value) != 1 || ps_test_same_sign(value) != 1 ||
            ps_or_unknown(value) != bit || ps_test_unknown(value) != bit)
        {
            fprintf(stderr, "partial status mismatch at %d\n", value);
            return 1;
        }
    }
    puts("partial status native PASS: 2560 results");
    return 0;
}
