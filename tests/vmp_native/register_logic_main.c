#include <stdio.h>

extern int rl_and_zero(int value);
extern int rl_or_nonzero(int value);
extern int rl_xor_sign(int value);
extern int rl_test_zero(int value);
extern int rl_test_nonzero(int value);
extern int rl_and_chain(int value);
extern int rl_or_chain(int value);
extern int rl_xor_chain(int value);
extern int rl_self_and(int value);
extern int rl_self_xor(int value);
extern int rl_test_unknown(int value);
extern int rl_or_unknown(int value);
extern int rl_two_and(int left, int right);
extern int rl_two_or(int left, int right);
extern int rl_two_xor(int left, int right);
extern int rl_two_test(int left, int right);
extern int rl_two_test_unknown(int left, int right);

int main(void)
{
    for (int value = 0; value < 256; ++value)
    {
        const int bit = value & 1;
        if (rl_and_zero(value) != 1 || rl_or_nonzero(value) != 1 || rl_xor_sign(value) != 1 ||
            rl_test_zero(value) != 1 || rl_test_nonzero(value) != 1 || rl_and_chain(value) != 1 ||
            rl_or_chain(value) != 1 || rl_xor_chain(value) != 1 || rl_self_and(value) != 1 ||
            rl_self_xor(value) != 1 || rl_test_unknown(value) != bit || rl_or_unknown(value) != bit)
        {
            fprintf(stderr, "register logic mismatch at %d\n", value);
            return 1;
        }
    }
    for (int left = 0; left < 256; ++left)
        for (int right = 0; right < 256; ++right)
            if (rl_two_and(left, right) != 1 || rl_two_or(left, right) != 1 ||
                rl_two_xor(left, right) != 1 || rl_two_test(left, right) != 1 ||
                rl_two_test_unknown(left, right) != ((left & 1) && (right & 1)))
            {
                fprintf(stderr, "two-register logic mismatch at %d,%d\n", left, right);
                return 1;
            }
    puts("register logic native PASS: 330752 results");
    return 0;
}
