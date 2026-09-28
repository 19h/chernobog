#include <stdio.h>

extern int rep_lods_zero_target(int input);

int main(void)
{
    for (int input = 0; input < 256; ++input)
        if (rep_lods_zero_target(input) != 73)
            return 1;
    puts("{\"passed\":true,\"checks\":256}");
    return 0;
}
