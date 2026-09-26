#include <stdio.h>

extern int jc_register(int), jc_memory(int), jc_stack(int), jc_dynamic(int), jc_cap(int);

int main(void)
{
    unsigned checks = 0;
    for (int input = -256; input <= 255; ++input)
    {
        if (jc_register(input) != 7 || jc_memory(input) != 7 || jc_stack(input) != 7 ||
            jc_dynamic(input) != (input ? 8 : 7) || jc_cap(input) != 7)
            return 1;
        checks += 5;
    }
    printf("{\"passed\":true,\"checks\":%u}\n", checks);
    return 0;
}
