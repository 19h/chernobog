#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#ifdef RECOVERED
#include "recovered.c"
#else
__attribute__((noinline)) uint32_t threaded_select(const int32_t *values)
{
    const uint32_t left = values[0] > 1 ? (uint32_t)values[0] : 1;
    const uint32_t right = values[1] > 1 ? (uint32_t)values[1] : 1;
    const uint32_t product = (right + 3) * left;
    return (product > 11 ? product : 11) + 1;
}
#endif

int main(void)
{
    const int32_t inputs[] = {INT32_MIN, -1, 0, 1, 2, 3, 11, INT32_MAX};
    for (size_t left = 0; left < sizeof(inputs) / sizeof(inputs[0]); ++left)
    {
        for (size_t right = 0; right < sizeof(inputs) / sizeof(inputs[0]); ++right)
        {
            const int32_t values[] = {inputs[left], inputs[right]};
            printf("%08" PRIx32 "\n", threaded_select(values));
        }
    }
    return 0;
}
