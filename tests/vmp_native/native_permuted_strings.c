#include <stdint.h>
#include <stdlib.h>
#include <string.h>

volatile uint64_t native_permuted_key = UINT64_C(0x5a5a5a5a5a5a5a5a);
volatile const uint64_t native_permuted_oracle_key = UINT64_C(0x5a5a5a5a5a5a5a5a);
#ifndef NATIVE_PERMUTED_ORACLE
#define NATIVE_PERMUTED_ORACLE UINT64_C(0x5a7b2e3f28393f29)
#endif

__attribute__((noinline)) int native_permuted_strings(void)
{
    static const unsigned char order[8] = {3, 1, 6, 0, 7, 2, 5, 4};
    uint64_t *buffer = malloc(32);
    if (buffer == NULL)
        return 2;
    *buffer = UINT64_C(0x5a7b2e3f28393f29) ^ native_permuted_key;
    uint64_t observed = 0;
    for (unsigned index = 0; index < 8; ++index)
    {
        const unsigned offset = order[index];
        observed |= (uint64_t)((volatile unsigned char *)buffer)[offset] << (8 * offset);
#ifdef NATIVE_PERMUTED_DISJOINT_WRITE
        ((volatile unsigned char *)buffer)[24] = (unsigned char)index;
#endif
    }
    memset(buffer, 0, 32);
    free(buffer);
    return (observed ^ native_permuted_oracle_key) != NATIVE_PERMUTED_ORACLE;
}

int main(void) { return native_permuted_strings(); }
