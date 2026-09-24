#include <stdint.h>
#include <stdlib.h>
#include <string.h>

volatile uint64_t native_multisite_key = UINT64_C(0x5a5a5a5a5a5a5a5a);
volatile const uint64_t native_multisite_oracle_key = UINT64_C(0x5a5a5a5a5a5a5a5a);
#ifndef NATIVE_MULTISITE_ORACLE
#define NATIVE_MULTISITE_ORACLE UINT64_C(0x5a7b2e3f28393f29)
#endif

__attribute__((noinline)) int native_multisite_strings(unsigned mode)
{
    static const unsigned char forward[8] = {3, 1, 6, 0, 7, 2, 5, 4};
    static const unsigned char reverse[8] = {7, 6, 5, 4, 3, 2, 1, 0};
    const unsigned char *order = (mode & 1) != 0 ? reverse : forward;
    uint64_t *buffer = malloc(32);
    if (buffer == NULL)
        return 2;
    *buffer = UINT64_C(0x5a7b2e3f28393f29) ^ native_multisite_key;
    uint64_t observed = 0;
    for (unsigned index = 0; index < 8; ++index)
    {
        const unsigned offset = order[index];
        const unsigned char *pointer = (const unsigned char *)buffer + offset;
        unsigned char byte;
        if ((offset & 1) != 0)
        {
            __atomic_signal_fence(__ATOMIC_SEQ_CST);
            byte = *(const volatile unsigned char *)pointer;
            __atomic_signal_fence(__ATOMIC_SEQ_CST);
        }
        else
            byte = *(const volatile unsigned char *)pointer;
        observed |= (uint64_t)byte << (8 * offset);
    }
    memset(buffer, 0, 32);
    free(buffer);
    return (observed ^ native_multisite_oracle_key) != NATIVE_MULTISITE_ORACLE;
}

int main(void) { return native_multisite_strings(0) | native_multisite_strings(1); }
