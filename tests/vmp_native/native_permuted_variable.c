#include <stdint.h>
#include <stdlib.h>
#include <string.h>

volatile uint64_t native_permuted_variable_key = UINT64_C(0x5a5a5a5a5a5a5a5a);
volatile const uint64_t native_permuted_variable_oracle_key = UINT64_C(0x5a5a5a5a5a5a5a5a);
#ifndef NATIVE_PERMUTED_VARIABLE_ORACLE
#define NATIVE_PERMUTED_VARIABLE_ORACLE UINT64_C(0x5a7b2e3f28393f29)
#endif

__attribute__((noinline)) int native_permuted_variable(unsigned mode)
{
    static const unsigned char forward[8] = {3, 1, 6, 0, 7, 2, 5, 4};
    static const unsigned char reverse[8] = {7, 6, 5, 4, 3, 2, 1, 0};
    const unsigned char *order = (mode & 1) != 0 ? reverse : forward;
    uint64_t *buffer = malloc(32);
    if (buffer == NULL)
        return 2;
    *buffer = UINT64_C(0x5a7b2e3f28393f29) ^ native_permuted_variable_key;
    uint64_t observed = 0;
    for (unsigned index = 0; index < 8; ++index)
    {
        const unsigned offset = order[index];
        observed |= (uint64_t)((volatile unsigned char *)buffer)[offset] << (8 * offset);
    }
    memset(buffer, 0, 32);
    free(buffer);
    return (observed ^ native_permuted_variable_oracle_key) != NATIVE_PERMUTED_VARIABLE_ORACLE;
}

int main(void) { return native_permuted_variable(0) | native_permuted_variable(1); }
