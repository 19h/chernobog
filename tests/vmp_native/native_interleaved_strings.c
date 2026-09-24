#include <stdint.h>
#include <stdlib.h>
#include <string.h>

volatile uint64_t native_interleaved_key = UINT64_C(0x5a5a5a5a5a5a5a5a);
volatile const uint64_t native_interleaved_oracle_key = UINT64_C(0x5a5a5a5a5a5a5a5a);
#ifndef SNAPSHOT_ORACLE_FIRST
#define SNAPSHOT_ORACLE_FIRST UINT64_C(0x5a7b2e3f28393f29)
#endif
#ifndef SNAPSHOT_ORACLE_SECOND
#define SNAPSHOT_ORACLE_SECOND UINT64_C(0x5a7b3e3435393f29)
#endif

__attribute__((noinline)) int native_interleaved_strings(void)
{
    uint64_t *first = malloc(32);
#ifdef SHARED_ALLOCATION
    uint64_t *second = first + 2;
#else
    uint64_t *second = malloc(32);
#endif
    *first = UINT64_C(0x5a7b2e3f28393f29) ^ native_interleaved_key;
    *second = UINT64_C(0x5a7b3e3435393f29) ^ native_interleaved_key;
    uint64_t first_value = 0, second_value = 0;
    for (unsigned i = 0; i < 8; ++i)
    {
        first_value |= (uint64_t)((volatile unsigned char *)first)[i] << (8 * i);
        second_value |= (uint64_t)((volatile unsigned char *)second)[i] << (8 * i);
#ifdef WRITE_FIRST_ALLOCATION
        ((volatile unsigned char *)first)[24] = (unsigned char)i;
#endif
    }
    memset(first, 0, 32);
    free(first);
#ifndef SHARED_ALLOCATION
    memset(second, 0, 32);
    free(second);
#endif
    return (first_value ^ native_interleaved_oracle_key) != SNAPSHOT_ORACLE_FIRST ||
           (second_value ^ native_interleaved_oracle_key) != SNAPSHOT_ORACLE_SECOND;
}

int main(void) { return native_interleaved_strings(); }
