#include <stdint.h>
#include <stdlib.h>
#include <string.h>

volatile uint64_t native_snapshot_key = UINT64_C(0x5a5a5a5a5a5a5a5a);
volatile const uint64_t native_snapshot_oracle_key = UINT64_C(0x5a5a5a5a5a5a5a5a);
#ifndef SNAPSHOT_ORACLE_FIRST
#define SNAPSHOT_ORACLE_FIRST UINT64_C(0x5a7b2e3f28393f29)
#endif
#ifndef SNAPSHOT_ORACLE_SECOND
#define SNAPSHOT_ORACLE_SECOND UINT64_C(0x5a7b3e3435393f29)
#endif

__attribute__((noinline)) int native_snapshot_strings(void)
{
    uint64_t *first = malloc(16);
    *first = UINT64_C(0x5a7b2e3f28393f29) ^ native_snapshot_key;
    const uint64_t first_value = *(volatile uint64_t *)first;
    const size_t first_length = strlen((char *)first);
    memset(first, 0, 16);
    free(first);
    uint64_t *second = malloc(16);
    *second = UINT64_C(0x5a7b3e3435393f29) ^ native_snapshot_key;
    const uint64_t second_value = *(volatile uint64_t *)second;
    const size_t second_length = strlen((char *)second);
    memset(second, 0, 16);
    free(second);
    return (first_value ^ native_snapshot_oracle_key) != SNAPSHOT_ORACLE_FIRST ||
           (second_value ^ native_snapshot_oracle_key) != SNAPSHOT_ORACLE_SECOND ||
           first_length != 7 || second_length != 7;
}

int main(void) { return native_snapshot_strings(); }
