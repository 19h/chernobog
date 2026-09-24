#include <stdint.h>
#include <stdlib.h>
#include <string.h>

volatile uint64_t indirect_temporal_key = UINT64_C(0x5a5a5a5a5a5a5a5a);
size_t (*volatile indirect_strlen_dispatch)(const char *) = strlen;

#ifndef INDIRECT_ORACLE_FIRST
#define INDIRECT_ORACLE_FIRST UINT64_C(0x5a7b2e3f28393f29)
#endif
#ifndef INDIRECT_ORACLE_SECOND
#define INDIRECT_ORACLE_SECOND UINT64_C(0x5a7b3e3435393f29)
#endif

__attribute__((noinline)) int indirect_temporal_strings(void)
{
    char *first = malloc(16);
    if (first == NULL)
        return 2;
    *(uint64_t *)first = UINT64_C(0x5a7b2e3f28393f29) ^ indirect_temporal_key;
    size_t first_length = indirect_strlen_dispatch(first);
    uint64_t first_value = *(volatile uint64_t *)first;
    memset(first, 0, 16);
    free(first);

    char *second = malloc(16);
    if (second == NULL)
        return 2;
    *(uint64_t *)second = UINT64_C(0x5a7b3e3435393f29) ^ indirect_temporal_key;
    size_t second_length = indirect_strlen_dispatch(second);
    uint64_t second_value = *(volatile uint64_t *)second;
    memset(second, 0, 16);
    free(second);

    return first_length != 7 || second_length != 7 ||
           (first_value ^ indirect_temporal_key) != INDIRECT_ORACLE_FIRST ||
           (second_value ^ indirect_temporal_key) != INDIRECT_ORACLE_SECOND;
}

int main(void) { return indirect_temporal_strings(); }
