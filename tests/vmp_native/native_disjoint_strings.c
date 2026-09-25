#include <stdint.h>
#include <stdlib.h>

volatile uint64_t native_disjoint_key = UINT64_C(0x5a5a5a5a5a5a5a5a);
#ifndef NATIVE_DISJOINT_ORACLE_SECOND_FORWARD
#define NATIVE_DISJOINT_ORACLE_SECOND_FORWARD UINT64_C(0x685549afbb9a90ee)
#endif

__attribute__((noinline)) int native_disjoint_strings(unsigned mode)
{
    static const unsigned char forward[8] = {3, 1, 6, 0, 7, 2, 5, 4};
    static const unsigned char reverse[8] = {7, 6, 5, 4, 3, 2, 1, 0};
    const volatile unsigned char *order = (mode & 1) != 0 ? reverse : forward;
    uint64_t *buffer = malloc(32);
    if (buffer == NULL)
        return 2;
    buffer[0] = UINT64_C(0x5a7b2e3f28393f29) ^ native_disjoint_key;
    buffer[2] = UINT64_C(0x5a7b3e3435393f29) ^ native_disjoint_key;
    unsigned mismatch = 0;
    for (unsigned string_index = 0; string_index < 2; ++string_index)
    {
#ifdef NATIVE_DISJOINT_STACK_HASH
        volatile uint64_t observed = UINT64_C(0xcbf29ce484222325);
#else
        uint64_t observed = UINT64_C(0xcbf29ce484222325);
#endif
#pragma clang loop unroll(disable)
        for (unsigned index = 0; index < 8; ++index)
        {
            const unsigned offset = order[index];
            const unsigned char *pointer =
                (const unsigned char *)buffer + 16 * string_index + offset;
            unsigned char byte;
            if ((offset & 1) != 0)
            {
                __atomic_signal_fence(__ATOMIC_SEQ_CST);
                byte = *(const volatile unsigned char *)pointer;
                __atomic_signal_fence(__ATOMIC_SEQ_CST);
            }
            else
                byte = *(const volatile unsigned char *)pointer;
            observed = (observed ^ byte) * UINT64_C(0x100000001b3);
        }
        const uint64_t expected =
            string_index == 0
                ? ((mode & 1) ? UINT64_C(0x77236cf6baa607ba) : UINT64_C(0xdff4af628384f6e6))
                : ((mode & 1) ? UINT64_C(0x53faff9a8a2acc16)
                              : NATIVE_DISJOINT_ORACLE_SECOND_FORWARD);
        mismatch |= observed != expected;
    }
    volatile unsigned char *clear = (volatile unsigned char *)buffer;
    for (unsigned index = 0; index < 32; ++index)
        clear[index] = 0;
    free(buffer);
    return mismatch;
}

int main(void) { return native_disjoint_strings(0) | native_disjoint_strings(1); }
