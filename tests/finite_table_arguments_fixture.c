#include <stdint.h>
#include <stdio.h>

#define ROW(b, k)                                                                                  \
    ((b) ^ (k)), (((b) + 1) ^ (k)), (((b) + 2) ^ (k)), (((b) + 3) ^ (k)), (((b) + 4) ^ (k)),       \
        (((b) + 5) ^ (k)), (((b) + 6) ^ (k)), (((b) + 7) ^ (k)), (((b) + 8) ^ (k)),                \
        (((b) + 9) ^ (k)), (((b) + 10) ^ (k)), (((b) + 11) ^ (k)), (((b) + 12) ^ (k)),             \
        (((b) + 13) ^ (k)), (((b) + 14) ^ (k)), (((b) + 15) ^ (k))
#define TABLE(k)                                                                                   \
    ROW(0, k), ROW(16, k), ROW(32, k), ROW(48, k), ROW(64, k), ROW(80, k), ROW(96, k),             \
        ROW(112, k), ROW(128, k), ROW(144, k), ROW(160, k), ROW(176, k), ROW(192, k), ROW(208, k), \
        ROW(224, k), ROW(240, k)

static const uint8_t first[256] = {TABLE(0x53)};
static const uint8_t second[256] = {TABLE(0x99)};
volatile uint8_t mutable_first[256] = {TABLE(0x53)};
static unsigned ticks;
unsigned observed_value;
static const uint32_t data_offsets[256] = {[0x61] = 16};

__attribute__((noinline)) unsigned consume_value(unsigned value) { return value ^ 0x1234; }
__attribute__((noinline)) unsigned next_input(unsigned value) { return (value + ++ticks) & 255; }

#ifndef RECOVERED
__attribute__((noinline)) unsigned table_argument(unsigned input)
{
    uint8_t index = (uint8_t)input;
    return consume_value(second[first[index] ^ 0xAB] ^ index);
}

__attribute__((noinline)) unsigned mutable_argument(unsigned input)
{
    uint8_t index = (uint8_t)input;
    return consume_value(second[mutable_first[index] ^ 0xAB] ^ index);
}

__attribute__((noinline)) unsigned effectful_argument(unsigned input)
{
    return consume_value(second[first[next_input(input)] ^ 0xAB] ^ next_input(input));
}

__attribute__((noinline)) unsigned table_data_read(unsigned input)
{
    uint8_t index = (uint8_t)input;
    return *(unsigned *)((uintptr_t)&observed_value +
                         data_offsets[second[first[index] ^ 0xAB] ^ index] - 16) +
           input;
}
#else
#include "recovered.c"
#endif

int main(void)
{
    for (unsigned input = 0; input < 256; ++input)
    {
        mutable_first[input] ^= (uint8_t)input;
        ticks = 0;
        observed_value = input * 0x12345u;
        unsigned effectful = effectful_argument(input);
        printf("%u %u %u %u %u %u\n", input, table_argument(input), mutable_argument(input),
               effectful, ticks, table_data_read(input));
    }
    return 0;
}
