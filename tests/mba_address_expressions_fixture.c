#include <stdint.h>
#include <stdio.h>

#define NOINLINE __attribute__((noinline))

NOINLINE uint32_t verify_key(const void *packet, uint32_t encoded)
{
    uint32_t address = (uint32_t)(uintptr_t)packet;
    return encoded - (0xFB273F5Fu * (address ^ 0xC1F4666Au) + 7);
}

NOINLINE uint32_t verify_sum(const void *packet, uint32_t encoded)
{
    return encoded - ((uint32_t)(uintptr_t)packet + 0x0344A6ECu);
}

NOINLINE uint32_t verify_pair(const void *first, const void *second, uint32_t encoded)
{
    uint32_t a = (uint32_t)(uintptr_t)first;
    uint32_t b = (uint32_t)(uintptr_t)second;
    return encoded - ((a ^ 0x4CEA06F4u) + a - b);
}

#ifndef RECOVERED
NOINLINE uint32_t address_key(unsigned input)
{
    uint32_t packet;
    uint32_t p = (uint32_t)(uintptr_t)&packet;
    uint32_t mixed = (p | 0x4CEA06F4u) - p + (p & 0xB315F90Bu);
    return input + verify_key(&packet, 0xFB273F5Fu * (mixed ^ 0x8D1E609Eu) + 7);
}

NOINLINE uint32_t partial_address_key(unsigned input)
{
    uint32_t packet;
    uint32_t p = (uint32_t)(uintptr_t)&packet;
    uint32_t mixed = (p | 0x4CEA06F4u) - p + (p & 0xB315F908u);
    return input + verify_key(&packet, 0xFB273F5Fu * (mixed ^ 0x8D1E609Eu) + 7);
}

NOINLINE uint32_t address_sum(unsigned input)
{
    uint32_t packet;
    uint32_t p = (uint32_t)(uintptr_t)&packet;
    return input + verify_sum(&packet, (p | 0xFCBB5913u) + (p | 0x0344A6ECu) + 0x0344A6EDu);
}

NOINLINE uint32_t distinct_addresses(unsigned input)
{
    uint32_t packet[8];
    uint32_t a = (uint32_t)(uintptr_t)&packet[0];
    uint32_t b = (uint32_t)(uintptr_t)&packet[4];
    uint32_t mixed = (a | 0x4CEA06F4u) - b + (a & 0xB315F90Bu);
    return input + verify_pair(&packet[0], &packet[4], mixed);
}
#else
#include "recovered.c"
#endif

int main(void)
{
    for (unsigned input = 0; input < 256; ++input)
        printf("%u %u %u %u %u\n", input, address_key(input), partial_address_key(input),
               address_sum(input), distinct_addresses(input));
    return 0;
}
