#include <stdint.h>
#include <stdio.h>

__attribute__((noinline)) uint32_t predicate_or_odd32(uint32_t x)
{
    uint32_t result;
    __asm__ volatile("movl %1, %%eax; orl $1, %%eax; setne %%al; movzbl %%al, %%eax"
                     : "=&a"(result)
                     : "r"(x)
                     : "cc");
    return result;
}

__attribute__((noinline)) uint32_t predicate_and_zero32(uint32_t x)
{
    uint32_t result;
    __asm__ volatile("movl %1, %%eax; andl $0, %%eax; sete %%al; movzbl %%al, %%eax"
                     : "=&a"(result)
                     : "r"(x)
                     : "cc");
    return result;
}

__attribute__((noinline)) uint32_t predicate_unsigned_bound32(uint32_t x)
{
    uint32_t result;
    __asm__ volatile("cmpl $0, %1; setb %%al; movzbl %%al, %%eax" : "=&a"(result) : "r"(x) : "cc");
    return result;
}

__attribute__((noinline)) uint32_t predicate_signed_negative8(uint32_t x)
{
    uint32_t result;
    __asm__ volatile("movl %1, %%eax; cmpb $0, %%al; setl %%al; movzbl %%al, %%eax"
                     : "=&a"(result)
                     : "r"(x)
                     : "cc");
    return result;
}

__attribute__((noinline)) uint32_t predicate_zext_not8(uint32_t x)
{
    uint32_t result;
    __asm__ volatile(
        "movl %1, %%eax; notb %%al; movzbl %%al, %%eax; "
        "movzbl %b1, %%ecx; notl %%ecx; cmpl %%ecx, %%eax; sete %%al; movzbl %%al, %%eax"
        : "=&a"(result)
        : "r"(x)
        : "cc", "ecx");
    return result;
}

__attribute__((noinline)) uint32_t predicate_alias_write32(uint32_t *cell, uint32_t x)
{
    uint32_t result;
    __asm__ volatile(
        "movl (%1), %%eax; movl %2, (%1); cmpl (%1), %%eax; sete %%al; movzbl %%al, %%eax"
        : "=&a"(result)
        : "r"(cell), "r"(x)
        : "cc", "memory");
    return result;
}

int main(void)
{
    unsigned comparisons = 0;
    for (unsigned x = 0; x < 256; ++x)
    {
        if (predicate_or_odd32(x) != 1 || predicate_and_zero32(x) != 1 ||
            predicate_unsigned_bound32(x) != 0)
            return 1;
        if (predicate_signed_negative8(x) != (uint32_t)((int8_t)x < 0) ||
            predicate_zext_not8(x) != 0)
            return 2;
        comparisons += 5;
        for (unsigned y = 0; y < 256; ++y)
        {
            uint32_t cell = x;
            if (predicate_alias_write32(&cell, y) != (uint32_t)(x == y) || cell != y)
                return 3;
            ++comparisons;
        }
    }
    const uint32_t corner[] = {UINT32_C(0x7fffffff), UINT32_C(0x80000000), UINT32_MAX};
    for (unsigned i = 0; i < 3; ++i)
    {
        const uint32_t x = corner[i];
        if (predicate_or_odd32(x) != 1 || predicate_and_zero32(x) != 1 ||
            predicate_unsigned_bound32(x) != 0 ||
            predicate_signed_negative8(x) != (uint32_t)((int8_t)x < 0) ||
            predicate_zext_not8(x) != 0)
            return 4;
        comparisons += 5;
    }
    printf("native predicate oracle passed; comparisons=%u\n", comparisons);
    return 0;
}
