#include <stdint.h>
#include <stdio.h>

#define DEFINE_FLAGS(bits, type, suffix)                                                           \
    static __attribute__((noinline)) void flags##bits(type x, type y, unsigned char result[4])     \
    {                                                                                              \
        type sum = x, difference = x;                                                              \
        unsigned char carry, add_overflow, subtract_overflow, parity;                              \
        __asm__ volatile("add" suffix " %3, %2; setc %0; seto %1"                                  \
                         : "=qm"(carry), "=qm"(add_overflow), "+r"(sum)                            \
                         : "r"(y)                                                                  \
                         : "cc");                                                                  \
        __asm__ volatile("sub" suffix " %3, %2; seto %0; setp %1"                                  \
                         : "=qm"(subtract_overflow), "=qm"(parity), "+r"(difference)               \
                         : "r"(y)                                                                  \
                         : "cc");                                                                  \
        result[0] = carry;                                                                         \
        result[1] = add_overflow;                                                                  \
        result[2] = subtract_overflow;                                                             \
        result[3] = parity;                                                                        \
    }

DEFINE_FLAGS(8, uint8_t, "b")
DEFINE_FLAGS(16, uint16_t, "w")
DEFINE_FLAGS(32, uint32_t, "l")
DEFINE_FLAGS(64, uint64_t, "q")

__attribute__((noinline)) unsigned flag_parity_zero32(void)
{
    unsigned result;
    __asm__ volatile("xorl %%eax, %%eax; testl %%eax, %%eax; setp %%al; movzbl %%al, %%eax"
                     : "=a"(result)
                     :
                     : "cc");
    return result;
}

__attribute__((noinline)) unsigned flag_parity_one32(void)
{
    unsigned result;
    __asm__ volatile("movl $1, %%eax; testl %%eax, %%eax; setp %%al; movzbl %%al, %%eax"
                     : "=a"(result)
                     :
                     : "cc");
    return result;
}

__attribute__((noinline)) unsigned char flag_parity_compare32(uint32_t x, uint32_t y)
{
    unsigned char result;
    __asm__ volatile("cmpl %2, %1; setp %0" : "=qm"(result) : "r"(x), "r"(y) : "cc");
    return result;
}

__attribute__((noinline)) unsigned char flag_overflow_zero8(void)
{
    unsigned char result = 1;
    __asm__ volatile("addb $1, %0; seto %0" : "+q"(result) : : "cc");
    return result;
}

__attribute__((noinline)) unsigned char flag_overflow_one8(void)
{
    unsigned char result = 127;
    __asm__ volatile("addb $1, %0; seto %0" : "+q"(result) : : "cc");
    return result;
}

static int emit(unsigned bytes, uint64_t x, uint64_t y)
{
    unsigned char values[4];
    switch (bytes)
    {
    case 1:
        flags8((uint8_t)x, (uint8_t)y, values);
        break;
    case 2:
        flags16((uint16_t)x, (uint16_t)y, values);
        break;
    case 4:
        flags32((uint32_t)x, (uint32_t)y, values);
        break;
    case 8:
        flags64(x, y, values);
        break;
    default:
        return 1;
    }
    if (flag_parity_compare32((uint32_t)x, (uint32_t)y) != values[3])
        return 1;
    return fwrite(values, 1, sizeof(values), stdout) != sizeof(values);
}

int main(void)
{
    if (flag_parity_zero32() != 1 || flag_parity_one32() != 0 || flag_overflow_zero8() != 0 ||
        flag_overflow_one8() != 1)
        return 1;
    for (unsigned x = 0; x < 256; ++x)
        for (unsigned y = 0; y < 256; ++y)
            if (emit(1, x, y))
                return 1;
    for (unsigned bytes = 2; bytes <= 8; bytes *= 2)
    {
        const uint64_t mask = bytes == 8 ? UINT64_MAX : (UINT64_C(1) << (8 * bytes)) - 1;
        const uint64_t sign = UINT64_C(1) << (8 * bytes - 1);
        const uint64_t corners[] = {0, 1, 2, sign - 1, sign, sign + 1, mask - 1, mask};
        for (unsigned x = 0; x < sizeof(corners) / sizeof(corners[0]); ++x)
            for (unsigned y = 0; y < sizeof(corners) / sizeof(corners[0]); ++y)
                if (emit(bytes, corners[x], corners[y]))
                    return 1;
    }
    return fflush(stdout) != 0;
}
