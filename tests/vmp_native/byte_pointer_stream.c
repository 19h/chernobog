/* Exact x64 byte-pointer read shape and a loaded-global-pointer control. */
#include <stddef.h>
#include <stdint.h>

#define KEY UINT32_C(0xA17E395B)
#define ROT32(k, n)                                                                                \
    (((uint32_t)(k) << ((n) & 31u)) | ((uint32_t)(k) >> ((32u - ((n) & 31u)) & 31u)))
#define ENC8(c, n) ((uint8_t)((uint8_t)(c) ^ (uint8_t)(ROT32(KEY, n) + (n))))

const uint8_t byte_pointer_source[] = {ENC8('V', 0), ENC8('M', 1), ENC8('P', 2),
                                       ENC8(' ', 3), ENC8('b', 4), ENC8('y', 5),
                                       ENC8('t', 6), ENC8('e', 7), ENC8(0, 8)};
uint8_t byte_pointer_output[sizeof(byte_pointer_source)];
uint8_t byte_pointer_loaded_output[sizeof(byte_pointer_source)];
const uint8_t *byte_pointer_global = byte_pointer_source;

void byte_pointer_stream(void);
void byte_pointer_loaded_global(void);

#if defined(__x86_64__) && defined(__APPLE__)
__asm__(".globl _byte_pointer_stream\n"
        "_byte_pointer_stream:\n"
        "leaq _byte_pointer_source(%rip), %rax\n"
        "xorl %ecx, %ecx\n"
        "leaq _byte_pointer_output(%rip), %rsi\n"
        "1:\n"
        "movzbl (%rax), %edx\n"
        "incq %rax\n"
        "movl $0xA17E395B, %r8d\n"
        "roll %cl, %r8d\n"
        "addl %ecx, %r8d\n"
        "xorb %r8b, %dl\n"
        "movb %dl, (%rsi,%rcx)\n"
        "incq %rcx\n"
        "cmpq $9, %rcx\n"
        "jne 1b\n"
        "retq\n"
        ".globl _byte_pointer_loaded_global\n"
        "_byte_pointer_loaded_global:\n"
        "movq _byte_pointer_global(%rip), %rax\n"
        "xorl %ecx, %ecx\n"
        "leaq _byte_pointer_loaded_output(%rip), %rsi\n"
        "2:\n"
        "movzbl (%rax), %edx\n"
        "incq %rax\n"
        "movl $0xA17E395B, %r8d\n"
        "roll %cl, %r8d\n"
        "addl %ecx, %r8d\n"
        "xorb %r8b, %dl\n"
        "movb %dl, (%rsi,%rcx)\n"
        "incq %rcx\n"
        "cmpq $9, %rcx\n"
        "jne 2b\n"
        "retq\n");
#else
void byte_pointer_stream(void)
{
    const uint8_t *source = byte_pointer_source;
    for (size_t i = 0; i < sizeof(byte_pointer_source); ++i)
        byte_pointer_output[i] = *source++ ^ (uint8_t)(ROT32(KEY, i) + i);
}

void byte_pointer_loaded_global(void)
{
    const uint8_t *source = byte_pointer_global;
    for (size_t i = 0; i < sizeof(byte_pointer_source); ++i)
        byte_pointer_loaded_output[i] = *source++ ^ (uint8_t)(ROT32(KEY, i) + i);
}
#endif

int main(void)
{
    static const uint8_t expected[] = "VMP byte";
    byte_pointer_stream();
    byte_pointer_loaded_global();
    for (size_t i = 0; i < sizeof(expected); ++i)
    {
        if (byte_pointer_output[i] != expected[i])
            return 1;
        if (byte_pointer_loaded_output[i] != expected[i])
            return 2;
    }
    return 0;
}
