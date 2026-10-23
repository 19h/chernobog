#include <stdint.h>
#include <stdio.h>

#define NOINLINE __attribute__((noinline))
#if defined(__APPLE__)
#define SYMBOL(name) "_" #name
#else
#define SYMBOL(name) #name
#endif

uint64_t calls;
uint64_t observed;

NOINLINE uint64_t forward_target(uint64_t a, uint64_t b)
{
    ++calls;
    observed = a;
    return a * 3 + b;
}

NOINLINE uint64_t alternate_target(uint64_t a, uint64_t b)
{
    ++calls;
    observed = b;
    return a ^ (b + 0x55);
}

uint64_t (*volatile target_slot)(uint64_t, uint64_t) = forward_target;

#if defined(__x86_64__)
#define WRAPPER(name, body)                                                                        \
    __attribute__((naked, noinline)) uint64_t name(uint64_t a, uint64_t b)                         \
    {                                                                                              \
        __asm__ volatile(body);                                                                    \
    }

WRAPPER(direct_wrapper, "pushq %rax\ncallq " SYMBOL(forward_target) "\npopq %rcx\nretq\n")
WRAPPER(indirect_wrapper, "pushq %rax\ncallq *" SYMBOL(target_slot) "(%rip)\npopq %rcx\nretq\n")
WRAPPER(aligned_wrapper, "subq $8,%rsp\ncallq " SYMBOL(forward_target) "\naddq $8,%rsp\nretq\n")
WRAPPER(framed_wrapper, "pushq %rbp\nmovq %rsp,%rbp\nsubq $16,%rsp\ncallq " SYMBOL(
                            forward_target) "\naddq $16,%rsp\npopq %rbp\nretq\n")
WRAPPER(chain_wrapper, "pushq %rax\ncallq " SYMBOL(direct_wrapper) "\npopq %rcx\nretq\n")
WRAPPER(custom_wrapper, "pushq %rax\ncallq " SYMBOL(forward_target) "\npopq %rcx\nretq\n")
WRAPPER(postprocess_wrapper,
        "pushq %rax\ncallq " SYMBOL(forward_target) "\npopq %rcx\naddq $1,%rax\nretq\n")
WRAPPER(restore_wrapper, "pushq %rax\ncallq " SYMBOL(forward_target) "\npopq %rax\nretq\n")
WRAPPER(restore_caller, "movq $0x12345678,%rax\nsubq $8,%rsp\ncallq " SYMBOL(
                            restore_wrapper) "\naddq $8,%rsp\nretq\n")
#else
NOINLINE uint64_t direct_wrapper(uint64_t a, uint64_t b) { return forward_target(a, b); }
NOINLINE uint64_t indirect_wrapper(uint64_t a, uint64_t b) { return target_slot(a, b); }
NOINLINE uint64_t aligned_wrapper(uint64_t a, uint64_t b) { return forward_target(a, b); }
NOINLINE uint64_t framed_wrapper(uint64_t a, uint64_t b) { return forward_target(a, b); }
NOINLINE uint64_t chain_wrapper(uint64_t a, uint64_t b) { return direct_wrapper(a, b); }
NOINLINE uint64_t custom_wrapper(uint64_t a, uint64_t b) { return forward_target(a, b); }
NOINLINE uint64_t postprocess_wrapper(uint64_t a, uint64_t b) { return forward_target(a, b) + 1; }
NOINLINE uint64_t restore_caller(uint64_t a, uint64_t b)
{
    forward_target(a, b);
    return 0x12345678;
}
#endif

NOINLINE uint64_t forward_caller(uint64_t input)
{
    uint64_t value = direct_wrapper(input, 7);
    value ^= indirect_wrapper(input, 11);
    value += aligned_wrapper(input, 13);
    value ^= framed_wrapper(input, 17);
    return value + chain_wrapper(input, 19);
}

NOINLINE uint64_t negative_caller(uint64_t input)
{
    return postprocess_wrapper(input, 23) + custom_wrapper(input, 31);
}

int main(void)
{
    const uint64_t inputs[] = {0, 1, 2, 7, 0x7fffffff, 0x80000000, 0xffffffff, UINT64_MAX};
    for (unsigned mode = 0; mode < 2; ++mode)
    {
        target_slot = mode ? alternate_target : forward_target;
        for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i)
        {
            calls = 0;
            uint64_t value = forward_caller(inputs[i]);
            uint64_t negative = negative_caller(inputs[i]);
            uint64_t restored = restore_caller(inputs[i], 29);
            printf("%u %llu %llu %llu %llu %llu %llu\n", mode, (unsigned long long)inputs[i],
                   (unsigned long long)value, (unsigned long long)negative,
                   (unsigned long long)restored, (unsigned long long)calls,
                   (unsigned long long)observed);
        }
    }
    return 0;
}
