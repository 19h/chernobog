/* Known bit positions through 32/64-bit BSWAP; invalid and unknown controls. */
#ifdef __APPLE__
#define NAME(x) _##x
#else
#define NAME(x) x
#endif

.text
.macro BEGIN name
.p2align 4
.globl \name
\name:
.endm
.macro RESULT condition
    \condition %al
    movzbl %al, %eax
    ret
.endm

BEGIN NAME(main)
    xorl %eax, %eax
    ret

BEGIN NAME(bswap64_known_zero)
    rdtsc
    bswapq %rax
    btq $0, %rax
    RESULT setae

BEGIN NAME(bswap64_known_one)
    rdtsc
    btsq $63, %rax
    bswapq %rax
    btq $7, %rax
    RESULT setb

BEGIN NAME(bswap32_masked_byte)
    rdtsc
    andl $0xffffff00, %eax
    bswapl %eax
    btq $24, %rax
    RESULT setae

BEGIN NAME(bswap32_zero_extend)
    movq $-1, %rax
    rdtsc
    bswapl %eax
    btq $63, %rax
    RESULT setae

BEGIN NAME(bswap_flags)
    stc
    rdtsc
    bswapq %rax
    RESULT setb

BEGIN NAME(bswap32_unknown)
    rdtsc
    bswapl %eax
    cmpl $0, %eax
    RESULT sete

BEGIN NAME(bswap64_unknown)
    rdtsc
    bswapq %rax
    cmpq $0, %rax
    RESULT sete

BEGIN NAME(bswap_locked)
    stc
    rdtsc
    .byte 0xf0, 0x0f, 0xc8
    RESULT setb

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
