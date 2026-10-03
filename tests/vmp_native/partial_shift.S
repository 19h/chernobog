/* Partly known register shifts after nondeterministic RDTSC data. */
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

BEGIN NAME(shift_right_upper_a)
    rdtsc
    shrq $32, %rax
    cmpq $0, %rax
    RESULT sete

BEGIN NAME(shift_right_upper_d)
    rdtsc
    shrq $32, %rdx
    cmpq $0, %rdx
    RESULT sete

BEGIN NAME(shift_left_inserted_zero)
    rdtsc
    shlq $1, %rax
    btq $0, %rax
    RESULT setae

BEGIN NAME(shift_right_sign)
    rdtsc
    shrq $1, %rax
    RESULT setns

BEGIN NAME(shift_arithmetic_zero_sign)
    rdtsc
    sarq $16, %rax
    RESULT setns

BEGIN NAME(shift_arithmetic_one_sign)
    rdtsc
    btsq $63, %rax
    sarq $16, %rax
    RESULT sets

BEGIN NAME(shift_masked_zero)
    stc
    rdtsc
    shlq $0, %rax
    RESULT setb

BEGIN NAME(shift_unknown_low)
    rdtsc
    shrq $16, %rax
    cmpq $0, %rax
    RESULT sete

BEGIN NAME(shift_unknown_count)
    rdtsc
    movb %al, %cl
    shrq %cl, %rdx
    cmpq $0, %rdx
    RESULT sete

BEGIN NAME(shift_unknown_carry)
    rdtsc
    shrq $32, %rax
    RESULT setb

BEGIN NAME(shift_locked)
    stc
    rdtsc
    .byte 0xf0, 0x48, 0xc1, 0xe8, 0x20
    RESULT setb

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
