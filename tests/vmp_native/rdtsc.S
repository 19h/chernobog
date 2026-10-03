/* RDTSC nondeterministic output, preserved state, and invalid-prefix fixtures. */
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

BEGIN NAME(tsc_flags_carry)
    stc
    rdtsc
    RESULT setb

BEGIN NAME(tsc_flags_zero)
    xorl %r8d, %r8d
    rdtsc
    RESULT sete

BEGIN NAME(tsc_unrelated_register)
    movl $7, %r8d
    rdtsc
    cmpl $7, %r8d
    RESULT sete

BEGIN NAME(tsc_disjoint_memory)
    movl $7, NAME(tsc_slot)(%rip)
    rdtsc
    movl NAME(tsc_slot)(%rip), %r8d
    cmpl $7, %r8d
    RESULT sete

BEGIN NAME(tsc_zero_extend_a)
    movq $-1, %rax
    rdtsc
    btq $32, %rax
    RESULT setae

BEGIN NAME(tsc_zero_extend_d)
    movq $-1, %rdx
    rdtsc
    btq $32, %rdx
    RESULT setae

BEGIN NAME(tsc_unknown_a)
    rdtsc
    cmpl $0, %eax
    RESULT sete

BEGIN NAME(tsc_unknown_d)
    rdtsc
    cmpl $0, %edx
    RESULT sete

BEGIN NAME(tsc_locked)
    stc
    .byte 0xf0, 0x0f, 0x31
    RESULT setb

.data
.p2align 3
NAME(tsc_slot):
    .quad 0

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
