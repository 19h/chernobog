/* x86-64 REP postconditions consumed by conditions and PUSH/RET targets. */
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

.macro MEMORY
    leaq NAME(repeat_index_source)+24(%rip), %rsi
    leaq NAME(repeat_index_dest)+24(%rip), %rdi
    movabsq $(0x0807060504030201), %rax
    .irp offset, -24, -16, -8, 0, 8, 16, 24, 32
    movq %rax, \offset(%rsi)
    .endr
    movabsq $(0x9999999999999999), %rax
    .irp offset, -24, -16, -8, 0, 8, 16, 24, 32
    movq %rax, \offset(%rdi)
    .endr
.endm

.macro TARGET name, operation, index, advance, direction
BEGIN \name
    \direction
    MEMORY
    leaq NAME(repeat_index_target)(%rip), %rdx
    subq %\index, %rdx
    subq $\advance, %rdx
    movl $(2), %ecx
    rep \operation
    addq %rdx, %\index
    pushq %\index
    ret
.endm

TARGET NAME(repeat_movsb_di), movsb, rdi, 2, cld
TARGET NAME(repeat_movsw_di), movsw, rdi, -4, std
TARGET NAME(repeat_movsd_di), movsl, rdi, 8, cld
TARGET NAME(repeat_movsq_di), movsq, rdi, -16, std
TARGET NAME(repeat_stosb_di), stosb, rdi, -2, std
TARGET NAME(repeat_stosw_di), stosw, rdi, 4, cld
TARGET NAME(repeat_stosd_di), stosl, rdi, -8, std
TARGET NAME(repeat_stosq_di), stosq, rdi, 16, cld
TARGET NAME(repeat_movsb_si), movsb, rsi, 2, cld
TARGET NAME(repeat_movsq_si), movsq, rsi, -16, std

/* A byte count in [0,3] and either DF leave the index in the same 16 B block. */
.macro PARTIAL name, operation, index, partial, direction
BEGIN \name
    movl %edi, %ecx
    \direction
    MEMORY
    .if \partial
    andl $(3), %ecx
    .else
    movl $(2), %ecx
    .endif
    leaq NAME(repeat_index_target)(%rip), %rdx
    subq %\index, %rdx
    addq $(8), %rdx
    rep \operation
    andq $(-16), %\index
    addq %rdx, %\index
    pushq %\index
    ret
.endm

PARTIAL NAME(repeat_unknown_df_masked), stosb, rdi, 0, nop
PARTIAL NAME(repeat_partial_count_masked), stosb, rdi, 1, cld
PARTIAL NAME(repeat_both_masked), stosb, rdi, 1, nop
PARTIAL NAME(repeat_movs_si_masked), movsb, rsi, 1, nop

.macro CONDITION
    sete %al
    cld
    movzbl %al, %eax
    ret
.endm

BEGIN NAME(repeat_unknown_df_unmasked)
    MEMORY
    movl $2, %ecx
    rep stosb
    leaq NAME(repeat_index_dest)+26(%rip), %rdx
    cmpq %rdx, %rdi
    CONDITION

BEGIN NAME(repeat_partial_count_unmasked)
    movl %edi, %ecx
    cld
    MEMORY
    andl $3, %ecx
    rep stosb
    leaq NAME(repeat_index_dest)+26(%rip), %rdx
    cmpq %rdx, %rdi
    CONDITION

BEGIN NAME(repeat_count_nine)
    cld
    MEMORY
    movl $9, %ecx
    rep stosb
    leaq NAME(repeat_index_dest)+33(%rip), %rdx
    cmpq %rdx, %rdi
    CONDITION

BEGIN NAME(repeat_unknown_source)
    movq %rsi, %r8
    cld
    MEMORY
    movq %r8, %rsi
    movl $2, %ecx
    rep movsb
    leaq NAME(repeat_index_source)+26(%rip), %rdx
    cmpq %rdx, %rsi
    CONDITION

BEGIN NAME(repeat_stos_preserves_si)
    std
    MEMORY
    movl $2, %ecx
    rep stosq
    leaq NAME(repeat_index_source)+24(%rip), %rdx
    cmpq %rdx, %rsi
    CONDITION

BEGIN NAME(repeat_zero_index)
    MEMORY
    movl $0, %ecx
    rep movsq
    leaq NAME(repeat_index_dest)+24(%rip), %rdx
    cmpq %rdx, %rdi
    CONDITION

BEGIN NAME(repeat_index_target)
    cld
    movl $73, %eax
    ret

.data
.p2align 4
.globl NAME(repeat_index_source)
NAME(repeat_index_source):
    .space 64
.globl NAME(repeat_index_dest)
NAME(repeat_index_dest):
    .space 64

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
