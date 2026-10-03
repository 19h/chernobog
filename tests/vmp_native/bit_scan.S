/* BSF/BSR register, memory, zero-source, and invalid-prefix replay fixtures. */
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

BEGIN NAME(bs_forward)
    movl $0x28, %edx
    bsfl %edx, %eax
    cmpl $3, %eax
    RESULT sete

BEGIN NAME(bs_reverse)
    movl $0x28, %edx
    bsrl %edx, %eax
    cmpl $5, %eax
    RESULT sete

BEGIN NAME(bs_zero_flag)
    xorl %edx, %edx
    bsfl %edx, %eax
    RESULT sete

BEGIN NAME(bs_nonzero_flag)
    movl $8, %edx
    bsrl %edx, %eax
    RESULT setne

BEGIN NAME(bs_alias)
    movl $8, %eax
    bsfl %eax, %eax
    cmpl $3, %eax
    RESULT sete

BEGIN NAME(bs_zero_extend)
    movq $-1, %rax
    movl $8, %edx
    bsrl %edx, %eax
    cmpq $3, %rax
    RESULT sete

BEGIN NAME(bs_preserve_upper_16)
    movq $0x12340000, %rax
    movw $8, %dx
    bsfw %dx, %ax
    cmpq $0x12340003, %rax
    RESULT sete

BEGIN NAME(bs_reverse_64)
    movabsq $0x8000000000000000, %rdx
    bsrq %rdx, %rax
    cmpq $63, %rax
    RESULT sete

BEGIN NAME(bs_forward_memory)
    movl $8, NAME(bs_slot)(%rip)
    bsfl NAME(bs_slot)(%rip), %eax
    cmpl $3, %eax
    RESULT sete

BEGIN NAME(bs_reverse_memory)
    movabsq $0x8000000000000000, %rdx
    movq %rdx, NAME(bs_slot)(%rip)
    bsrq NAME(bs_slot)(%rip), %rax
    cmpq $63, %rax
    RESULT sete

BEGIN NAME(bs_partial_nonzero)
    movl %edi, %eax
    btsl $3, %eax
    bsfl %eax, %edx
    RESULT setne

BEGIN NAME(bs_preserve_unrelated)
    movl $7, %r8d
    bsfl %edi, %eax
    cmpl $7, %r8d
    RESULT sete

BEGIN NAME(bs_preserve_disjoint_memory)
    movl $7, NAME(bs_other_slot)(%rip)
    bsfl %edi, %eax
    movl NAME(bs_other_slot)(%rip), %eax
    cmpl $7, %eax
    RESULT sete

BEGIN NAME(bs_zero_destination)
    xorl %edx, %edx
    movl $7, %eax
    bsfl %edx, %eax
    cmpl $7, %eax
    RESULT sete

BEGIN NAME(bs_unknown_forward)
    bsfl %edi, %eax
    cmpl $3, %eax
    RESULT sete

BEGIN NAME(bs_unknown_reverse)
    bsrl %edi, %eax
    cmpl $3, %eax
    RESULT sete

BEGIN NAME(bs_locked_register)
    movl $8, %edx
    .byte 0xf0
    bsfl %edx, %eax
    RESULT setne

BEGIN NAME(bs_locked_memory)
    movl $8, NAME(bs_slot)(%rip)
    .byte 0xf0
    bsrl NAME(bs_slot)(%rip), %eax
    RESULT setne

.data
.p2align 3
NAME(bs_slot):
    .quad 0
NAME(bs_other_slot):
    .quad 0

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
