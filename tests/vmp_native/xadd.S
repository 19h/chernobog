/* XADD register, alias, flag, and local memory replay fixtures. */
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

BEGIN NAME(xa_reg_value)
    movl $7, %eax
    movl $5, %edx
    xaddl %edx, %eax
    cmpl $12, %eax
    RESULT sete

BEGIN NAME(xa_reg_source)
    movl $7, %eax
    movl $5, %edx
    xaddl %edx, %eax
    cmpl $7, %edx
    RESULT sete

BEGIN NAME(xa_overflow)
    movl $0x7fffffff, %eax
    movl $1, %edx
    xaddl %edx, %eax
    RESULT seto

BEGIN NAME(xa_carry)
    movl $-1, %eax
    movl $1, %edx
    xaddl %edx, %eax
    RESULT setb

BEGIN NAME(xa_same)
    movl $7, %eax
    xaddl %eax, %eax
    cmpl $14, %eax
    RESULT sete

BEGIN NAME(xa_zero_extend_destination)
    movq $-1, %rax
    movl $1, %edx
    xaddl %edx, %eax
    cmpq $0, %rax
    RESULT sete

BEGIN NAME(xa_zero_extend_source)
    movq $-1, %rdx
    movl $7, %eax
    xaddl %edx, %eax
    cmpq $7, %rdx
    RESULT sete

BEGIN NAME(xa_unknown_source_exchange)
    movl $7, %eax
    movl %edi, %edx
    xaddl %edx, %eax
    cmpl $7, %edx
    RESULT sete

BEGIN NAME(xa_alias8)
    movl $0x1234, %eax
    xaddb %ah, %al
    cmpw $0x3446, %ax
    RESULT sete

BEGIN NAME(xa_memory)
    movl $7, NAME(xa_slot)(%rip)
    movl $5, %edx
    xaddl %edx, NAME(xa_slot)(%rip)
    movl NAME(xa_slot)(%rip), %eax
    cmpl $12, %eax
    RESULT sete

BEGIN NAME(xa_memory_source)
    movl $7, NAME(xa_slot)(%rip)
    movl $5, %edx
    xaddl %edx, NAME(xa_slot)(%rip)
    cmpl $7, %edx
    RESULT sete

BEGIN NAME(xa_memory_unknown_source_exchange)
    movl $7, NAME(xa_slot)(%rip)
    movl %edi, %edx
    xaddl %edx, NAME(xa_slot)(%rip)
    cmpl $7, %edx
    RESULT sete

BEGIN NAME(xa_address_alias)
    leaq NAME(xa_slot)(%rip), %rax
    movq $7, NAME(xa_slot)(%rip)
    xaddq %rax, (%rax)
    cmpq $7, %rax
    RESULT sete

BEGIN NAME(xa_locked_memory)
    movl $7, NAME(xa_slot)(%rip)
    movl $5, %edx
    lock xaddl %edx, NAME(xa_slot)(%rip)
    movl NAME(xa_slot)(%rip), %eax
    cmpl $12, %eax
    RESULT sete

BEGIN NAME(xa_preserve_unrelated)
    movl %edi, %eax
    movl $5, %edx
    movl $7, %r8d
    xaddl %edx, %eax
    cmpl $7, %r8d
    RESULT sete

BEGIN NAME(xa_preserve_disjoint_memory)
    movl $7, NAME(xa_other_slot)(%rip)
    movl $5, %edx
    xaddl %edx, NAME(xa_slot)(%rip)
    movl NAME(xa_other_slot)(%rip), %eax
    cmpl $7, %eax
    RESULT sete

BEGIN NAME(xa_unknown_destination)
    movl %edi, %eax
    movl $5, %edx
    xaddl %edx, %eax
    cmpl $12, %eax
    RESULT sete

BEGIN NAME(xa_locked_register)
    movl $7, %eax
    movl $5, %edx
    .byte 0xf0, 0x0f, 0xc1, 0xd0
    cmpl $12, %eax
    RESULT sete

.data
.p2align 3
NAME(xa_slot):
    .quad 0
NAME(xa_other_slot):
    .quad 0

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
