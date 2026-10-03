/* SHLD/SHRD native replay fixtures for the IDA abstract interpreter. */
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

BEGIN NAME(ds_shld_register)
    movl $0x8123, %eax
    movl $0x5678, %edx
    shldw $1, %dx, %ax
    cmpw $0x0246, %ax
    RESULT sete

BEGIN NAME(ds_shrd_register)
    movl $0x8123, %eax
    movl $0x5678, %edx
    shrdw $1, %dx, %ax
    cmpw $0x4091, %ax
    RESULT sete

BEGIN NAME(ds_shld_carry)
    movl $0x8123, %eax
    movl $0x5678, %edx
    shldw $1, %dx, %ax
    RESULT setb

BEGIN NAME(ds_shrd_overflow)
    movl $0x8123, %eax
    movl $0x5678, %edx
    shrdw $1, %dx, %ax
    RESULT seto

BEGIN NAME(ds_zero_count)
    movl $0x8123, %eax
    movl $0x5678, %edx
    stc
    shldw $32, %dx, %ax
    RESULT setb

BEGIN NAME(ds_alias)
    movl $0x80000001, %eax
    shldl $1, %eax, %eax
    cmpl $3, %eax
    RESULT sete

BEGIN NAME(ds_shld_64)
    movabsq $0x8000000000000001, %rax
    movabsq $0x8000000000000000, %rdx
    shldq $1, %rdx, %rax
    cmpq $3, %rax
    RESULT sete

BEGIN NAME(ds_shrd_64)
    movq $2, %rax
    movq $0, %rdx
    shrdq $1, %rdx, %rax
    cmpq $1, %rax
    RESULT sete

BEGIN NAME(ds_count_alias)
    movl $1, %ecx
    shldl %cl, %ecx, %ecx
    cmpl $2, %ecx
    RESULT sete

BEGIN NAME(ds_memory)
    movl $0x8123, NAME(ds_slot)(%rip)
    movl $0x5678, %edx
    shldl $1, %edx, NAME(ds_slot)(%rip)
    movl NAME(ds_slot)(%rip), %eax
    cmpl $0x10246, %eax
    RESULT sete

BEGIN NAME(ds_preserve_unrelated)
    movl %edi, %ecx
    movl $7, %r8d
    movl $0x8123, %eax
    movl $0x5678, %edx
    shldw %cl, %dx, %ax
    cmpl $7, %r8d
    RESULT sete

BEGIN NAME(ds_preserve_disjoint_memory)
    movl %edi, %ecx
    movl $0x8123, NAME(ds_slot)(%rip)
    movl $7, NAME(ds_other_slot)(%rip)
    movl $0x5678, %edx
    shldl %cl, %edx, NAME(ds_slot)(%rip)
    movl NAME(ds_other_slot)(%rip), %eax
    cmpl $7, %eax
    RESULT sete

BEGIN NAME(ds_unknown_count)
    movl %edi, %ecx
    movl $0x8123, %eax
    movl $0x5678, %edx
    shldw %cl, %dx, %ax
    cmpw $0x0246, %ax
    RESULT sete

BEGIN NAME(ds_unknown_count_upper)
    movl %edi, %ecx
    movq $-1, %rax
    xorl %edx, %edx
    shldl %cl, %edx, %eax
    shrq $32, %rax
    testl %eax, %eax
    RESULT sete

BEGIN NAME(ds_undefined_count)
    movl $0x8123, %eax
    movl $0x5678, %edx
    shrdw $17, %dx, %ax
    cmpw $0x4091, %ax
    RESULT sete

.data
.p2align 3
NAME(ds_slot):
    .long 0
NAME(ds_other_slot):
    .long 0

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
