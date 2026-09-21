// Linked ELF32 analysis fixture; not a macOS executable.
.code32
.text
.macro GP32_BEGIN name
.p2align 4
.globl \name
.type \name,@function
\name:
.endm

GP32_BEGIN _start
    call gp32_materialize
    call gp32_reg
    call gp32_mem
    call gp32_call
    movl $1, %eax
    xorl %ebx, %ebx
    int $0x80

GP32_BEGIN gp32_target
    movl $7, %eax
    ret

GP32_BEGIN gp32_materialize
    pushl $1f
1:  popl %eax
    addl $(gp32_target-1b), %eax
    pushl %eax
    ret

GP32_BEGIN gp32_literal
    pushl $gp32_target
    popl %eax
    ret

GP32_BEGIN gp32_reg
    movl $gp32_target, %eax
    pushl %eax
    ret

GP32_BEGIN gp32_mem
    pushl gp32_ro
    ret

GP32_BEGIN gp32_unknown
    pushl %edi
    ret

GP32_BEGIN gp32_writable
    pushl gp32_rw
    ret

GP32_BEGIN gp32_width
    pushw %ax
    ret

GP32_BEGIN gp32_far
    pushl $gp32_target
    lret

GP32_BEGIN gp32_extra
    pushl $gp32_target
    ret $4

GP32_BEGIN gp32_alternate
    testl %edi, %edi
    jnz 2f
    pushl $gp32_target
2:  ret

GP32_BEGIN gp32_call
    call 3f
    movl $7, %eax
    ret
3:  popl %eax
    pushl %eax
    ret

GP32_BEGIN gp32_next
    call 4f
4:  popl %eax
    jmp gp32_target

.section .rodata
.p2align 2
gp32_ro:
    .long gp32_target
.data
.p2align 2
gp32_rw:
    .long gp32_target
.section .note.GNU-stack,"",@progbits
