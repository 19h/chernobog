// Independent Linux i386 execution control for the ELF32 analysis shapes.
.code32
.text
.macro GP32_BEGIN name
.p2align 4
.globl \name
.type \name,@function
\name:
.endm

GP32_BEGIN _start
    movl %esp, %esi
    call gp32_oracle
    testl %eax, %eax
    jnz 9f
    call gp32_materialize
    cmpl $7, %eax
    jne 9f
    cmpl %esi, %esp
    jne 9f
    call gp32_literal
    cmpl $gp32_target, %eax
    jne 9f
    cmpl %esi, %esp
    jne 9f
    call gp32_reg
    cmpl $7, %eax
    jne 9f
    cmpl %esi, %esp
    jne 9f
    call gp32_mem
    cmpl $7, %eax
    jne 9f
    cmpl %esi, %esp
    jne 9f
    call gp32_call
    cmpl $7, %eax
    jne 9f
    cmpl %esi, %esp
    jne 9f
    call gp32_next
    cmpl $7, %eax
    jne 9f
    cmpl %esi, %esp
    jne 9f
    xorl %ebx, %ebx
    jmp 8f
9:  movl $1, %ebx
8:  movl $1, %eax
    int $0x80

// Check the 32-bit PUSH-next address, net SP delta and defined arithmetic flags.
GP32_BEGIN gp32_oracle
    movl %esp, %edx
    stc
    pushfl
    popl %ecx
    pushl $1f
1:  popl %eax
    pushfl
    popl %ebx
    cmpl %edx, %esp
    jne 2f
    cmpl $1b, %eax
    jne 2f
    xorl %ecx, %ebx
    testl $0x8d5, %ebx
    jne 2f
    xorl %eax, %eax
    ret
2:  movl $1, %eax
    ret

GP32_BEGIN gp32_target
#ifdef GP32_NEGATIVE_CONTROL
    movl $8, %eax
#else
    movl $7, %eax
#endif
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
.section .note.GNU-stack,"",@progbits
