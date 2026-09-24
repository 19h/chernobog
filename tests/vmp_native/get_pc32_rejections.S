// Linux i386 execution oracle for stack transfers rejected by the IDA recognizer.
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

    movl $gp32_target7, %edi
    call gp32_unknown
    cmpl $7, %eax
    jne 9f
    cmpl %esi, %esp
    jne 9f
    movl $gp32_target8, %edi
    call gp32_unknown
    cmpl $8, %eax
    jne 9f
    cmpl %esi, %esp
    jne 9f

    movl $gp32_target7, gp32_rw
    call gp32_writable
    cmpl $7, %eax
    jne 9f
    cmpl %esi, %esp
    jne 9f
    movl $gp32_target8, gp32_rw
    call gp32_writable
    cmpl $8, %eax
    jne 9f
    cmpl %esi, %esp
    jne 9f

    xorl %edi, %edi
    call gp32_alternate
    cmpl $7, %eax
    jne 9f
    cmpl %esi, %esp
    jne 9f
    movl $1, %edi
    movl $42, %eax
    call gp32_alternate
    cmpl $42, %eax
    jne 9f
    cmpl %esi, %esp
    jne 9f

    // RET 4 skips the CALL return address. The target's RET consumes the
    // supplied continuation, leaving one marker word for this caller.
    pushl $0x13579bdf
    pushl $1f
    call gp32_extra
1:  cmpl $0x13579bdf, (%esp)
    jne 9f
    addl $4, %esp
    cmpl $7, %eax
    jne 9f
    cmpl %esi, %esp
    jne 9f

    xorl %ebx, %ebx
    jmp 8f
9:  movl $1, %ebx
8:  movl $1, %eax
    int $0x80

GP32_BEGIN gp32_target7
    movl $7, %eax
    ret

GP32_BEGIN gp32_target8
#ifdef GP32_NEGATIVE_CONTROL
    movl $9, %eax
#else
    movl $8, %eax
#endif
    ret

GP32_BEGIN gp32_unknown
    pushl %edi
    ret

GP32_BEGIN gp32_writable
    pushl gp32_rw
    ret

GP32_BEGIN gp32_alternate
    testl %edi, %edi
    jnz 2f
    pushl $gp32_target7
2:  ret

GP32_BEGIN gp32_extra
    pushl $gp32_target7
    ret $4

.data
.p2align 2
gp32_rw:
    .long gp32_target7
.section .note.GNU-stack,"",@progbits
