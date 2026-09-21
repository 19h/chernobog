// Independent instruction fixtures. Only positive cases are executed.
.section __TEXT,__text,regular,pure_instructions
.macro GP_BEGIN name
.p2align 4
.globl _\name
_\name:
.endm
.macro GP_LABEL name
L\name:
.endm

GP_BEGIN main
    subq $8, %rsp
    callq _gp_oracle
    testl %eax, %eax
    jnz 1f
    callq _gp_materialize
    cmpl $7, %eax
    jne 2f
    callq _gp_renamed
    cmpl $7, %eax
    jne 2f
    callq _gp_restore
    cmpl $7, %eax
    jne 2f
    callq _gp_read
    cmpl $7, %eax
    jne 2f
    callq _gp_call
    cmpl $7, %eax
    jne 2f
    callq _gp_sign8
    cmpl $1, %eax
    jne 2f
    callq _gp_sign32
    cmpl $1, %eax
    jne 2f
    xorl %eax, %eax
1:  addq $8, %rsp
    retq
2:  movl $1, %eax
    jmp 1b

// Check register restoration, materialized value, SP and defined flags against
// actual x86-64 execution. Capture the written slot before any further PUSH.
GP_BEGIN gp_oracle
    movq %rsp, %r8
    movabsq $0x13579bdf2468ace0, %rax
    movq %rax, %r9
    xorl %ecx, %ecx
    stc
    pushfq
    popq %r10
    pushq %rax
    leaq 3f(%rip), %rax
    xchgq %rax, (%rsp)
3:  movq (%rsp), %r11
    popq %rcx
    pushfq
    popq %rdx
    cmpq %r8, %rsp
    jne 4f
    cmpq %r9, %rax
    jne 4f
    leaq 3b(%rip), %r9
    cmpq %r9, %rcx
    jne 4f
    cmpq %r9, %r11
    jne 4f
    xorq %r10, %rdx
    testq $0x8d5, %rdx
    jnz 4f
    xorl %eax, %eax
    retq
4:  movl $2, %eax
    retq

GP_BEGIN gp_target
    movl $7, %eax
    retq

GP_BEGIN gp_sign8
    pushq $-1
    popq %rax
    cmpq $-1, %rax
    sete %al
    movzbl %al, %eax
    retq

GP_BEGIN gp_sign32
    .byte 0x68
    .long 0x80000000
    popq %rax
    movabsq $-2147483648, %rcx
    cmpq %rcx, %rax
    sete %al
    movzbl %al, %eax
    retq

GP_BEGIN gp_materialize
    pushq %rax
GP_LABEL gp_materialize_lea
    leaq _gp_target(%rip), %rax
GP_LABEL gp_materialize_xchg
    xchgq %rax, (%rsp)
    popq %rcx
    pushq %rcx
GP_LABEL gp_materialize_ret
    retq

GP_BEGIN gp_renamed
    pushq %r11
    leaq _gp_target(%rip), %r11
    xchgq %r11, (%rsp)
    popq %r10
    pushq %r10
GP_LABEL gp_renamed_ret
    retq

GP_BEGIN gp_restore
    leaq _gp_target(%rip), %rax
GP_LABEL gp_restore_push
    pushq %rax
    leaq _gp_target(%rip), %rax
    xchgq %rax, (%rsp)
    popq %rcx
    pushq %rax
GP_LABEL gp_restore_ret
    retq

GP_BEGIN gp_read
    pushq %rax
    leaq _gp_target(%rip), %rax
    xchgq %rax, (%rsp)
    movq (%rsp), %rcx
    popq %rdx
    pushq %rcx
GP_LABEL gp_read_ret
    retq

GP_BEGIN gp_alias
    pushq %rax
    leaq _gp_target(%rip), %rax
    xchgq %rax, (%rsp)
    movq %rsi, (%rdi)
    popq %rcx
    pushq %rcx
GP_LABEL gp_alias_ret
    retq

GP_BEGIN gp_spwrite
    pushq %rax
    leaq _gp_target(%rip), %rax
    xchgq %rax, (%rsp)
    leaq 8(%rsp), %rsp
    popq %rcx
    pushq %rcx
GP_LABEL gp_spwrite_ret
    retq

GP_BEGIN gp_wrongreg
    pushq %rax
    leaq _gp_target(%rip), %rax
    xchgq %rcx, (%rsp)
    retq

GP_BEGIN gp_offset
    pushq %rax
    leaq _gp_target(%rip), %rax
    xchgq %rax, 8(%rsp)
    retq

GP_BEGIN gp_indexed
    pushq %rax
    leaq _gp_target(%rip), %rax
    xchgq %rax, (%rsp,%rdi,8)
    retq

GP_BEGIN gp_segment
    pushq %rax
    leaq _gp_target(%rip), %rax
    xchgq %rax, %gs:(%rsp)
    retq

GP_BEGIN gp_width
    pushw %ax
    leaq _gp_target(%rip), %rax
    xchgq %rax, (%rsp)
    retq

GP_BEGIN gp_partial
    pushq %rax
    leaq _gp_target(%rip), %rax
    xchgl %eax, (%rsp)
    retq

GP_BEGIN gp_stackreg
    pushq %rsp
    leaq _gp_target(%rip), %rsp
    xchgq %rsp, (%rsp)
    retq

GP_BEGIN gp_call
    callq Lgp_call_entry
GP_LABEL gp_call_resume
    movl $7, %eax
    retq
GP_LABEL gp_call_entry
    popq %r11
    pushq %r11
GP_LABEL gp_call_ret
    retq

GP_BEGIN gp_adjust
    callq Lgp_adjust_entry
    .byte 0xcc, 0xcc, 0xcc
GP_LABEL gp_adjust_resume
    movl $7, %eax
    retq
GP_LABEL gp_adjust_entry
    addq $3, (%rsp)
GP_LABEL gp_adjust_ret
    retq

GP_BEGIN gp_next
    callq Lgp_next_entry
GP_LABEL gp_next_entry
    popq %r10
    jmp _gp_target

// Rejected extended call-context summaries, decoded but never executed.
.macro GP_BAD name
GP_BEGIN \name
    callq 5f
    retq
5:  popq %rax
    pushq %rax
.endm
GP_BAD gp_ret_extra
    retq $8
GP_BAD gp_ret_far
    .byte 0xcb
GP_BAD gp_ret_width
    .byte 0x66, 0xc3

GP_BEGIN gp_popsp
    callq 6f
    retq
6:  popq %rsp
    jmp _gp_target

GP_BEGIN gp_call_alias
    callq 7f
    retq
7:  movq (%rsp), %rax
    movq %rsi, (%rdi)
    retq

GP_BEGIN gp_call_xchgsp
    callq 8f
    retq
8:  popq %rax
    xchgq %rax, %rsp
    pushq %rax
    retq

.subsections_via_symbols
