.section __TEXT,__text,regular,pure_instructions
.p2align 4
.globl _main
_main:
    pushq %rbx
    movq %rsp, %rbx
    pushfq
    popq %r9
    pushq $0x5a
    leaq _continuation(%rip), %r8
    pushq %r8
    callq _adjust
    ud2

_continuation:
    popq %rcx
    cmpq $0x5a, %rcx
    jne _failure
    cmpq %rbx, %rsp
    jne _failure
    cmpq $7, %rax
    jne _failure
    leaq _target(%rip), %r8
    cmpq %r8, -32(%rsp)
    jne _failure
    cmpq %r9, %r10
    jne _failure
    xorl %eax, %eax
    popq %rbx
    retq

_failure:
    movl $1, %eax
    popq %rbx
    retq

.p2align 4
.globl _adjust
_adjust:
    leaq _target(%rip), %rax
    pushq %rax
    retq $8

.p2align 4
.globl _target
_target:
    pushfq
    popq %r10
#ifdef RET_ADJUST_NEGATIVE
    movl $8, %eax
#else
    movl $7, %eax
#endif
    retq
.subsections_via_symbols
