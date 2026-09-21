.section __TEXT,__text,regular,pure_instructions
.macro REGION name
.p2align 4
.globl _\name
_\name:
.endm

REGION main
    subq $8, %rsp
    callq _gp_call
    cmpl $7, %eax
    jne 1f
    callq _gp_adjust
    cmpl $7, %eax
    jne 1f
    callq _gp_backward
    cmpl $7, %eax
    jne 1f
    callq _gp_nonzero
    cmpl $7, %eax
    jne 1f
    xorl %eax, %eax
    addq $8, %rsp
    retq
1:  movl $1, %eax
    addq $8, %rsp
    retq

REGION gp_backward_anchor
    retq
Lbackward_body:
    popq %r11
    pushq %r11
    retq
REGION gp_backward
    callq Lbackward_body
    movl $7, %eax
    retq

REGION gp_nonzero
    callq Lnonzero_body
    leaq 8(%rsp), %rsp
    movl $7, %eax
    retq
Lnonzero_body:
    movq (%rsp), %r11
    pushq %r11
    retq
.subsections_via_symbols
