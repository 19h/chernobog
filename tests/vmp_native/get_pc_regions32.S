.code32
.text
.macro REGION name
.p2align 4
.globl \name
.type \name,@function
\name:
.endm

REGION gp32_backward_anchor
    ret
.Lbackward_body:
    popl %eax
    pushl %eax
    ret
REGION gp32_backward
    call .Lbackward_body
    movl $7, %eax
    ret

REGION gp32_nonzero
    call .Lnonzero_body
    leal 4(%esp), %esp
    movl $7, %eax
    ret
.Lnonzero_body:
    movl (%esp), %eax
    pushl %eax
    ret
.section .note.GNU-stack,"",@progbits
