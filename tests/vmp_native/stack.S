.section __TEXT,__text,regular,pure_instructions
.macro VT_BEGIN name
.p2align 4
.globl _\name
_\name:
.endm

VT_BEGIN main
    subq $8, %rsp
    callq _vt_reg
    cmpl $7, %eax
    jne 1f
    callq _vt_mem
    cmpl $7, %eax
    jne 1f
    callq _vt_indexed
    cmpl $7, %eax
    jne 1f
    xorl %eax, %eax
    addq $8, %rsp
    retq
1:
    movl $1, %eax
    addq $8, %rsp
    retq

VT_BEGIN vt_target
    movl $7, %eax
    retq

VT_BEGIN vt_reg
    leaq _vt_target(%rip), %rax
    pushq %rax
    retq

VT_BEGIN vt_mem
    pushq _vt_ro(%rip)
    retq

VT_BEGIN vt_indexed
    leaq _vt_ro(%rip), %rax
    xorl %ecx, %ecx
    pushq (%rax,%rcx,8)
    retq

VT_BEGIN vt_unknown_reg
    pushq %rdi
    retq

VT_BEGIN vt_alias
    leaq _vt_target(%rip), %rax
    movb %dl, %ah
    pushq %rax
    retq

VT_BEGIN vt_writable
    pushq _vt_rw(%rip)
    retq

VT_BEGIN vt_unknown_index
    leaq _vt_ro(%rip), %rax
    pushq (%rax,%rdi,8)
    retq

VT_BEGIN vt_load_writable
    movq _vt_rw(%rip), %rax
    pushq %rax
    retq

VT_BEGIN vt_adjust
    leaq _vt_target(%rip), %rax
    pushq %rax
    retq $8

VT_BEGIN vt_far
    leaq _vt_target(%rip), %rax
    pushq %rax
    .byte 0xcb

VT_BEGIN vt_width
    leaq _vt_target(%rip), %rax
    pushw %ax
    retq

VT_BEGIN vt_alternate
    testl %edi, %edi
    jnz 2f
    leaq _vt_target(%rip), %rax
    pushq %rax
2:
    retq

.section __TEXT,__const
.p2align 3
_vt_ro:
    .quad _vt_target
.section __DATA,__data
.p2align 3
_vt_rw:
    .quad _vt_target
.subsections_via_symbols
