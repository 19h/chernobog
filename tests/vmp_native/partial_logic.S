/* Immediate logical operations on partially known register values. */
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
#ifdef __i386__
    movl 4(%esp), %ecx
#else
    movl %edi, %ecx
#endif
.endm
.macro RETURN_Z
    setz %al
    movzbl %al, %eax
    ret
.endm
.macro RETURN_NZ
    setnz %al
    movzbl %al, %eax
    ret
.endm

BEGIN NAME(pl_or_chain)
    andl $1, %ecx
    orl $2, %ecx
    andl $2, %ecx
    cmpl $2, %ecx
    RETURN_Z

BEGIN NAME(pl_xor_chain)
    andl $1, %ecx
    xorl $2, %ecx
    andl $2, %ecx
    cmpl $2, %ecx
    RETURN_Z

BEGIN NAME(pl_or_flags)
    andl $1, %ecx
    orl $1, %ecx
    RETURN_NZ

BEGIN NAME(pl_or_unknown)
    andl $1, %ecx
    orl $2, %ecx
    testl $1, %ecx
    RETURN_NZ

BEGIN NAME(pl_xor_unknown)
    andl $1, %ecx
    xorl $2, %ecx
    testl $1, %ecx
    RETURN_NZ

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
