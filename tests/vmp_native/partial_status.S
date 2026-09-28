/* Status flags fixed by a partial logical result. */
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
.macro RETURN cc
    set\cc %al
    movzbl %al, %eax
    ret
.endm

BEGIN NAME(ps_or_nonzero)
    andl $1, %ecx
    orl $2, %ecx
    RETURN nz

BEGIN NAME(ps_or_sign)
    andl $1, %ecx
    orl $0x80000002, %ecx
    RETURN s

BEGIN NAME(ps_or_parity)
    andl $0x100, %ecx
    orl $3, %ecx
    RETURN p

BEGIN NAME(ps_xor_sign)
    andl $1, %ecx
    xorl $0x80000000, %ecx
    RETURN s

BEGIN NAME(ps_and_sign)
    andl $1, %ecx
    RETURN ns

BEGIN NAME(ps_test_zero)
    andl $1, %ecx
    testl $2, %ecx
    RETURN z

BEGIN NAME(ps_test_nonzero)
    andl $1, %ecx
    orl $2, %ecx
    testl $2, %ecx
    RETURN nz

BEGIN NAME(ps_test_same_sign)
    andl $1, %ecx
    testl %ecx, %ecx
    RETURN ns

BEGIN NAME(ps_or_unknown)
    andl $1, %ecx
    orl $2, %ecx
    RETURN p

BEGIN NAME(ps_test_unknown)
    andl $1, %ecx
    testl $1, %ecx
    RETURN nz

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
