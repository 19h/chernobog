/* Two-register logical operations with partial destination facts. */
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
.macro BEGIN2 name
.p2align 4
.globl \name
\name:
#ifdef __i386__
    movl 4(%esp), %ecx
    movl 8(%esp), %edx
#else
    movl %edi, %ecx
    movl %esi, %edx
#endif
.endm
.macro RETURN cc
    set\cc %al
    movzbl %al, %eax
    ret
.endm

BEGIN NAME(rl_and_zero)
    andl $1, %ecx
    movl $2, %edx
    andl %edx, %ecx
    RETURN z

BEGIN NAME(rl_or_nonzero)
    andl $1, %ecx
    movl $2, %edx
    orl %edx, %ecx
    RETURN nz

BEGIN NAME(rl_xor_sign)
    andl $1, %ecx
    movl $0x80000000, %edx
    xorl %edx, %ecx
    RETURN s

BEGIN NAME(rl_test_zero)
    andl $1, %ecx
    movl $2, %edx
    testl %edx, %ecx
    RETURN z

BEGIN NAME(rl_test_nonzero)
    andl $1, %ecx
    orl $2, %ecx
    movl $2, %edx
    testl %edx, %ecx
    RETURN nz

BEGIN NAME(rl_and_chain)
    andl $1, %ecx
    movl $2, %edx
    andl %edx, %ecx
    cmpl $0, %ecx
    RETURN z

BEGIN NAME(rl_or_chain)
    andl $1, %ecx
    movl $2, %edx
    orl %edx, %ecx
    andl $2, %ecx
    cmpl $2, %ecx
    RETURN z

BEGIN NAME(rl_xor_chain)
    andl $1, %ecx
    movl $2, %edx
    xorl %edx, %ecx
    andl $2, %ecx
    cmpl $2, %ecx
    RETURN z

BEGIN NAME(rl_self_and)
    andl $1, %ecx
    andl %ecx, %ecx
    RETURN ns

BEGIN NAME(rl_self_xor)
    andl $1, %ecx
    xorl %ecx, %ecx
    RETURN z

BEGIN NAME(rl_test_unknown)
    andl $1, %ecx
    movl $1, %edx
    testl %edx, %ecx
    RETURN nz

BEGIN NAME(rl_or_unknown)
    andl $1, %ecx
    movl $2, %edx
    orl %edx, %ecx
    RETURN p

BEGIN2 NAME(rl_two_and)
    andl $1, %ecx
    andl $2, %edx
    andl %edx, %ecx
    RETURN z

BEGIN2 NAME(rl_two_or)
    orl $1, %ecx
    orl $2, %edx
    orl %edx, %ecx
    RETURN nz

BEGIN2 NAME(rl_two_xor)
    andl $1, %ecx
    andl $2, %edx
    xorl %edx, %ecx
    RETURN ns

BEGIN2 NAME(rl_two_test)
    andl $1, %ecx
    andl $2, %edx
    testl %edx, %ecx
    RETURN z

BEGIN2 NAME(rl_two_test_unknown)
    andl $1, %ecx
    andl $1, %edx
    testl %edx, %ecx
    RETURN nz

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
