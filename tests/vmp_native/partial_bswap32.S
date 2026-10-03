/* i386 partial BSWAP proofs with an input-dependent EAX value. */
.text
.p2align 4
.globl _start
_start:
    movl $1, %eax
    xorl %ebx, %ebx
    int $0x80

.macro BEGIN name
.p2align 4
.globl \name
\name:
.endm
.macro RESULT condition
    \condition %al
    movzbl %al, %eax
    ret
.endm

BEGIN bswap32_masked_byte
    movl 4(%esp), %eax
    andl $0xffffff00, %eax
    bswapl %eax
    btl $24, %eax
    RESULT setae

BEGIN bswap32_known_one
    movl 4(%esp), %eax
    btsl $31, %eax
    bswapl %eax
    btl $7, %eax
    RESULT setb

BEGIN bswap32_flags
    stc
    movl 4(%esp), %eax
    bswapl %eax
    RESULT setb

BEGIN bswap32_unknown
    movl 4(%esp), %eax
    bswapl %eax
    cmpl $0, %eax
    RESULT sete

.section .note.GNU-stack,"",@progbits
