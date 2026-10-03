.text
.globl _main
.p2align 4
_main:
    call _rex_bswap_cf
    cmpl $1, %eax
    jne 1f
    call _rex_bswap_zf
    cmpl $1, %eax
    jne 1f
    xorl %eax, %eax
    retq
1:
    movl $1, %eax
    retq

.globl _rex_bswap_cf
.p2align 4
_rex_bswap_cf:
    movl $0x12345678, %r9d
    stc
    .byte 0x66, 0x41, 0x0f, 0xc9
.globl _rex_bswap_cf_use
_rex_bswap_cf_use:
    setc %al
    movzbl %al, %eax
    retq

.globl _rex_bswap_zf
.p2align 4
_rex_bswap_zf:
    movl $0x12345678, %r9d
    xorl %eax, %eax
    .byte 0x66, 0x41, 0x0f, 0xc9
.globl _rex_bswap_zf_use
_rex_bswap_zf_use:
    setz %al
    movzbl %al, %eax
    retq

.globl _rex_bswap_unknown
.p2align 4
_rex_bswap_unknown:
    movl $0x12345678, %r9d
    .byte 0x66, 0x41, 0x0f, 0xc9
.globl _rex_bswap_unknown_use
_rex_bswap_unknown_use:
    testw %r9w, %r9w
    setz %al
    movzbl %al, %eax
    retq
