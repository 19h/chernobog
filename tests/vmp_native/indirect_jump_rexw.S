.text
.globl _main
.p2align 4
_main:
    callq _rexw_rax
    cmpl $7, %eax
    jne 1f
    callq _rexw_r8
    cmpl $8, %eax
    jne 1f
    callq _rexw_rx_r8
    cmpl $7, %eax
    jne 1f
    leaq _target_seven(%rip), %rdi
    callq _dynamic_rexw
    cmpl $7, %eax
    jne 1f
    leaq _target_eight(%rip), %rdi
    callq _dynamic_rexw
    cmpl $8, %eax
    jne 1f
    xorl %eax, %eax
    retq
1:
    movl $1, %eax
    retq

.globl _rexw_rax
.p2align 4
_rexw_rax:
    leaq _target_seven(%rip), %rax
.globl _rexw_rax_site
_rexw_rax_site:
    .byte 0x48, 0xff, 0xe0

.globl _rexw_r8
.p2align 4
_rexw_r8:
    leaq _target_eight(%rip), %r8
.globl _rexw_r8_site
_rexw_r8_site:
    .byte 0x49, 0xff, 0xe0

.globl _rexw_rx_r8
.p2align 4
_rexw_rx_r8:
    leaq _target_seven(%rip), %r8
.globl _rexw_rx_r8_site
_rexw_rx_r8_site:
    .byte 0x4f, 0xff, 0xe0

.globl _dynamic_rexw
.p2align 4
_dynamic_rexw:
.globl _dynamic_rexw_site
_dynamic_rexw_site:
    .byte 0x48, 0xff, 0xe7

.globl _target_seven
.p2align 4
_target_seven:
    movl $7, %eax
    retq

.globl _target_eight
.p2align 4
_target_eight:
    movl $8, %eax
    retq
