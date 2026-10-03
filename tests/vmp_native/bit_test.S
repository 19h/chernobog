/* BT, BTC, BTR, and BTS register and memory replay fixtures. */
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
.endm
.macro RESULT condition
    \condition %al
    movzbl %al, %eax
    ret
.endm

BEGIN NAME(main)
    xorl %eax, %eax
    ret

BEGIN NAME(bt_register_carry)
    movl $8, %eax
    btl $3, %eax
    RESULT setb

BEGIN NAME(bt_register_zero_preserved)
    xorl %edx, %edx
    movl $8, %eax
    btl $3, %eax
    RESULT sete

BEGIN NAME(bt_register_wrap)
    movl $8, %eax
    movl $35, %edx
    btl %edx, %eax
    RESULT setb

BEGIN NAME(bt_register_unknown_uniform)
    xorl %eax, %eax
    btl %edi, %eax
    RESULT setae

BEGIN NAME(btc_register)
    movl $8, %eax
    btcl $3, %eax
    cmpl $0, %eax
    RESULT sete

BEGIN NAME(btr_register)
    movl $8, %eax
    btrl $3, %eax
    cmpl $0, %eax
    RESULT sete

BEGIN NAME(bts_register)
    xorl %eax, %eax
    btsl $3, %eax
    cmpl $8, %eax
    RESULT sete

BEGIN NAME(btc_alias)
    movl $1, %eax
    btcl %eax, %eax
    cmpl $3, %eax
    RESULT sete

BEGIN NAME(bt_memory_carry)
    movl $8, NAME(bt_slot)(%rip)
    btl $3, NAME(bt_slot)(%rip)
    RESULT setb

BEGIN NAME(bts_memory_positive_index)
    movq $0, NAME(bt_slot)(%rip)
    movl $36, %edx
    btsl %edx, NAME(bt_slot)(%rip)
    movb NAME(bt_slot)+4(%rip), %al
    cmpb $16, %al
    RESULT sete

BEGIN NAME(bts_memory_negative_index)
    movq $0, NAME(bt_slot)(%rip)
    leaq NAME(bt_slot)+4(%rip), %rax
    movl $-1, %edx
    btsl %edx, (%rax)
    movb NAME(bt_slot)+3(%rip), %al
    cmpb $128, %al
    RESULT sete

BEGIN NAME(btr_memory_immediate)
    movl $8, NAME(bt_slot)(%rip)
    btrl $3, NAME(bt_slot)(%rip)
    movl NAME(bt_slot)(%rip), %eax
    cmpl $0, %eax
    RESULT sete

BEGIN NAME(bts_memory_high_immediate)
    movq $0, NAME(bt_slot)(%rip)
    leaq NAME(bt_slot)(%rip), %rax
    .byte 0x0f, 0xba, 0x28, 0x23
    movl NAME(bt_slot)(%rip), %eax
    cmpl $8, %eax
    RESULT sete

BEGIN NAME(btc_locked_memory)
    movl $8, NAME(bt_slot)(%rip)
    lock btcl $3, NAME(bt_slot)(%rip)
    movl NAME(bt_slot)(%rip), %eax
    cmpl $0, %eax
    RESULT sete

BEGIN NAME(bt_preserve_disjoint_memory)
    movl $7, NAME(bt_other_slot)(%rip)
    movl $8, NAME(bt_slot)(%rip)
    btsl $3, NAME(bt_slot)(%rip)
    movl NAME(bt_other_slot)(%rip), %eax
    cmpl $7, %eax
    RESULT sete

BEGIN NAME(bt_unknown_offset)
    movl $8, %eax
    btl %edi, %eax
    RESULT setb

BEGIN NAME(bts_unknown_memory_offset)
    movq $0, NAME(bt_slot)(%rip)
    btsl %edi, NAME(bt_slot)(%rip)
    movl NAME(bt_slot)(%rip), %eax
    cmpl $8, %eax
    RESULT sete

BEGIN NAME(bt_locked_register)
    movl $8, %eax
    .byte 0xf0, 0x0f, 0xba, 0xe0, 0x03
    RESULT setb

BEGIN NAME(bt_locked_memory)
    movl $8, NAME(bt_slot)(%rip)
    .byte 0xf0
    btl $3, NAME(bt_slot)(%rip)
    RESULT setb

.data
.p2align 3
NAME(bt_slot):
    .quad 0
NAME(bt_other_slot):
    .quad 0

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
