.text
.globl _start
_start:
    call known_stack_jump
    cmpl $7, %eax
    jne fail
    movl $target_seven, %edi
    call dynamic_stack_jump
    cmpl $7, %eax
    jne fail
    movl $target_eight, %edi
    call dynamic_stack_jump
    cmpl $8, %eax
    jne fail
    movl $1, %eax
    xorl %ebx, %ebx
    int $0x80
fail:
    movl $1, %eax
    movl $1, %ebx
    int $0x80

.globl known_stack_jump
.p2align 4
known_stack_jump:
    pushl $target_seven
.globl known_stack_jump_site
known_stack_jump_site:
    .byte 0xff, 0x24, 0x24

.globl dynamic_stack_jump
.p2align 4
dynamic_stack_jump:
    pushl %edi
.globl dynamic_stack_jump_site
dynamic_stack_jump_site:
    .byte 0xff, 0x24, 0x24

.globl target_seven
.p2align 4
target_seven:
    addl $4, %esp
    movl $7, %eax
    ret

.globl target_eight
.p2align 4
target_eight:
    addl $4, %esp
    movl $8, %eax
    ret
