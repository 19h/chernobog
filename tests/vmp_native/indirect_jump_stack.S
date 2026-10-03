.text
.globl _main
.p2align 4
_main:
    callq _known_stack_jump
    cmpl $7, %eax
    jne 1f
    callq _rexw_stack_jump
    cmpl $7, %eax
    jne 1f
    leaq _target_seven(%rip), %rdi
    callq _dynamic_stack_jump
    cmpl $7, %eax
    jne 1f
    leaq _target_eight(%rip), %rdi
    callq _dynamic_stack_jump
    cmpl $8, %eax
    jne 1f
    xorl %eax, %eax
    retq
1:
    movl $1, %eax
    retq

.globl _known_stack_jump
.p2align 4
_known_stack_jump:
    leaq _target_seven(%rip), %rax
    pushq %rax
.globl _known_stack_jump_site
_known_stack_jump_site:
    .byte 0xff, 0x24, 0x24

.globl _rexw_stack_jump
.p2align 4
_rexw_stack_jump:
    leaq _target_seven(%rip), %rax
    pushq %rax
.globl _rexw_stack_jump_site
_rexw_stack_jump_site:
    .byte 0x48, 0xff, 0x24, 0x24

.globl _dynamic_stack_jump
.p2align 4
_dynamic_stack_jump:
    pushq %rdi
.globl _dynamic_stack_jump_site
_dynamic_stack_jump_site:
    .byte 0xff, 0x24, 0x24

.globl _target_seven
.p2align 4
_target_seven:
    addq $8, %rsp
    movl $7, %eax
    retq

.globl _target_eight
.p2align 4
_target_eight:
    addq $8, %rsp
    movl $8, %eax
    retq
