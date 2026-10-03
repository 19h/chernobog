.text
.globl _main
.p2align 4
_main:
    callq _known_jump
    cmpl $7, %eax
    jne 1f
    leaq _target_seven(%rip), %rdi
    callq _unknown_jump
    cmpl $7, %eax
    jne 1f
    leaq _target_eight(%rip), %rdi
    callq _unknown_jump
    cmpl $8, %eax
    jne 1f
    leaq _target_seven(%rip), %rax
    movq %rax, _mutable_pointer(%rip)
    callq _memory_jump
    cmpl $7, %eax
    jne 1f
    leaq _target_eight(%rip), %rax
    movq %rax, _mutable_pointer(%rip)
    callq _memory_jump
    cmpl $8, %eax
    jne 1f
    xorl %eax, %eax
    retq
1:
    movl $1, %eax
    retq

.globl _known_jump
.p2align 4
_known_jump:
    leaq _target_seven(%rip), %r10
.globl _known_jump_site
_known_jump_site:
    jmpq *%r10

.globl _unknown_jump
.p2align 4
_unknown_jump:
    jmpq *%rdi

.globl _memory_jump
.p2align 4
_memory_jump:
    movq _mutable_pointer(%rip), %r10
.globl _memory_jump_site
_memory_jump_site:
    jmpq *%r10

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

.data
.globl _mutable_pointer
.p2align 3
_mutable_pointer:
    .quad _target_seven
