.text
.globl _start
_start:
    call _known_jump
    cmpl $7, %eax
    jne 1f
    movl $_target_seven, %edi
    call _unknown_jump
    cmpl $7, %eax
    jne 1f
    movl $_target_eight, %edi
    call _unknown_jump
    cmpl $8, %eax
    jne 1f
    movl $_target_seven, _mutable_pointer
    call _memory_jump
    cmpl $7, %eax
    jne 1f
    movl $_target_eight, _mutable_pointer
    call _memory_jump
    cmpl $8, %eax
    jne 1f
    movl $1, %eax
    xorl %ebx, %ebx
    int $0x80
1:
    movl $1, %eax
    movl $1, %ebx
    int $0x80

.globl _known_jump
_known_jump:
    movl $_target_seven, %edi
.globl _known_jump_site
_known_jump_site:
    jmpl *%edi

.globl _unknown_jump
_unknown_jump:
    jmpl *%edi

.globl _memory_jump
_memory_jump:
    movl _mutable_pointer, %edi
.globl _memory_jump_site
_memory_jump_site:
    jmpl *%edi

.globl _target_seven
_target_seven:
    movl $7, %eax
    ret

.globl _target_eight
_target_eight:
    movl $8, %eax
    ret

.data
.globl _mutable_pointer
.p2align 2
_mutable_pointer:
    .long _target_seven

.section .note.GNU-stack,"",@progbits
