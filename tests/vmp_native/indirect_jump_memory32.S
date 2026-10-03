.text
.globl _start
_start:
    call known_memory_jump
    cmpl $7, %eax
    jne fail
    movl $target_seven, %edi
    call dynamic_memory_jump
    cmpl $7, %eax
    jne fail
    movl $target_eight, %edi
    call dynamic_memory_jump
    cmpl $8, %eax
    jne fail
    movl $1, %eax
    xorl %ebx, %ebx
    int $0x80
fail:
    movl $1, %eax
    movl $1, %ebx
    int $0x80

.globl known_memory_jump
.p2align 4
known_memory_jump:
    movl $target_seven, mutable_pointer
.globl known_memory_jump_site
known_memory_jump_site:
    jmp *mutable_pointer

.globl dynamic_memory_jump
.p2align 4
dynamic_memory_jump:
    movl %edi, mutable_pointer
.globl dynamic_memory_jump_site
dynamic_memory_jump_site:
    jmp *mutable_pointer

.globl target_seven
.p2align 4
target_seven:
    movl $7, %eax
    ret

.globl target_eight
.p2align 4
target_eight:
    movl $8, %eax
    ret

.data
.globl mutable_pointer
.p2align 2
mutable_pointer:
    .long target_seven
