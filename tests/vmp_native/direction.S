/* x86-64 DF definitions, saved flags, and joins before bounded REP memory. */
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

/* Initialize every observed byte inside the replay, after any stack operation. */
.macro MEMORY
    leaq NAME(direction_source)+8(%rip), %rsi
    leaq NAME(direction_dest)+8(%rip), %rdi
    movabsq $(0x1817161514131211), %rax
    movq %rax, -8(%rsi)
    movabsq $(0x2827262524232221), %rax
    movq %rax, (%rsi)
    movabsq $(0x9999999999999999), %rax
    movq %rax, -8(%rdi)
    movq %rax, (%rdi)
    movl $(2), %ecx
.endm

.macro FINISH value
    cmpb $\value, NAME(direction_dest)+9(%rip)
    sete %al
    cld
    movzbl %al, %eax
    ret
.endm

BEGIN NAME(direction_forward)
    cld
    MEMORY
    rep movsb
    FINISH 0x22

BEGIN NAME(direction_reverse)
    std
    MEMORY
    rep movsb
    FINISH 0x22

BEGIN NAME(direction_saved_forward)
    cld
    pushfq
    std
    popfq
    MEMORY
    rep movsb
    FINISH 0x22

BEGIN NAME(direction_saved_reverse)
    std
    pushfq
    cld
    popfq
    MEMORY
    rep movsb
    FINISH 0x22

BEGIN NAME(direction_literal_reverse)
    pushq $0x400
    popfq
    MEMORY
    rep movsb
    FINISH 0x22

BEGIN NAME(direction_unknown_pop)
    cld
    pushq %rdi
    popfq
    MEMORY
    rep movsb
    FINISH 0x22

BEGIN NAME(direction_unknown)
    MEMORY
    rep movsb
    FINISH 0x22

BEGIN NAME(direction_prefixed)
    .byte 0x66, 0xfc
    MEMORY
    rep movsb
    FINISH 0x22

BEGIN NAME(direction_join_equal)
    testl %edi, %edi
    jz 1f
    cld
    jmp 2f
1:  cld
2:  MEMORY
    rep movsb
    FINISH 0x22

BEGIN NAME(direction_join_conflict)
    testl %edi, %edi
    jz 1f
    cld
    jmp 2f
1:  std
2:  MEMORY
    rep movsb
    FINISH 0x22

BEGIN NAME(direction_stos_forward)
    cld
    MEMORY
    movb $(0x5a), %al
    rep stosb
    FINISH 0x5a

BEGIN NAME(direction_stos_reverse)
    std
    MEMORY
    movb $0x5a, %al
    rep stosb
    FINISH 0x5a

.data
.p2align 4
.globl NAME(direction_source)
NAME(direction_source):
    .space 16
.globl NAME(direction_dest)
NAME(direction_dest):
    .space 16

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
