/* Independent branch/join/loop fixtures for the owned native must-analysis. */
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
#ifdef __i386__
    movl 4(%esp), %ecx
#else
    movl %edi, %ecx
#endif
.endm
.macro RESULT condition
    \condition %al
    movzbl %al, %eax
    ret
.endm

BEGIN NAME(df_equal)
    testl %ecx, %ecx
    jz 1f
    movl $42, %eax
    jmp 2f
1:  movl $42, %eax
2:  cmpl $42, %eax
    RESULT sete

BEGIN NAME(df_different)
    testl %ecx, %ecx
    jz 1f
    movl $41, %eax
    jmp 2f
1:  movl $42, %eax
2:  cmpl $42, %eax
    RESULT sete

BEGIN NAME(df_flags)
    testl %ecx, %ecx
    jz 1f
    stc
    jmp 2f
1:  stc
2:  RESULT setb

BEGIN NAME(df_direction)
    testl %ecx, %ecx
    jz 1f
    stc
    std
    cld
    jmp 2f
1:  stc
    std
    cld
2:  RESULT setb

/* Native status-bit oracle: compare all six modeled flags around STD and CLD. */
BEGIN NAME(df_direction_status)
    testl $1, %ecx
    jz 1f
    subl $0x55, %ecx
    jmp 2f
1:  subl $0x80000000, %ecx
2:
#ifdef __i386__
    pushfl
    popl %eax
    std
    pushfl
    popl %edx
    cld
    pushfl
    popl %ecx
#else
    pushfq
    popq %rax
    std
    pushfq
    popq %rdx
    cld
    pushfq
    popq %rcx
#endif
    xorl %eax, %edx
    xorl %eax, %ecx
    orl %ecx, %edx
    andl $0x8d5, %edx
    movl %edx, %eax
    ret

BEGIN NAME(df_loop)
    stc
1:  decl %ecx
    jnz 1b
    RESULT setb

BEGIN NAME(df_loop_changes)
    stc
1:  cmc
    decl %ecx
    jnz 1b
    RESULT setb

BEGIN NAME(df_stack)
    testl %ecx, %ecx
    jz 1f
    push $7
    jmp 2f
1:  push $7
2:
#ifdef __i386__
    pop %eax
#else
    pop %rax
#endif
    cmpl $7, %eax
    RESULT sete

BEGIN NAME(df_stack_changes)
    testl %ecx, %ecx
    jz 1f
    push $8
    jmp 2f
1:  push $7
2:
#ifdef __i386__
    pop %eax
#else
    pop %rax
#endif
    cmpl $7, %eax
    RESULT sete

BEGIN NAME(df_jump)
    xorl %eax, %eax
    jmp 1f
    int3
1:  RESULT sete

BEGIN NAME(df_external)
    ret

BEGIN NAME(df_target)
    testl %ecx, %ecx
    jz 1f
#ifdef __i386__
    leal 3f, %eax
#else
    leaq 3f(%rip), %rax
#endif
    jmp 2f
1:
#ifdef __i386__
    leal 3f, %eax
#else
    leaq 3f(%rip), %rax
#endif
2:
#ifdef __i386__
    push %eax
#else
    push %rax
#endif
    ret
3:  movl $7, %eax
    ret

BEGIN NAME(df_target_changes)
    testl %ecx, %ecx
    jz 1f
#ifdef __i386__
    leal 3f, %eax
#else
    leaq 3f(%rip), %rax
#endif
    jmp 2f
1:
#ifdef __i386__
    leal 4f, %eax
#else
    leaq 4f(%rip), %rax
#endif
2:
#ifdef __i386__
    push %eax
#else
    push %rax
#endif
    ret
3:  movl $7, %eax
    ret
4:  movl $9, %eax
    ret

/* The probe assigns the remote body as a tail of df_flow_root. The CLC
 * immediately before that tail is deliberately outside its owned graph. */
.p2align 4
.globl NAME(df_flow_root)
NAME(df_flow_root):
    stc
    jmp NAME(df_flow_tail)
.globl NAME(df_flow_root_end)
NAME(df_flow_root_end):
    int3
.p2align 4
.globl NAME(df_flow_external)
NAME(df_flow_external):
    clc
.globl NAME(df_flow_tail)
NAME(df_flow_tail):
    setb %al
.globl NAME(df_flow_branch)
NAME(df_flow_branch):
    jb NAME(df_flow_taken)
    movl $0, %eax
    ret
.globl NAME(df_flow_taken)
NAME(df_flow_taken):
    movl $1, %eax
    ret
.globl NAME(df_flow_tail_end)
NAME(df_flow_tail_end):
    int3

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
