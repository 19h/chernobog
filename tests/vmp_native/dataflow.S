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

BEGIN NAME(df_flags_saved)
    stc
#ifdef __i386__
    pushfl
#else
    pushfq
#endif
    clc
#ifdef __i386__
    popfl
#else
    popfq
#endif
    RESULT setb

BEGIN NAME(df_flags_full)
    movl $0x7fffffff, %eax
    addl $1, %eax
#ifdef __i386__
    pushfl
#else
    pushfq
#endif
    xorl %eax, %eax
#ifdef __i386__
    popfl
#else
    popfq
#endif
    RESULT seto

BEGIN NAME(df_flags_status)
    movl %ecx, %eax
    subl $0x55, %eax
#ifdef __i386__
    pushfl
    popl %edx
    pushfl
#else
    pushfq
    popq %rdx
    pushfq
#endif
    clc
#ifdef __i386__
    popfl
    pushfl
    popl %eax
#else
    popfq
    pushfq
    popq %rax
#endif
    xorl %edx, %eax
    andl $0x8d5, %eax
    ret

BEGIN NAME(df_flags_literal)
    push $1
#ifdef __i386__
    popfl
#else
    popfq
#endif
    RESULT setb

BEGIN NAME(df_flags_overwrite)
    stc
#ifdef __i386__
    pushfl
    movl $0, (%esp)
#else
    pushfq
    movq $0, (%rsp)
#endif
    clc
#ifdef __i386__
    popfl
#else
    popfq
#endif
    RESULT setb

BEGIN NAME(df_flags_dynamic)
    andl $1, %ecx
#ifdef __i386__
    pushl %ecx
    popfl
#else
    pushq %rcx
    popfq
#endif
    RESULT setb

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

/* The second PUSH reads the prior top word before decrementing SP. The
 * destination discards that prior word before returning to the C caller. */
BEGIN NAME(df_stack_top_transfer)
#ifdef __i386__
    movl $NAME(df_stack_top_destination), %eax
    pushl %eax
#else
    leaq NAME(df_stack_top_destination)(%rip), %rax
    pushq %rax
#endif
#ifdef __i386__
    pushl (%esp)
#else
    pushq (%rsp)
#endif
    ret
.p2align 4
.globl NAME(df_stack_top_destination)
NAME(df_stack_top_destination):
#ifdef __i386__
    addl $4, %esp
#else
    addq $8, %rsp
#endif
    movl $7, %eax
    ret

BEGIN NAME(df_stack_top_overwrite)
#ifdef __i386__
    movl $NAME(df_stack_top_other), %eax
    pushl %eax
    movl $NAME(df_stack_top_overwritten_destination), %eax
    movl %eax, (%esp)
#else
    leaq NAME(df_stack_top_other)(%rip), %rax
    pushq %rax
    leaq NAME(df_stack_top_overwritten_destination)(%rip), %rax
    movq %rax, (%rsp)
#endif
#ifdef __i386__
    pushl (%esp)
#else
    pushq (%rsp)
#endif
    ret
.p2align 4
.globl NAME(df_stack_top_other)
NAME(df_stack_top_other):
#ifdef __i386__
    addl $4, %esp
#else
    addq $8, %rsp
#endif
    movl $7, %eax
    ret
.p2align 4
.globl NAME(df_stack_top_overwritten_destination)
NAME(df_stack_top_overwritten_destination):
#ifdef __i386__
    addl $4, %esp
#else
    addq $8, %rsp
#endif
    movl $8, %eax
    ret

BEGIN NAME(df_stack_top_dynamic)
    testl %ecx, %ecx
    jz 1f
#ifdef __i386__
    movl $NAME(df_stack_top_dynamic_eight), %eax
#else
    leaq NAME(df_stack_top_dynamic_eight)(%rip), %rax
#endif
    jmp 2f
1:
#ifdef __i386__
    movl $NAME(df_stack_top_dynamic_seven), %eax
#else
    leaq NAME(df_stack_top_dynamic_seven)(%rip), %rax
#endif
2:
#ifdef __i386__
    pushl %eax
    pushl (%esp)
#else
    pushq %rax
    pushq (%rsp)
#endif
    ret
.p2align 4
.globl NAME(df_stack_top_dynamic_seven)
NAME(df_stack_top_dynamic_seven):
#ifdef __i386__
    addl $4, %esp
#else
    addq $8, %rsp
#endif
    movl $7, %eax
    ret
.p2align 4
.globl NAME(df_stack_top_dynamic_eight)
NAME(df_stack_top_dynamic_eight):
#ifdef __i386__
    addl $4, %esp
#else
    addq $8, %rsp
#endif
    movl $8, %eax
    ret

/* The writable slot starts unknown to analysis. Each transfer establishes
 * its address and value with a local store before the memory-source PUSH. */
BEGIN NAME(df_memory_store_transfer)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_direct_store)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl %eax, NAME(df_memory_slot)
    pushl NAME(df_memory_slot)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    movq %rax, NAME(df_memory_slot)(%rip)
    pushq NAME(df_memory_slot)(%rip)
#endif
    ret

/* Build a pointer from two narrower stores. The source register is shifted
 * between stores; no initial byte of the writable slot is used. */
BEGIN NAME(df_memory_split_store)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movw %ax, (%edx)
    shrl $16, %eax
    movw %ax, 2(%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movl %eax, (%rdx)
    shrq $32, %rax
    movl %eax, 4(%rdx)
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_known_byte_overwrite)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    shrl $8, %eax
    movb %al, 1(%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    shrq $8, %rax
    movb %al, 1(%rdx)
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_repaired_byte)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movb 1(%edx), %cl
    movb %cl, 1(%edx)
    shrl $8, %eax
    movb %al, 1(%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    movb 1(%rdx), %cl
    movb %cl, 1(%rdx)
    shrq $8, %rax
    movb %al, 1(%rdx)
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_missing_byte)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_initial_slot), %edx
    movb %al, (%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_initial_slot)(%rip), %rdx
    movb %al, (%rdx)
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_conflicting_byte)
#ifdef __i386__
    movl $NAME(df_memory_byte_target_seven), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
#else
    leaq NAME(df_memory_byte_target_seven)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
#endif
    testl %ecx, %ecx
    jz 1f
#ifdef __i386__
    movl $NAME(df_memory_byte_target_eight), %eax
#else
    leaq NAME(df_memory_byte_target_eight)(%rip), %rax
#endif
1:
#ifdef __i386__
    movb %al, (%edx)
    pushl (%edx)
#else
    movb %al, (%rdx)
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_initial_word)
#ifdef __i386__
    movl $NAME(df_memory_initial_slot), %edx
    pushl (%edx)
#else
    leaq NAME(df_memory_initial_slot)(%rip), %rdx
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_equal_stores)
#ifdef __i386__
    movl $NAME(df_memory_slot), %edx
#else
    leaq NAME(df_memory_slot)(%rip), %rdx
#endif
    testl %ecx, %ecx
    jz 1f
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl %eax, (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    movq %rax, (%rdx)
#endif
    jmp 2f
1:
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl %eax, (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    movq %rax, (%rdx)
#endif
2:
#ifdef __i386__
    pushl (%edx)
#else
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_disjoint_store)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl $0, 8(%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    movq $0, 8(%rdx)
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_overlapping_store)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movb 1(%edx), %cl
    movb %cl, 1(%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    movb 1(%rdx), %cl
    movb %cl, 1(%rdx)
    pushq (%rdx)
#endif
    ret

/* The second argument is disjoint at execution time; its entry value is
 * unknown to static analysis and therefore may alias the pointer slot. */
BEGIN NAME(df_memory_unknown_alias)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl 8(%esp), %ecx
    movl $0, (%ecx)
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    movq $0, (%rsi)
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_conflicting_store)
    testl %ecx, %ecx
    jz 1f
#ifdef __i386__
    movl $NAME(df_memory_target_eight), %eax
#else
    leaq NAME(df_memory_target_eight)(%rip), %rax
#endif
    jmp 2f
1:
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
#endif
2:
#ifdef __i386__
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    pushq (%rdx)
#endif
    ret

.p2align 4
.globl NAME(df_memory_target)
NAME(df_memory_target):
    movl $7, %eax
    ret
.p2align 4
.globl NAME(df_memory_target_eight)
NAME(df_memory_target_eight):
    movl $8, %eax
    ret

.p2align 8
.globl NAME(df_memory_byte_target_seven)
NAME(df_memory_byte_target_seven):
    movl $7, %eax
    ret
.globl NAME(df_memory_byte_target_eight)
NAME(df_memory_byte_target_eight):
    movl $8, %eax
    ret

.data
.p2align 3
.globl NAME(df_memory_slot)
NAME(df_memory_slot):
    .quad 0
    .quad 0
.p2align 3
.globl NAME(df_memory_initial_slot)
NAME(df_memory_initial_slot):
#ifdef __i386__
    .long NAME(df_memory_target)
#else
    .quad NAME(df_memory_target)
#endif
.text

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
