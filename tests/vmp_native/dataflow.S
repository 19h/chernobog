/* Independent branch/join/loop fixtures for the owned native must-analysis. */
#ifdef __APPLE__
#define NAME(x) _##x
#else
#define NAME(x) x
#endif
#ifdef __i386__
#define CMPS_SI %esi
#define CMPS_DI %edi
#define STOS_DX %edx
#define STOS_DI %edi
#else
#define CMPS_SI %rsi
#define CMPS_DI %rdi
#define STOS_DX %rdx
#define STOS_DI %rdi
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

/* Register-preserving stack traffic cannot retain a writable-memory must-fact:
 * the abstract stack address may alias the previously established slot. */
BEGIN NAME(df_memory_stack_round_trip)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    pushal
    popal
    pushl NAME(df_memory_slot)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    pushq %rax
    popq %rax
    pushq NAME(df_memory_slot)(%rip)
#endif
    ret

/* Atomic register/memory exchange under the flat normal-completion model. */
BEGIN NAME(df_memory_xchg_store)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    xchgl %eax, (%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    xchgq %rax, (%rdx)
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_xchg_partial)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    xchgw %ax, (%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    xchgl %eax, (%rdx)
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_xchg_byte)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    xchgb %al, (%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    xchgb %al, (%rdx)
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_xchg_load)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl $NAME(df_memory_target_eight), %eax
    xchgl %eax, (%edx)
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    leaq NAME(df_memory_target_eight)(%rip), %rax
    xchgq %rax, (%rdx)
    pushq %rax
#endif
    ret

BEGIN NAME(df_memory_xchg_unknown_source)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl 8(%esp), %eax
    xchgl %eax, (%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    movq %rsi, %rax
    xchgq %rax, (%rdx)
    pushq (%rdx)
#endif
    ret

/* A local writable store can supply a subsequent MOV register load. */
BEGIN NAME(df_memory_mov_load)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    xorl %eax, %eax
    movl (%edx), %eax
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    xorq %rax, %rax
    movq (%rdx), %rax
    pushq %rax
#endif
    ret

BEGIN NAME(df_memory_mov_load_byte)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    xorb $1, %al
    movb (%edx), %al
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    xorb $1, %al
    movb (%rdx), %al
    pushq %rax
#endif
    ret

/* Initial image bytes and an entry-supplied alias remain unknown to replay. */
BEGIN NAME(df_memory_mov_load_initial)
#ifdef __i386__
    movl $NAME(df_memory_initial_slot), %edx
    movl (%edx), %eax
    pushl %eax
#else
    leaq NAME(df_memory_initial_slot)(%rip), %rdx
    movq (%rdx), %rax
    pushq %rax
#endif
    ret

BEGIN NAME(df_memory_mov_load_alias)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl 8(%esp), %ecx
    movl $0, (%ecx)
    movl (%edx), %eax
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    movq $0, (%rsi)
    movq (%rdx), %rax
    pushq %rax
#endif
    ret

/* Zero/sign-extension loads recover a locally written low pointer byte. */
BEGIN NAME(df_memory_movzx_byte)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    andl $-256, %eax
    movzbl (%edx), %ecx
    orl %ecx, %eax
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    andq $-256, %rax
    movzbl (%rdx), %ecx
    orq %rcx, %rax
    pushq %rax
#endif
    ret

BEGIN NAME(df_memory_movsx_byte)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    andl $-256, %eax
    movsbl (%edx), %ecx
    andl $255, %ecx
    orl %ecx, %eax
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    andq $-256, %rax
    movsbl (%rdx), %ecx
    andl $255, %ecx
    orq %rcx, %rax
    pushq %rax
#endif
    ret

BEGIN NAME(df_memory_movzx_word)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    andl $-65536, %eax
    movzwl (%edx), %ecx
    orl %ecx, %eax
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    andq $-65536, %rax
    movzwl (%rdx), %ecx
    orq %rcx, %rax
    pushq %rax
#endif
    ret

BEGIN NAME(df_memory_movsx_word)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    andl $-65536, %eax
    movswl (%edx), %ecx
    andl $65535, %ecx
    orl %ecx, %eax
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    andq $-65536, %rax
    movswl (%rdx), %ecx
    andl $65535, %ecx
    orq %rcx, %rax
    pushq %rax
#endif
    ret

/* Runtime-valid inputs cannot establish an initial byte or disjoint alias. */
BEGIN NAME(df_memory_movzx_initial)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    andl $-256, %eax
    movl $NAME(df_memory_initial_slot), %edx
    movzbl (%edx), %ecx
    orl %ecx, %eax
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    andq $-256, %rax
    leaq NAME(df_memory_initial_slot)(%rip), %rdx
    movzbl (%rdx), %ecx
    orq %rcx, %rax
    pushq %rax
#endif
    ret

BEGIN NAME(df_memory_movzx_alias)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl 8(%esp), %ecx
    movl $0, (%ecx)
    andl $-256, %eax
    movzbl (%edx), %ecx
    orl %ecx, %eax
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    movl $0, (%rsi)
    andq $-256, %rax
    movzbl (%rdx), %ecx
    orq %rcx, %rax
    pushq %rax
#endif
    ret

/* The negative source byte verifies sign extension through a SETcc fact. */
BEGIN NAME(df_memory_movsx_negative)
#ifdef __i386__
    movl $NAME(df_memory_slot), %edx
    movb $0x80, 8(%edx)
    movsbl 8(%edx), %ecx
#else
    leaq NAME(df_memory_slot)(%rip), %rdx
    movb $0x80, 8(%rdx)
    movsbl 8(%rdx), %ecx
#endif
    cmpl $-128, %ecx
    RESULT sete

BEGIN NAME(df_memory_movsx_initial_negative)
#ifdef __i386__
    movl $NAME(df_memory_initial_byte), %edx
    movsbl (%edx), %ecx
#else
    leaq NAME(df_memory_initial_byte)(%rip), %rdx
    movsbl (%rdx), %ecx
#endif
    cmpl $-128, %ecx
    RESULT sete

BEGIN NAME(df_memory_movsx_word_negative)
#ifdef __i386__
    movl $NAME(df_memory_slot), %edx
    movw $0x8000, 8(%edx)
    movswl 8(%edx), %ecx
#else
    leaq NAME(df_memory_slot)(%rip), %rdx
    movw $0x8000, 8(%rdx)
    movswl 8(%rdx), %ecx
#endif
    cmpl $-32768, %ecx
    RESULT sete

BEGIN NAME(df_memory_movsx_initial_word_negative)
#ifdef __i386__
    movl $NAME(df_memory_initial_signed_word), %edx
    movswl (%edx), %ecx
#else
    leaq NAME(df_memory_initial_signed_word)(%rip), %rdx
    movswl (%rdx), %ecx
#endif
    cmpl $-32768, %ecx
    RESULT sete

/* MOVSXD is a long-mode dword load; i386 uses a full-width MOV control. */
BEGIN NAME(df_memory_movsxd_negative)
#ifdef __i386__
    movl $NAME(df_memory_slot), %edx
    movl $0x80000000, 8(%edx)
    movl 8(%edx), %ecx
    cmpl $0x80000000, %ecx
#else
    leaq NAME(df_memory_slot)(%rip), %rdx
    movl $0x80000000, 8(%rdx)
    movslq 8(%rdx), %rcx
    movabsq $0xffffffff80000000, %rax
    cmpq %rax, %rcx
#endif
    RESULT sete

BEGIN NAME(df_memory_movsxd_initial_negative)
#ifdef __i386__
    movl $NAME(df_memory_initial_dword), %edx
    movl (%edx), %ecx
    cmpl $0x80000000, %ecx
#else
    leaq NAME(df_memory_initial_dword)(%rip), %rdx
    movslq (%rdx), %rcx
    movabsq $0xffffffff80000000, %rax
    cmpq %rax, %rcx
#endif
    RESULT sete

/* Arithmetic reads locally established bytes before replacing them. */
BEGIN NAME(df_memory_alu_add)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    subl $1, %eax
    movl %eax, (%edx)
    addl $1, (%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    subq $1, %rax
    movq %rax, (%rdx)
    addq $1, (%rdx)
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_alu_xor_byte)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    xorl $0x5a, %eax
    movl %eax, (%edx)
    xorb $0x5a, (%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    xorq $0x5a, %rax
    movq %rax, (%rdx)
    xorb $0x5a, (%rdx)
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_alu_source)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    xorl %eax, %eax
    addl (%edx), %eax
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    xorq %rax, %rax
    addq (%rdx), %rax
    pushq %rax
#endif
    ret

BEGIN NAME(df_memory_alu_initial)
#ifdef __i386__
    movl $NAME(df_memory_initial_slot), %edx
    xorl %eax, %eax
    addl (%edx), %eax
    pushl %eax
#else
    leaq NAME(df_memory_initial_slot)(%rip), %rdx
    xorq %rax, %rax
    addq (%rdx), %rax
    pushq %rax
#endif
    ret

BEGIN NAME(df_memory_alu_alias)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl 8(%esp), %ecx
    movl %eax, (%ecx)
    xorl %eax, %eax
    addl (%edx), %eax
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    movl %eax, (%rsi)
    xorq %rax, %rax
    addq (%rdx), %rax
    pushq %rax
#endif
    ret

BEGIN NAME(df_memory_alu_compare)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    cmpl %eax, (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    cmpq %rax, (%rdx)
#endif
    RESULT sete

BEGIN NAME(df_memory_alu_rmw_initial)
#ifdef __i386__
    movl $NAME(df_memory_initial_slot), %edx
    addl $0, (%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_initial_slot)(%rip), %rdx
    addq $0, (%rdx)
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_alu_rmw_alias)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    subl $1, %eax
    movl %eax, (%edx)
    movl 8(%esp), %ecx
    movl %eax, (%ecx)
    addl $1, (%edx)
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    subq $1, %rax
    movq %rax, (%rdx)
    movl %eax, (%rsi)
    addq $1, (%rdx)
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_memory_alu_compare_initial)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_initial_slot), %edx
    cmpl %eax, (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_initial_slot)(%rip), %rdx
    cmpq %rax, (%rdx)
#endif
    RESULT sete

BEGIN NAME(df_memory_alu_flags)
#ifdef __i386__
    movl $NAME(df_memory_slot), %edx
    movl $-1, (%edx)
    addl $1, (%edx)
#else
    leaq NAME(df_memory_slot)(%rip), %rdx
    movl $-1, (%rdx)
    addl $1, (%rdx)
#endif
    RESULT sete

BEGIN NAME(df_memory_alu_flags_initial)
#ifdef __i386__
    movl $NAME(df_memory_alu_initial_flag_slot), %edx
    addl $1, (%edx)
#else
    leaq NAME(df_memory_alu_initial_flag_slot)(%rip), %rdx
    addl $1, (%rdx)
#endif
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    movl $-1, (%edx)
#else
    movl $-1, (%rdx)
#endif
    ret

BEGIN NAME(df_rep_movs_cf)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_string_source), %esi
    movl $NAME(df_string_dest), %edi
#else
    leaq NAME(df_string_source)(%rip), %rsi
    leaq NAME(df_string_dest)(%rip), %rdi
#endif
    movl $4, %ecx
    stc
    rep movsb
    setb %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
    popl %esi
#endif
    ret

BEGIN NAME(df_rep_movs_zf)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_string_source), %esi
    movl $NAME(df_string_dest), %edi
#else
    leaq NAME(df_string_source)(%rip), %rsi
    leaq NAME(df_string_dest)(%rip), %rdi
#endif
    movl $4, %ecx
    xorl %eax, %eax
    rep movsb
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
    popl %esi
#endif
    ret

BEGIN NAME(df_movs_plain_cf)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_string_source), %esi
    movl $NAME(df_string_dest), %edi
#else
    leaq NAME(df_string_source)(%rip), %rsi
    leaq NAME(df_string_dest)(%rip), %rdi
#endif
    stc
    movsb
    setb %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
    popl %esi
#endif
    ret

BEGIN NAME(df_cmps_flags_changed)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_string_source), %esi
    movl $NAME(df_string_source), %edi
#else
    leaq NAME(df_string_source)(%rip), %rsi
    leaq NAME(df_string_source)(%rip), %rdi
#endif
    stc
    cmpsb
    setb %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
    popl %esi
#endif
    ret

BEGIN NAME(df_cmps_same_zf)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_string_source), %esi
    movl $NAME(df_string_source), %edi
#else
    leaq NAME(df_string_source)(%rip), %rsi
    leaq NAME(df_string_source)(%rip), %rdi
#endif
    cmpsb
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
    popl %esi
#endif
    ret

BEGIN NAME(df_cmps_local_cf_true)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_cmps_source), %esi
    movl $NAME(df_cmps_dest), %edi
#else
    leaq NAME(df_cmps_source)(%rip), %rsi
    leaq NAME(df_cmps_dest)(%rip), %rdi
#endif
    movb $0x5a, (CMPS_SI)
    movb $0x5b, (CMPS_DI)
    cmpsb
    setb %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
    popl %esi
#endif
    ret

BEGIN NAME(df_cmps_local_cf_false)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_cmps_source), %esi
    movl $NAME(df_cmps_dest), %edi
#else
    leaq NAME(df_cmps_source)(%rip), %rsi
    leaq NAME(df_cmps_dest)(%rip), %rdi
#endif
    movb $0x5b, (CMPS_SI)
    movb $0x5a, (CMPS_DI)
    cmpsb
    setb %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
    popl %esi
#endif
    ret

BEGIN NAME(df_cmps_word_cf)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_cmps_source), %esi
    movl $NAME(df_cmps_dest), %edi
#else
    leaq NAME(df_cmps_source)(%rip), %rsi
    leaq NAME(df_cmps_dest)(%rip), %rdi
#endif
    movw $0x00ff, (CMPS_SI)
    movw $0x0100, (CMPS_DI)
    cmpsw
    setb %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
    popl %esi
#endif
    ret

BEGIN NAME(df_cmps_dword_zf)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_cmps_source), %esi
    movl $NAME(df_cmps_dest), %edi
#else
    leaq NAME(df_cmps_source)(%rip), %rsi
    leaq NAME(df_cmps_dest)(%rip), %rdi
#endif
    movl $0x12345678, (CMPS_SI)
    movl $0x12345678, (CMPS_DI)
    cmpsl
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
    popl %esi
#endif
    ret

#ifndef __i386__
BEGIN NAME(df_cmps_qword_zf)
    leaq NAME(df_cmps_source)(%rip), %rsi
    leaq NAME(df_cmps_dest)(%rip), %rdi
    movq $0x12345678, (%rsi)
    movq $0x12345678, (%rdi)
    cmpsq
    sete %al
    movzbl %al, %eax
    ret
#endif

BEGIN NAME(df_cmps_initial_unknown)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_cmps_initial_source), %esi
    movl $NAME(df_cmps_initial_dest), %edi
#else
    leaq NAME(df_cmps_initial_source)(%rip), %rsi
    leaq NAME(df_cmps_initial_dest)(%rip), %rdi
#endif
    cmpsb
    setb %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
    popl %esi
#endif
    ret

BEGIN NAME(df_rep_cmps_count_ambiguity)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_cmps_source), %esi
    movl $NAME(df_cmps_source), %edi
#else
    leaq NAME(df_cmps_source)(%rip), %rsi
    leaq NAME(df_cmps_source)(%rip), %rdi
#endif
    andl $1, %ecx
    stc
    repe cmpsb
    setb %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
    popl %esi
#endif
    ret

BEGIN NAME(df_rep_stos_cf)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_string_dest), %edi
#else
    leaq NAME(df_string_dest)(%rip), %rdi
#endif
    movl $4, %ecx
    movb $0x5a, %al
    stc
    rep stosb
    setb %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
#endif
    ret

BEGIN NAME(df_rep_stos_count_target)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_string_dest), %edi
#else
    leaq NAME(df_string_dest)(%rip), %rdi
#endif
    andl $1, %ecx
    movb $0x5a, %al
    rep stosb
#ifdef __i386__
    popl %edi
    movl $NAME(df_memory_target), %eax
    addl %ecx, %eax
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    addq %rcx, %rax
    pushq %rax
#endif
    ret

BEGIN NAME(df_lods_plain_cf)
#ifdef __i386__
    pushl %esi
    movl $NAME(df_string_source), %esi
#else
    leaq NAME(df_string_source)(%rip), %rsi
#endif
    stc
    lodsb
    setb %al
    movzbl %al, %eax
#ifdef __i386__
    popl %esi
#endif
    ret

BEGIN NAME(df_rep_lods_zf)
#ifdef __i386__
    pushl %esi
    movl $NAME(df_string_source), %esi
#else
    leaq NAME(df_string_source)(%rip), %rsi
#endif
    movl $4, %ecx
    xorl %eax, %eax
    rep lodsb
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    popl %esi
#endif
    ret

BEGIN NAME(df_rep_lods_count_target)
#ifdef __i386__
    pushl %esi
    movl $NAME(df_string_source), %esi
#else
    leaq NAME(df_string_source)(%rip), %rsi
#endif
    andl $1, %ecx
    rep lodsb
#ifdef __i386__
    popl %esi
    movl $NAME(df_memory_target), %eax
    addl %ecx, %eax
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    addq %rcx, %rax
    pushq %rax
#endif
    ret

BEGIN NAME(df_scas_flags_changed)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_string_dest), %edi
    movb $0x5a, (%edi)
#else
    leaq NAME(df_string_dest)(%rip), %rdi
    movb $0x5a, (%rdi)
#endif
    movb $0x5a, %al
    stc
    scasb
    setb %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
#endif
    ret

BEGIN NAME(df_scas_cf_true)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_string_dest), %edi
    movb $0x5b, (%edi)
#else
    leaq NAME(df_string_dest)(%rip), %rdi
    movb $0x5b, (%rdi)
#endif
    movb $0x5a, %al
    scasb
    setb %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
#endif
    ret

BEGIN NAME(df_scas_zf_true)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_string_dest), %edi
    movb $0x5a, (%edi)
#else
    leaq NAME(df_string_dest)(%rip), %rdi
    movb $0x5a, (%rdi)
#endif
    movb $0x5a, %al
    scasb
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
#endif
    ret

BEGIN NAME(df_scas_word_cf)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_string_dest), %edi
    movw $0x0100, (%edi)
#else
    leaq NAME(df_string_dest)(%rip), %rdi
    movw $0x0100, (%rdi)
#endif
    movw $0x00ff, %ax
    scasw
    setb %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
#endif
    ret

BEGIN NAME(df_scas_dword_zf)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_string_dest), %edi
    movl $0x12345678, (%edi)
#else
    leaq NAME(df_string_dest)(%rip), %rdi
    movl $0x12345678, (%rdi)
#endif
    movl $0x12345678, %eax
    scasl
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
#endif
    ret

#ifndef __i386__
BEGIN NAME(df_scas_qword_zf)
    leaq NAME(df_scas_qword_dest)(%rip), %rdi
    movq $0x12345678, (%rdi)
    movq $0x12345678, %rax
    scasq
    sete %al
    movzbl %al, %eax
    ret
#endif

BEGIN NAME(df_scas_initial_cf)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_string_source), %edi
#else
    leaq NAME(df_string_source)(%rip), %rdi
#endif
    movb $0x5a, %al
    scasb
    setb %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
#endif
    ret

BEGIN NAME(df_rep_scas_count_ambiguity)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_string_dest), %edi
    movb $0x5a, (%edi)
#else
    leaq NAME(df_string_dest)(%rip), %rdi
    movb $0x5a, (%rdi)
#endif
    movb $0x5a, %al
    andl $1, %ecx
    stc
    repe scasb
    setb %al
    movzbl %al, %eax
#ifdef __i386__
    popl %edi
#endif
    ret

BEGIN NAME(df_stos_alias)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    pushl %edi
    movl 12(%esp), %edi
    movb $0, %al
    stosb
    popl %edi
    movl $NAME(df_memory_slot), %edx
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    movq %rsi, %rdi
    movb $0, %al
    stosb
    leaq NAME(df_memory_slot)(%rip), %rdx
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_stos_register_target)
#ifdef __i386__
    movl $NAME(df_memory_target), %edx
    pushl %edi
    movl $NAME(df_string_dest), %edi
#else
    leaq NAME(df_memory_target)(%rip), %rdx
    leaq NAME(df_string_dest)(%rip), %rdi
#endif
    movl $1, %ecx
    movb $0, %al
    rep stosb
#ifdef __i386__
    popl %edi
    pushl %edx
#else
    pushq %rdx
#endif
    ret

BEGIN NAME(df_stos_disjoint_target)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl $NAME(df_stos_slot), %edi
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    leaq NAME(df_stos_slot)(%rip), %rdi
#endif
    movb $0x5a, %al
    stosb
#ifdef __i386__
    movl (%esp), %edi
    leal 4(%esp), %esp
    movl $NAME(df_memory_slot), %edx
    pushl (%edx)
#else
    leaq NAME(df_memory_slot)(%rip), %rdx
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_stos_unknown_value_disjoint_target)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl $NAME(df_stos_slot), %edi
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    leaq NAME(df_stos_slot)(%rip), %rdi
#endif
    movb %cl, %al
    stosb
#ifdef __i386__
    movl (%esp), %edi
    leal 4(%esp), %esp
    movl $NAME(df_memory_slot), %edx
    pushl (%edx)
#else
    leaq NAME(df_memory_slot)(%rip), %rdx
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_rep_stos_disjoint_target)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl $NAME(df_stos_slot), %edi
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    leaq NAME(df_stos_slot)(%rip), %rdi
#endif
    andl $1, %ecx
    movb $0x5a, %al
    rep stosb
#ifdef __i386__
    movl (%esp), %edi
    leal 4(%esp), %esp
    movl $NAME(df_memory_slot), %edx
    pushl (%edx)
#else
    leaq NAME(df_memory_slot)(%rip), %rdx
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_stos_overlap_known_target)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl %edx, %edi
    movb (%edx), %al
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    movq %rdx, %rdi
    movb (%rdx), %al
#endif
    stosb
#ifdef __i386__
    movl (%esp), %edi
    leal 4(%esp), %esp
    movl $NAME(df_memory_slot), %edx
    pushl (%edx)
#else
    leaq NAME(df_memory_slot)(%rip), %rdx
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_stos_byte_reload)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_stos_slot), %edi
#else
    leaq NAME(df_stos_slot)(%rip), %rdi
#endif
    movb $0x5a, %al
    stosb
#ifdef __i386__
    movl $NAME(df_stos_slot), %edx
#else
    leaq NAME(df_stos_slot)(%rip), %rdx
#endif
    movzbl (STOS_DX), %eax
    cmpl $0x5a, %eax
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    movl (%esp), %edi
    leal 4(%esp), %esp
#endif
    ret

BEGIN NAME(df_stos_word_reload)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_stos_slot), %edi
#else
    leaq NAME(df_stos_slot)(%rip), %rdi
#endif
    movw $0x5a5b, %ax
    stosw
#ifdef __i386__
    movl $NAME(df_stos_slot), %edx
#else
    leaq NAME(df_stos_slot)(%rip), %rdx
#endif
    movzwl (STOS_DX), %eax
    cmpl $0x5a5b, %eax
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    movl (%esp), %edi
    leal 4(%esp), %esp
#endif
    ret

BEGIN NAME(df_stos_dword_reload)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_stos_slot), %edi
#else
    leaq NAME(df_stos_slot)(%rip), %rdi
#endif
    movl $0x12345678, %eax
    stosl
#ifdef __i386__
    movl $NAME(df_stos_slot), %edx
#else
    leaq NAME(df_stos_slot)(%rip), %rdx
#endif
    movl (STOS_DX), %eax
    cmpl $0x12345678, %eax
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    movl (%esp), %edi
    leal 4(%esp), %esp
#endif
    ret

BEGIN NAME(df_stos_unknown_overlap_condition)
#ifdef __i386__
    pushl %edi
    movl $NAME(df_stos_slot), %edi
#else
    leaq NAME(df_stos_slot)(%rip), %rdi
#endif
    movb $0x5a, (STOS_DI)
    movb %cl, %al
    stosb
#ifdef __i386__
    movl $NAME(df_stos_slot), %edx
#else
    leaq NAME(df_stos_slot)(%rip), %rdx
#endif
    movzbl (STOS_DX), %eax
    cmpl $0x5a, %eax
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    movl (%esp), %edi
    leal 4(%esp), %esp
#endif
    ret

#ifndef __i386__
BEGIN NAME(df_stos_qword_reload)
    leaq NAME(df_stos_slot)(%rip), %rdi
    movq $0x12345678, %rax
    stosq
    leaq NAME(df_stos_slot)(%rip), %rdx
    movq (%rdx), %rax
    cmpq $0x12345678, %rax
    sete %al
    movzbl %al, %eax
    ret
#endif

BEGIN NAME(df_lods_memory_target)
#ifdef __i386__
    pushl %esi
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl $NAME(df_string_source), %esi
    lodsb
    movl (%esp), %esi
    leal 4(%esp), %esp
    movl $NAME(df_memory_slot), %edx
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    leaq NAME(df_string_source)(%rip), %rsi
    lodsb
    leaq NAME(df_memory_slot)(%rip), %rdx
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_lods_full_target)
#ifdef __i386__
    pushl %esi
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_lods_source), %edx
    movl %eax, (%edx)
    movl %edx, %esi
    lodsl
    movl (%esp), %esi
    leal 4(%esp), %esp
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_lods_source)(%rip), %rdx
    movq %rax, (%rdx)
    movq %rdx, %rsi
    lodsq
    pushq %rax
#endif
    ret

BEGIN NAME(df_lods_byte_preserved_target)
#ifdef __i386__
    pushl %esi
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_lods_source), %edx
    movb %al, (%edx)
    movl %edx, %esi
    lodsb
    movl (%esp), %esi
    leal 4(%esp), %esp
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_lods_source)(%rip), %rdx
    movb %al, (%rdx)
    movq %rdx, %rsi
    lodsb
    pushq %rax
#endif
    ret

BEGIN NAME(df_lods_byte_value)
#ifdef __i386__
    pushl %esi
    movl $NAME(df_lods_source), %edx
    movl %edx, %esi
#else
    leaq NAME(df_lods_source)(%rip), %rdx
    movq %rdx, %rsi
#endif
    movb $0x5a, (STOS_DX)
    lodsb
    cmpb $0x5a, %al
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    movl (%esp), %esi
    leal 4(%esp), %esp
#endif
    ret

BEGIN NAME(df_lods_word_value)
#ifdef __i386__
    pushl %esi
    movl $NAME(df_lods_source), %edx
    movl %edx, %esi
#else
    leaq NAME(df_lods_source)(%rip), %rdx
    movq %rdx, %rsi
#endif
    movw $0x1234, (STOS_DX)
    lodsw
    cmpw $0x1234, %ax
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    movl (%esp), %esi
    leal 4(%esp), %esp
#endif
    ret

BEGIN NAME(df_lods_dword_value)
#ifdef __i386__
    pushl %esi
    movl $NAME(df_lods_source), %edx
    movl %edx, %esi
#else
    leaq NAME(df_lods_source)(%rip), %rdx
    movq %rdx, %rsi
#endif
    movl $0x12345678, (STOS_DX)
    lodsl
    cmpl $0x12345678, %eax
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    movl (%esp), %esi
    leal 4(%esp), %esp
#endif
    ret

BEGIN NAME(df_lods_unknown_source_value)
#ifdef __i386__
    pushl %esi
    movl $NAME(df_lods_initial_source), %esi
#else
    leaq NAME(df_lods_initial_source)(%rip), %rsi
#endif
    lodsb
    cmpb $0x5a, %al
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    movl (%esp), %esi
    leal 4(%esp), %esp
#endif
    ret

BEGIN NAME(df_rep_lods_ambiguous_value)
#ifdef __i386__
    pushl %esi
    movl $NAME(df_lods_source), %edx
    movl %edx, %esi
#else
    leaq NAME(df_lods_source)(%rip), %rdx
    movq %rdx, %rsi
#endif
    movb $0x5a, (STOS_DX)
    movb $0x6b, %al
    andl $1, %ecx
    rep lodsb
    cmpb $0x5a, %al
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    movl (%esp), %esi
    leal 4(%esp), %esp
#endif
    ret

BEGIN NAME(df_lods_unknown_source_high_value)
#ifdef __i386__
    pushl %esi
    movl $NAME(df_lods_initial_source), %esi
#else
    leaq NAME(df_lods_initial_source)(%rip), %rsi
#endif
    movw $0x1234, %ax
    lodsb
    cmpb $0x12, %ah
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    movl (%esp), %esi
    leal 4(%esp), %esp
#endif
    ret

#ifndef __i386__
BEGIN NAME(df_lods_qword_value)
    leaq NAME(df_lods_source)(%rip), %rdx
    movq %rdx, %rsi
    movq $0x12345678, (%rdx)
    lodsq
    cmpq $0x12345678, %rax
    sete %al
    movzbl %al, %eax
    ret
#endif

BEGIN NAME(df_rep_movs_alias)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    pushl %esi
    pushl %edi
    movl 16(%esp), %edi
    movl $NAME(df_string_source), %esi
    movl $1, %ecx
    rep movsb
    popl %edi
    popl %esi
    movl $NAME(df_memory_slot), %edx
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    movq %rsi, %rdi
    leaq NAME(df_string_source)(%rip), %rsi
    movl $1, %ecx
    rep movsb
    leaq NAME(df_memory_slot)(%rip), %rdx
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_movs_disjoint_target)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl $NAME(df_movs_source), %esi
    movl $NAME(df_movs_dest), %edi
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    leaq NAME(df_movs_source)(%rip), %rsi
    leaq NAME(df_movs_dest)(%rip), %rdi
#endif
    movb $0x5a, (CMPS_SI)
    movsb
#ifdef __i386__
    movl (%esp), %edi
    movl 4(%esp), %esi
    leal 8(%esp), %esp
    movl $NAME(df_memory_slot), %edx
    pushl (%edx)
#else
    leaq NAME(df_memory_slot)(%rip), %rdx
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_movs_unknown_source_disjoint_target)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl $NAME(df_movs_initial_source), %esi
    movl $NAME(df_movs_dest), %edi
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    leaq NAME(df_movs_initial_source)(%rip), %rsi
    leaq NAME(df_movs_dest)(%rip), %rdi
#endif
    movsb
#ifdef __i386__
    movl (%esp), %edi
    movl 4(%esp), %esi
    leal 8(%esp), %esp
    movl $NAME(df_memory_slot), %edx
    pushl (%edx)
#else
    leaq NAME(df_memory_slot)(%rip), %rdx
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_movs_self_copy_target)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl %edx, %esi
    movl %edx, %edi
    movsl
    movl (%esp), %edi
    movl 4(%esp), %esi
    leal 8(%esp), %esp
    movl $NAME(df_memory_slot), %edx
    pushl (%edx)
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    movq %rdx, %rsi
    movq %rdx, %rdi
    movsq
    leaq NAME(df_memory_slot)(%rip), %rdx
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_rep_movs_disjoint_target)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_memory_target), %eax
    movl $NAME(df_memory_slot), %edx
    movl %eax, (%edx)
    movl $NAME(df_movs_source), %esi
    movl $NAME(df_movs_dest), %edi
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_memory_slot)(%rip), %rdx
    movq %rax, (%rdx)
    leaq NAME(df_movs_source)(%rip), %rsi
    leaq NAME(df_movs_dest)(%rip), %rdi
#endif
    movb $0x5a, (CMPS_SI)
    andl $1, %ecx
    rep movsb
#ifdef __i386__
    movl (%esp), %edi
    movl 4(%esp), %esi
    leal 8(%esp), %esp
    movl $NAME(df_memory_slot), %edx
    pushl (%edx)
#else
    leaq NAME(df_memory_slot)(%rip), %rdx
    pushq (%rdx)
#endif
    ret

BEGIN NAME(df_movs_byte_reload)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_movs_source), %esi
    movl $NAME(df_movs_dest), %edi
#else
    leaq NAME(df_movs_source)(%rip), %rsi
    leaq NAME(df_movs_dest)(%rip), %rdi
#endif
    movb $0x5a, (CMPS_SI)
    movsb
#ifdef __i386__
    movl $NAME(df_movs_dest), %edx
#else
    leaq NAME(df_movs_dest)(%rip), %rdx
#endif
    movzbl (STOS_DX), %eax
    cmpl $0x5a, %eax
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    movl (%esp), %edi
    movl 4(%esp), %esi
    leal 8(%esp), %esp
#endif
    ret

BEGIN NAME(df_movs_overlap_word_reload)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_movs_overlap), %edx
    movl %edx, %esi
    leal 1(%edx), %edi
#else
    leaq NAME(df_movs_overlap)(%rip), %rdx
    movq %rdx, %rsi
    leaq 1(%rdx), %rdi
#endif
    movw $0x1234, (STOS_DX)
    movsw
    movzwl 1(STOS_DX), %eax
    cmpl $0x1234, %eax
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    movl (%esp), %edi
    movl 4(%esp), %esi
    leal 8(%esp), %esp
#endif
    ret

BEGIN NAME(df_movs_dword_reload)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_movs_source), %esi
    movl $NAME(df_movs_dest), %edi
#else
    leaq NAME(df_movs_source)(%rip), %rsi
    leaq NAME(df_movs_dest)(%rip), %rdi
#endif
    movl $0x12345678, (CMPS_SI)
    movsl
#ifdef __i386__
    movl $NAME(df_movs_dest), %edx
#else
    leaq NAME(df_movs_dest)(%rip), %rdx
#endif
    movl (STOS_DX), %eax
    cmpl $0x12345678, %eax
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    movl (%esp), %edi
    movl 4(%esp), %esi
    leal 8(%esp), %esp
#endif
    ret

BEGIN NAME(df_movs_initial_source_unknown)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_movs_initial_source), %esi
    movl $NAME(df_movs_dest), %edi
#else
    leaq NAME(df_movs_initial_source)(%rip), %rsi
    leaq NAME(df_movs_dest)(%rip), %rdi
#endif
    movsb
#ifdef __i386__
    movl $NAME(df_movs_dest), %edx
#else
    leaq NAME(df_movs_dest)(%rip), %rdx
#endif
    movzbl (STOS_DX), %eax
    cmpl $0x5a, %eax
    sete %al
    movzbl %al, %eax
#ifdef __i386__
    movl (%esp), %edi
    movl 4(%esp), %esi
    leal 8(%esp), %esp
#endif
    ret

#ifndef __i386__
BEGIN NAME(df_movs_qword_reload)
    leaq NAME(df_movs_source)(%rip), %rsi
    leaq NAME(df_movs_dest)(%rip), %rdi
    movq $0x12345678, (%rsi)
    movsq
    leaq NAME(df_movs_dest)(%rip), %rdx
    movq (%rdx), %rax
    cmpq $0x12345678, %rax
    sete %al
    movzbl %al, %eax
    ret
#endif

BEGIN NAME(df_rep_movs_register_target)
#ifdef __i386__
    movl $NAME(df_memory_target), %eax
    pushl %esi
    pushl %edi
    movl $NAME(df_string_source), %esi
    movl $NAME(df_string_dest), %edi
#else
    leaq NAME(df_memory_target)(%rip), %rax
    leaq NAME(df_string_source)(%rip), %rsi
    leaq NAME(df_string_dest)(%rip), %rdi
#endif
    movl $1, %ecx
    rep movsb
#ifdef __i386__
    popl %edi
    popl %esi
    pushl %eax
#else
    pushq %rax
#endif
    ret

BEGIN NAME(df_movs_plain_count_target)
#ifdef __i386__
    movl $NAME(df_memory_target), %ecx
    pushl %esi
    pushl %edi
    movl $NAME(df_string_source), %esi
    movl $NAME(df_string_dest), %edi
#else
    leaq NAME(df_memory_target)(%rip), %rcx
    leaq NAME(df_string_source)(%rip), %rsi
    leaq NAME(df_string_dest)(%rip), %rdi
#endif
    movsb
#ifdef __i386__
    popl %edi
    popl %esi
    pushl %ecx
#else
    pushq %rcx
#endif
    ret

BEGIN NAME(df_rep_movs_count_unknown)
#ifdef __i386__
    pushl %esi
    pushl %edi
    movl $NAME(df_string_source), %esi
    movl $NAME(df_string_dest), %edi
#else
    leaq NAME(df_string_source)(%rip), %rsi
    leaq NAME(df_string_dest)(%rip), %rdi
#endif
    andl $1, %ecx
    rep movsb
#ifdef __i386__
    popl %edi
    popl %esi
    movl $NAME(df_memory_target), %eax
    addl %ecx, %eax
    pushl %eax
#else
    leaq NAME(df_memory_target)(%rip), %rax
    addq %rcx, %rax
    pushq %rax
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
.globl NAME(df_memory_initial_byte)
NAME(df_memory_initial_byte):
    .byte 0x80
.p2align 1
.globl NAME(df_memory_initial_signed_word)
NAME(df_memory_initial_signed_word):
    .word 0x8000
.p2align 2
.globl NAME(df_memory_initial_dword)
NAME(df_memory_initial_dword):
    .long 0x80000000
.p2align 2
.globl NAME(df_memory_alu_initial_flag_slot)
NAME(df_memory_alu_initial_flag_slot):
    .long -1
.p2align 2
.globl NAME(df_string_source)
NAME(df_string_source):
    .long 0x12345678
.globl NAME(df_string_dest)
NAME(df_string_dest):
    .long 0
.p2align 3
.globl NAME(df_scas_qword_dest)
NAME(df_scas_qword_dest):
    .quad 0
.p2align 3
.globl NAME(df_stos_slot)
NAME(df_stos_slot):
    .quad 0
.p2align 3
.globl NAME(df_movs_source)
NAME(df_movs_source):
    .quad 0
.globl NAME(df_movs_dest)
NAME(df_movs_dest):
    .quad 0
.globl NAME(df_movs_overlap)
NAME(df_movs_overlap):
    .quad 0
    .quad 0
.globl NAME(df_movs_initial_source)
NAME(df_movs_initial_source):
    .quad 0x5a
.p2align 3
.globl NAME(df_lods_source)
NAME(df_lods_source):
    .quad 0
.globl NAME(df_lods_initial_source)
NAME(df_lods_initial_source):
    .quad 0x5a
.p2align 3
.globl NAME(df_cmps_source)
NAME(df_cmps_source):
    .quad 0
.globl NAME(df_cmps_dest)
NAME(df_cmps_dest):
    .quad 0
.globl NAME(df_cmps_initial_source)
NAME(df_cmps_initial_source):
    .quad 0x5a
.globl NAME(df_cmps_initial_dest)
NAME(df_cmps_initial_dest):
    .quad 0x5b
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
