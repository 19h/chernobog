/* Synthetic source-grammar immediate push, including only the observed fast
 * stack-check continuation. The equality path is a controlled rejection stub;
 * it does not implement or claim the protector's relocation routine. INT3 gaps
 * keep transfer targets distinct from fallthrough: the current capture driver
 * lacks transfer witnesses for target-equals-fallthrough, which this fixture
 * does not validate. The final byte prevents the ELF end label aliasing _fini. */
#ifndef VM_PUSH_BITS
#define VM_PUSH_BITS 32
#endif
#ifndef VM_PUSH_BACKWARD
#define VM_PUSH_BACKWARD 0
#endif
#ifndef VM_PUSH_RELATIVE
#define VM_PUSH_RELATIVE 1
#endif
#if VM_PUSH_BITS == 8
#define SLOT 2
#else
#define SLOT (VM_PUSH_BITS / 8)
#endif
#if VM_PUSH_RELATIVE
#define DISPATCH_BYTES 4
#else
#define DISPATCH_BYTES 1
#endif
#if defined(__APPLE__)
#define NAME_IMPL(x) _##x
#define NAME(x) NAME_IMPL(x)
#else
#define NAME(x) x
#endif
#if defined(__x86_64__)
#define SP %rsp
#define VIP %rsi
#define VSP %rbp
#define KEY %rbx
#define BASE %rdi
#define AX %rax
#define CX %rcx
#define DX %rdx
#define MOVE movq
#define ADD addq
#define SUB subq
#define LEA leaq
#define COMPARE cmpq
#define THRESHOLD 256
#else
#define SP %esp
#define VIP %esi
#define VSP %ebp
#define KEY %ebx
#define BASE %edi
#define AX %eax
#define CX %ecx
#define DX %edx
#define MOVE movl
#define ADD addl
#define SUB subl
#define LEA leal
#define COMPARE cmpl
#define THRESHOLD 96
#endif

.text
.p2align 4
.globl NAME(vm_push_run), NAME(vm_push_handler), NAME(vm_push_store)
.globl NAME(vm_push_stack_check), NAME(vm_push_branch), NAME(vm_push_continuation)
.globl NAME(vm_push_dispatch), NAME(vm_push_capture), NAME(vm_push_slow), NAME(vm_push_end)

.macro READ_VALUE bits, r8, r16, r32, r64
#if VM_PUSH_BACKWARD
    SUB $(\bits / 8), VIP
#endif
.if \bits == 8
    movzbl (VIP), \r32
.elseif \bits == 16
    movzwl (VIP), \r32
.elseif \bits == 32
    movl (VIP), \r32
.else
    movq (VIP), \r64
.endif
#if !VM_PUSH_BACKWARD
    ADD $(\bits / 8), VIP
#endif
.if \bits == 8
    xorb %bl, \r8
    rolb $3, \r8
    addb $7, \r8
    xorb $0x5a, \r8
    subb $9, \r8
    xorb \r8, %bl
.elseif \bits == 16
    xorw %bx, \r16
    rolw $3, \r16
    addw $7, \r16
    xorw $0x5a, \r16
    subw $9, \r16
    xorw \r16, %bx
.elseif \bits == 32
    xorl %ebx, \r32
    roll $3, \r32
    addl $7, \r32
    xorl $0x5a, \r32
    subl $9, \r32
#if defined(__x86_64__)
    pushq %rbx
    xorl \r32, (%rsp)
    popq %rbx
#else
    xorl \r32, %ebx
#endif
.else
    xorq %rbx, \r64
    rolq $3, \r64
    addq $7, \r64
    xorq $0x5a, \r64
    subq $9, \r64
    xorq \r64, %rbx
.endif
.endm

NAME(vm_push_run):
#if defined(__x86_64__)
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    movq %rdi, %rax
    movq %rsi, %rcx
#else
    pushl %ebx
    pushl %ebp
    pushl %esi
    pushl %edi
    movl 20(%esp), %eax
    movl 24(%esp), %ecx
#endif
    SUB $768, SP
    MOVE AX, 0(SP)
    MOVE AX, VIP
    MOVE 16(AX), KEY
#if VM_PUSH_BACKWARD
    ADD $(VM_PUSH_BITS / 8 + DISPATCH_BYTES), VIP
#endif
#if VM_PUSH_RELATIVE
#if defined(__x86_64__)
    leaq NAME(vm_push_capture)(%rip), %rdi
    movslq 12(%rax), %rdx
    subq %rdx, %rdi
#else
    movl $NAME(vm_push_capture), %edi
    movl 12(%eax), %edx
    subl %edx, %edi
#endif
#elif defined(__x86_64__)
    leaq NAME(vm_push_table)(%rip), %rdi
#endif
    COMPARE $0, CX
    je Lpush_fast_setup
    LEA THRESHOLD+SLOT(SP), VSP
    jmp Lpush_initialized_slot
Lpush_fast_setup:
    LEA THRESHOLD+SLOT+64(SP), VSP
Lpush_initialized_slot:
    movl $0x3c3c3c3c, -SLOT-8(VSP)
    movl $0x3c3c3c3c, -SLOT-4(VSP)
    movl $0xa5a5a5a5, -SLOT(VSP)
    movl $0xa5a5a5a5, -SLOT+4(VSP)
    movl $0x5a5a5a5a, -SLOT+8(VSP)
    movl $0x5a5a5a5a, -SLOT+12(VSP)
NAME(vm_push_handler):
    READ_VALUE VM_PUSH_BITS, %dl, %dx, %edx, %rdx
    SUB $SLOT, VSP
NAME(vm_push_store):
#if SLOT == 2
    movw %dx, (VSP)
#elif SLOT == 4
    movl %edx, (VSP)
#else
    movq %rdx, (VSP)
#endif
#if VM_PUSH_RELATIVE
    READ_VALUE 32, %al, %ax, %eax, %rax
#if defined(__x86_64__)
    movslq %eax, %rax
#endif
    ADD AX, BASE
#endif
    jmp NAME(vm_push_stack_check)
    .byte 0xcc, 0xcc, 0xcc
NAME(vm_push_stack_check):
    LEA THRESHOLD(SP), CX
    COMPARE CX, VSP
NAME(vm_push_branch):
    ja NAME(vm_push_continuation)
NAME(vm_push_slow):
    xorl %eax, %eax
    jmp Lpush_record
NAME(vm_push_continuation):
#if !VM_PUSH_RELATIVE
    READ_VALUE 8, %al, %ax, %eax, %rax
#endif
NAME(vm_push_dispatch):
#if VM_PUSH_RELATIVE
    jmp *BASE
#elif defined(__x86_64__)
    jmp *(%rdi,%rax,8)
#else
    jmp *NAME(vm_push_table)(,%eax,4)
#endif
    .byte 0xcc, 0xcc, 0xcc
NAME(vm_push_capture):
    movl $1, %eax
Lpush_record:
    MOVE 0(SP), CX
    movl %eax, 48(CX)
    movl $0, 52(CX)
#if defined(__x86_64__)
    movq (VSP), %rdx
    movq %rdx, 24(CX)
    movq -8(VSP), %rdx
    movq %rdx, 56(CX)
    movq 8(VSP), %rdx
    movq %rdx, 64(CX)
    movq KEY, 32(CX)
#else
    movl (VSP), %edx
    movl %edx, 24(CX)
    movl 4(VSP), %edx
    movl %edx, 28(CX)
    movl -8(VSP), %edx
    movl %edx, 56(CX)
    movl -4(VSP), %edx
    movl %edx, 60(CX)
    movl 8(VSP), %edx
    movl %edx, 64(CX)
    movl 12(VSP), %edx
    movl %edx, 68(CX)
    movl KEY, 32(CX)
    movl $0, 36(CX)
#endif
    MOVE VIP, DX
    SUB CX, DX
    MOVE DX, 40(CX)
#if !defined(__x86_64__)
    movl $0, 44(CX)
#endif
    ADD $768, SP
#if defined(__x86_64__)
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    retq
#else
    popl %edi
    popl %esi
    popl %ebp
    popl %ebx
    ret
#endif
NAME(vm_push_end):
    .byte 0x90

.data
.p2align 3
NAME(vm_push_table):
#if defined(__x86_64__)
    .quad NAME(vm_push_capture)
#else
    .long NAME(vm_push_capture)
    .section .note.GNU-stack,"",@progbits
#endif
