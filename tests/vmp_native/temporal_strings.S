// Controlled native oracle for modeled decrypt/use/erase and free/reuse.
// This is a standalone fixture, not protector output.
.section __TEXT,__text,regular,pure_instructions
.p2align 4
.globl _temporal_strings
_temporal_strings:
    pushq %rbx
    pushq %r12
    subq $8, %rsp
    xorl %r12d, %r12d
    movl $16, %edi
    callq _malloc
    movq %rax, %rbx
    movabsq $0x5a7b2e3f28393f29, %rdx // "secret!\0" XOR key
    movq %rdx, (%rbx)
    movq Ltemporal_key(%rip), %rdx
    xorq %rdx, (%rbx)
    movq %rbx, %rdi
    callq _strlen
    addq %rax, %r12
    movq %rbx, %rdi
    xorl %esi, %esi
    movl $16, %edx
    callq _memset
    movq %rbx, %rdi
    callq _free
    movl $16, %edi
    callq _malloc
    movq %rax, %rbx
    movabsq $0x5a7b3e3435393f29, %rdx // "second!\0" XOR key
    movq %rdx, (%rbx)
    movq Ltemporal_key(%rip), %rdx
    xorq %rdx, (%rbx)
    movq %rbx, %rdi
    callq _strlen
    addq %rax, %r12
    movq %rbx, %rdi
    xorl %esi, %esi
    movl $16, %edx
    callq _memset
    movq %rbx, %rdi
    callq _free
    movq %r12, %rax
    addq $8, %rsp
    popq %r12
    popq %rbx
    retq

.p2align 4
.globl _main
_main:
    subq $8, %rsp
    callq _temporal_strings
    cmpq $14, %rax
    setne %al
    movzbl %al, %eax
    addq $8, %rsp
    retq

.section __DATA,__const
.p2align 3
.globl _temporal_key
_temporal_key:
Ltemporal_key:
    .quad 0x5a5a5a5a5a5a5a5a
.subsections_via_symbols
