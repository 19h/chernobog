// Independent SysV x64 corpus. Transform bodies alone are selected for protection.
#if defined(__APPLE__)
#define SYM(x) _##x
#else
#define SYM(x) x
#endif
.text
.globl SYM(corpus_transform)
SYM(corpus_transform):
    movl (%rdx), %eax
    xorl %edi, %eax
    roll $5, %eax
    addl %esi, %eax
    movl %eax, (%rdx)
    retq
.globl SYM(corpus_transform_end)
SYM(corpus_transform_end):
    nop

.globl SYM(corpus_branch)
SYM(corpus_branch):
    cmpl %esi, %edi
    jb Lless
    movl (%rdx), %eax
    xorl %edi, %eax
    jmp Ljoin
Lless:
    movl (%rdx), %eax
    xorl %esi, %eax
Ljoin:
    roll $5, %eax
    addl %esi, %eax
    movl %eax, (%rdx)
    retq
.globl SYM(corpus_branch_end)
SYM(corpus_branch_end):
    nop

// capture(function, x, y, memory, observation). Flags are sampled before any
// flag-changing caller instruction. The call uses SysV 16-byte stack alignment.
.globl SYM(corpus_capture)
SYM(corpus_capture):
    pushq %rbx
    pushq %r12
    pushq %r13
    movq %rdi, %rbx
    movq %r8, %r12
    movq %rsp, %r13
    movl %esi, %eax
    movl %edx, %esi
    movl %eax, %edi
    movq %rcx, %rdx
    callq *%rbx
    pushfq
    popq %rcx
    movq %rax, 0(%r12)
    movq %rcx, 8(%r12)
    movq %rsp, %rax
    subq %r13, %rax
    movq %rax, 16(%r12)
    popq %r13
    popq %r12
    popq %rbx
    retq
#if !defined(__APPLE__)
.section .note.GNU-stack,"",@progbits
#endif
