/* GNU assembler fixture emitted verbatim from formatted C string literals. */
__asm__(".text\n"
        ".macro START name\n"
        ".p2align 4\n"
#ifdef __APPLE__
        ".globl _\\name\n"
        "_\\name:\n"
        ".set \\name, _\\name\n"
#else
        ".globl \\name\n"
        "\\name:\n"
#endif
        ".endm\n"
        ".macro TRUE_RESULT\n"
        "    sete %al\n"
        "    movzbl %al, %eax\n"
        "    ret\n"
        ".endm\n"
        "\n"
        "/* The dispatch precedes status initialization; no instruction between the\n"
        " * before/after snapshots changes status flags except the tested opcode. */\n"
        "START sx_execute\n"
#ifdef __i386__
        "    pushl %ebx\n"
        "    pushl %esi\n"
        "    movl 12(%esp), %eax\n"
        "    movl 20(%esp), %edx\n"
        "    movl 28(%esp), %ecx\n"
        "    movl 32(%esp), %esi\n"
        "    movl %ecx, %ebx\n"
        "    shrl $8, %ebx\n"
        "    orl $2, %ebx\n"
#else
        "    movl %edx, %r8d\n"
        "    movq %rcx, %r9\n"
        "    movq %rdi, %rax\n"
        "    movq %rsi, %rdx\n"
        "    movl %r8d, %ecx\n"
        "    shrl $8, %r8d\n"
        "    orl $2, %r8d\n"
#endif
        "    andl $255, %ecx\n"
        "    cmpl $0, %ecx\n"
        "    je 1f\n"
        "    cmpl $1, %ecx\n"
        "    je 2f\n"
        "    cmpl $2, %ecx\n"
        "    je 3f\n"
        "    cmpl $3, %ecx\n"
        "    je 4f\n"
#ifndef __i386__
        "    cmpl $4, %ecx\n"
        "    je 5f\n"
        "    jmp 6f\n"
#endif
        ".macro SNAP opcode\n"
#ifdef __i386__
        "    pushl %ebx\n"
        "    popfl\n"
        "    pushfl\n"
        "    popl %ebx\n"
        "    \\opcode\n"
        "    pushfl\n"
        "    popl %ecx\n"
#else
        "    pushq %r8\n"
        "    popfq\n"
        "    pushfq\n"
        "    popq %r8\n"
        "    \\opcode\n"
        "    pushfq\n"
        "    popq %r10\n"
#endif
        "    jmp 7f\n"
        ".endm\n"
        "1:  SNAP cbtw\n"
        "2:  SNAP cwtl\n"
        "3:  SNAP cwtd\n"
        "4:  SNAP cltd\n"
#ifndef __i386__
        "5:  SNAP cltq\n"
        "6:  SNAP cqto\n"
#endif
        "7:\n"
#ifdef __i386__
        "    movl %eax, 0(%esi)\n"
        "    movl %edx, 4(%esi)\n"
        "    movl %ebx, 8(%esi)\n"
        "    movl %ecx, 12(%esi)\n"
        "    popl %esi\n"
        "    popl %ebx\n"
#else
        "    movq %rax, 0(%r9)\n"
        "    movq %rdx, 8(%r9)\n"
        "    movq %r8, 16(%r9)\n"
        "    movq %r10, 24(%r9)\n"
#endif
        "    ret\n"
        "\n"
        "START sx_cbw\n"
#ifdef __i386__
        "    movl $0x55667780, %eax\n"
        "    cbtw\n"
        "    cmpl $0x5566ff80, %eax\n"
#else
        "    movabsq $0x1122334455667780, %rax\n"
        "    cbtw\n"
        "    movabsq $0x112233445566ff80, %rcx\n"
        "    cmpq %rcx, %rax\n"
#endif
        "    TRUE_RESULT\n"
        "\n"
        "START sx_cwde\n"
#ifdef __i386__
        "    movl $0x55668000, %eax\n"
        "    cwtl\n"
        "    cmpl $0xffff8000, %eax\n"
#else
        "    movabsq $0x1122334455668000, %rax\n"
        "    cwtl\n"
        "    movl $0xffff8000, %ecx\n"
        "    cmpq %rcx, %rax\n"
#endif
        "    TRUE_RESULT\n"
        "\n"
        "START sx_cwd\n"
#ifdef __i386__
        "    movl $0x55667788, %edx\n"
        "    movl $0x8000, %eax\n"
        "    cwtd\n"
        "    cmpl $0x5566ffff, %edx\n"
#else
        "    movabsq $0x1122334455667788, %rdx\n"
        "    movl $0x8000, %eax\n"
        "    cwtd\n"
        "    movabsq $0x112233445566ffff, %rcx\n"
        "    cmpq %rcx, %rdx\n"
#endif
        "    TRUE_RESULT\n"
        "\n"
        "START sx_cdq\n"
        "    movl $0x80000000, %eax\n"
#ifdef __i386__
        "    movl $0x55667788, %edx\n"
        "    cltd\n"
        "    cmpl $-1, %edx\n"
#else
        "    movq $-1, %rdx\n"
        "    cltd\n"
        "    movl $-1, %ecx\n"
        "    cmpq %rcx, %rdx\n"
#endif
        "    TRUE_RESULT\n"
        "\n"
        "START sx_cwd_partial\n"
#ifdef __i386__
        "    movl 4(%esp), %eax\n"
#else
        "    movl %edi, %eax\n"
#endif
        "    movb $0x80, %ah\n"
        "    cwtd\n"
        "    cmpw $-1, %dx\n"
        "    TRUE_RESULT\n"
        "\n"
        "START sx_cdq_unknown\n"
#ifdef __i386__
        "    movl 4(%esp), %eax\n"
#else
        "    movl %edi, %eax\n"
#endif
        "    cltd\n"
        "    cmpl $-1, %edx\n"
        "    TRUE_RESULT\n"
        "\n"
        "START sx_flags\n"
        "    movl $0x80000000, %eax\n"
        "    stc\n"
        "    cbtw\n"
        "    cwtl\n"
        "    cwtd\n"
        "    cltd\n"
#ifndef __i386__
        "    cltq\n"
        "    cqto\n"
#endif
        "    setb %al\n"
        "    movzbl %al, %eax\n"
        "    ret\n"
        "\n"
        "/* This stack target survives implicit accumulator writes. */\n"
        "START sx_stack\n"
#ifdef __i386__
        "    pushl $sx_target\n"
#else
        "    leaq sx_target(%rip), %rcx\n"
        "    pushq %rcx\n"
#endif
        "    movl $0x80000000, %eax\n"
        "    cltd\n"
#ifdef __i386__
        "    popl %ecx\n"
        "    pushl %ecx\n"
#else
        "    popq %rcx\n"
        "    pushq %rcx\n"
#endif
        "    ret\n"
        "START sx_target\n"
        "    movl $7, %eax\n"
        "    ret\n"
        "\n"
#ifndef __i386__
        "START sx_cdqe\n"
        "    movl $0x80000000, %eax\n"
        "    cltq\n"
        "    movabsq $0xffffffff80000000, %rcx\n"
        "    cmpq %rcx, %rax\n"
        "    TRUE_RESULT\n"
        "\n"
        "START sx_cqo\n"
        "    movabsq $0x8000000000000000, %rax\n"
        "    cqto\n"
        "    cmpq $-1, %rdx\n"
        "    TRUE_RESULT\n"
#endif
        "\n"
        "START sx_prefixed_low\n"
        "    stc\n"
        "    .byte 0x67, 0x98\n"
        "    setb %al\n"
        "    movzbl %al, %eax\n"
        "    ret\n"
        "START sx_prefixed_high\n"
        "    stc\n"
        "    .byte 0x67, 0x99\n"
        "    setb %al\n"
        "    movzbl %al, %eax\n"
        "    ret\n"
        "\n"
#ifndef __APPLE__
        ".section .note.GNU-stack,\"\",@progbits\n"
#endif
);
