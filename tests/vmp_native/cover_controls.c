/* Controls for complete covers, partial sources and infeasible members. */
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
        ".macro INPUT\n"
#ifdef __i386__
        "movl 4(%esp), %ecx\n"
#else
        "movl %edi, %ecx\n"
#endif
        ".endm\n"
        ".macro ADDRESS name, reg\n"
#ifdef __i386__
        "movl $\\name, %e\\reg\n"
#else
        "leaq \\name(%rip), %r\\reg\n"
#endif
        ".endm\n"
        ".macro SAVE\n"
#ifdef __i386__
        "movl %eax, (%edx)\n"
#else
        "movq %rax, (%rdx)\n"
#endif
        ".endm\n"
        ".macro FINISH\n"
#ifdef __i386__
        "pushl %eax\n"
#else
        "pushq %rax\n"
#endif
        "ret\n"
        ".endm\n"
        ".macro MEMORY_FINISH\n"
#ifdef __i386__
        "pushl (%edx)\n"
#else
        "pushq (%rdx)\n"
#endif
        "ret\n"
        ".endm\n"
        "START cv_partial\n"
        "INPUT\n"
#ifdef __i386__
        "movl 8(%esp), %eax\n"
#else
        "movq %rsi, %rax\n"
#endif
        "testl %ecx, %ecx\n"
        "jnz 1f\n"
        "ADDRESS cv_seven, ax\n"
        "1: FINISH\n"
        "START cv_alias\n"
        "INPUT\n"
        "ADDRESS cv_seven, ax\n"
        "ADDRESS cv_cell_a, dx\n"
        "SAVE\n"
        "testl %ecx, %ecx\n"
        "jz 1f\n"
#ifdef __i386__
        "movl 8(%esp), %ecx\n"
        "movl $0, (%ecx)\n"
#else
        "movq $0, (%rsi)\n"
#endif
        "1: MEMORY_FINISH\n"
        "START cv_multi_address\n"
        "INPUT\n"
        "testl %ecx, %ecx\n"
        "jz 1f\n"
        "ADDRESS cv_eight, ax\n"
        "ADDRESS cv_cell_b, dx\n"
        "SAVE\n"
        "jmp 2f\n"
        "1: ADDRESS cv_seven, ax\n"
        "ADDRESS cv_cell_a, dx\n"
        "SAVE\n"
        "2: MEMORY_FINISH\n"
        "START cv_infeasible\n"
        "xorl %ecx, %ecx\n"
        "testl %ecx, %ecx\n"
        "jnz 1f\n"
        "ADDRESS cv_seven, ax\n"
        "jmp 2f\n"
        "1: ADDRESS cv_eight, ax\n"
        "2: FINISH\n"
        "START cv_call\n"
        "ADDRESS cv_seven, ax\n"
        "call cv_opaque\n"
        "FINISH\n"
        "START cv_opaque\n"
        "ret\n"
        "START cv_seven\n"
        "movl $7, %eax\n"
        "ret\n"
        "START cv_eight\n"
        "movl $8, %eax\n"
        "ret\n"
        "START cv_nine\n"
        "movl $9, %eax\n"
        "ret\n"
        ".data\n"
        ".p2align 3\n"
        "cv_cell_a: .quad 0\n"
        "cv_cell_b: .quad 0\n"
#ifndef __APPLE__
        ".section .note.GNU-stack,\"\",@progbits\n"
#endif
);
