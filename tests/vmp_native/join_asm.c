/* Literal correlated-join fixtures, shared by native and IDA observations. */
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
        ".macro OFFSET value\n"
#ifdef __i386__
        "movl $\\value, %ecx\n"
#else
        "movq $\\value, %rcx\n"
#endif
        ".endm\n"
        ".macro SAVE\n"
#ifdef __i386__
        "movl %eax, (%edx)\n"
#else
        "movq %rax, (%rdx)\n"
#endif
        ".endm\n"
        ".macro INCREMENT\n"
#ifdef __i386__
        "incl %eax\n"
#else
        "incq %rax\n"
#endif
        ".endm\n"
        ".macro ADJUST\n"
#ifdef __i386__
        "addl %ecx, %eax\n"
#else
        "addq %rcx, %rax\n"
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
        "START jc_register\n"
        "INPUT\n"
        "testl %ecx, %ecx\n"
        "jz 1f\n"
        "movl $0, %eax\n"
        "movl $7, %ecx\n"
        "jmp 2f\n"
        "1: movl $7, %eax\n"
        "movl $0, %ecx\n"
        "2: imull %ecx, %eax\n"
        "ADDRESS jc_register_destination, dx\n"
#ifdef __i386__
        "addl %edx, %eax\n"
#else
        "addq %rdx, %rax\n"
#endif
        "FINISH\n"
        "START jc_register_destination\n"
        "movl $7, %eax\n"
        "ret\n"
        "START jc_memory\n"
        "INPUT\n"
        "ADDRESS jc_cell, dx\n"
        "testl %ecx, %ecx\n"
        "jz 1f\n"
        "ADDRESS jc_memory_destination, ax\n"
        "INCREMENT\n"
        "SAVE\n"
        "OFFSET -1\n"
        "jmp 2f\n"
        "1: ADDRESS jc_memory_destination, ax\n"
        "SAVE\n"
        "OFFSET 0\n"
#ifdef __i386__
        "2: movl (%edx), %eax\n"
#else
        "2: movq (%rdx), %rax\n"
#endif
        "ADJUST\n"
        "SAVE\n"
#ifdef __i386__
        "pushl (%edx)\n"
#else
        "pushq (%rdx)\n"
#endif
        "ret\n"
        "START jc_memory_destination\n"
        "movl $7, %eax\n"
        "ret\n"
        "START jc_stack\n"
        "INPUT\n"
        "testl %ecx, %ecx\n"
        "jz 1f\n"
        "ADDRESS jc_stack_destination, ax\n"
        "INCREMENT\n"
#ifdef __i386__
        "pushl %eax\n"
#else
        "pushq %rax\n"
#endif
        "OFFSET -1\n"
        "jmp 2f\n"
        "1: ADDRESS jc_stack_destination, ax\n"
#ifdef __i386__
        "pushl %eax\n"
#else
        "pushq %rax\n"
#endif
        "OFFSET 0\n"
#ifdef __i386__
        "2: popl %eax\n"
#else
        "2: popq %rax\n"
#endif
        "ADJUST\n"
#ifdef __i386__
        "pushl %eax\n"
        "pushl (%esp)\n"
#else
        "pushq %rax\n"
        "pushq (%rsp)\n"
#endif
        "ret\n"
        "START jc_stack_destination\n"
#ifdef __i386__
        "addl $4, %esp\n"
#else
        "addq $8, %rsp\n"
#endif
        "movl $7, %eax\n"
        "ret\n"
        "START jc_dynamic\n"
        "INPUT\n"
        "testl %ecx, %ecx\n"
        "jz 1f\n"
        "ADDRESS jc_dynamic_eight, ax\n"
        "jmp 2f\n"
        "1: ADDRESS jc_dynamic_seven, ax\n"
        "2: FINISH\n"
        "START jc_dynamic_seven\n"
        "movl $7, %eax\n"
        "ret\n"
        "START jc_dynamic_eight\n"
        "movl $8, %eax\n"
        "ret\n"
        "START jc_cap\n"
        "INPUT\n"
        ".macro CHOICE value\n"
        "cmpl $\\value, %ecx\n"
        "je jc_choice_\\value\n"
        ".endm\n"
        "CHOICE 0\nCHOICE 1\nCHOICE 2\nCHOICE 3\n"
        "CHOICE 4\nCHOICE 5\nCHOICE 6\nCHOICE 7\n"
        "jmp jc_choice_8\n"
        ".macro BLOCK value\n"
        "jc_choice_\\value:\n"
        "movl $\\value, %eax\n"
        "OFFSET -\\value\n"
        "jmp jc_cap_join\n"
        ".endm\n"
        "BLOCK 0\nBLOCK 1\nBLOCK 2\nBLOCK 3\nBLOCK 4\n"
        "BLOCK 5\nBLOCK 6\nBLOCK 7\nBLOCK 8\n"
        "jc_cap_join: ADJUST\n"
        "ADDRESS jc_cap_destination, dx\n"
#ifdef __i386__
        "addl %edx, %eax\n"
#else
        "addq %rdx, %rax\n"
#endif
        "FINISH\n"
        "START jc_cap_destination\n"
        "movl $7, %eax\n"
        "ret\n"
        "START jc_initial_memory\n"
        "ADDRESS jc_cell, dx\n"
#ifdef __i386__
        "pushl (%edx)\n"
#else
        "pushq (%rdx)\n"
#endif
        "ret\n"
        ".data\n"
        ".p2align 3\n"
        "jc_cell: .quad 0\n"
#ifndef __APPLE__
        ".section .note.GNU-stack,\"\",@progbits\n"
#endif
);
