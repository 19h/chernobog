/* All architectural Jcc codes, exact profiles and uncertain-path controls. */
__asm__(
    ".text\n"
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
    ".macro ADDRESS name, reg\n"
#ifdef __i386__
    "movl $\\name, %e\\reg\n"
#else
    "leaq \\name(%rip), %r\\reg\n"
#endif
    ".endm\n"
    ".macro FLAGS profile\n"
#ifdef __i386__
    "pushl $((\\profile & 1) | ((\\profile & 2)<<1) | ((\\profile & 4)<<2) | ((\\profile & 8)<<3) | ((\\profile & 16)<<3) | ((\\profile & 32)<<6) | 2)\n"
    "popfl\n"
#else
    "pushq $((\\profile & 1) | ((\\profile & 2)<<1) | ((\\profile & 4)<<2) | ((\\profile & 8)<<3) | ((\\profile & 16)<<3) | ((\\profile & 32)<<6) | 2)\n"
    "popfq\n"
#endif
    ".endm\n"
    ".macro INPUT_FLAGS\n"
#ifdef __i386__
    "movl 4(%esp), %ecx\n"
    "pushl %ecx\n"
    "popfl\n"
#else
    "movl %edi, %ecx\n"
    "pushq %rcx\n"
    "popfq\n"
#endif
    ".endm\n"
    ".macro SOURCE kind\n"
    ".if \\kind == 1\n"
#ifdef __i386__
    "movl %eax, (%edx)\n"
#else
    "movq %rax, (%rdx)\n"
#endif
    ".elseif \\kind == 2\n"
#ifdef __i386__
    "pushl %eax\n"
#else
    "pushq %rax\n"
#endif
    ".endif\n"
    ".endm\n"
    ".macro FINISH kind\n"
#ifdef __i386__
    ".if \\kind == 1\n pushl (%edx)\n"
    ".elseif \\kind == 2\n pushl (%esp)\n"
    ".else\n pushl %eax\n.endif\n"
#else
    ".if \\kind == 1\n pushq (%rdx)\n"
    ".elseif \\kind == 2\n pushq (%rsp)\n"
    ".else\n pushq %rax\n.endif\n"
#endif
    "ret\n"
    ".endm\n"
    ".macro CASE name, branch, profile, truth, kind=0\n"
    "START \\name\n"
    "FLAGS \\profile\n"
    ".if \\kind == 1\n ADDRESS bf_cell, dx\n.endif\n"
    "\\branch 1f\n"
    ".if \\kind == 2\n"
    ".if \\truth\n ADDRESS bf_stack_eight, ax\n"
    ".else\n ADDRESS bf_stack_seven, ax\n.endif\n"
    ".else\n"
    ".if \\truth\n ADDRESS bf_eight, ax\n"
    ".else\n ADDRESS bf_seven, ax\n.endif\n.endif\n"
    "SOURCE \\kind\n"
    "jmp 2f\n"
    "1:\n"
    ".if \\kind == 2\n"
    ".if \\truth\n ADDRESS bf_stack_seven, ax\n"
    ".else\n ADDRESS bf_stack_eight, ax\n.endif\n"
    ".else\n"
    ".if \\truth\n ADDRESS bf_seven, ax\n"
    ".else\n ADDRESS bf_eight, ax\n.endif\n.endif\n"
    "SOURCE \\kind\n"
    "2: FINISH \\kind\n"
    ".endm\n"
    ".macro DYNAMIC name, branch\n"
    "START \\name\n"
    "INPUT_FLAGS\n"
    "\\branch 1f\n"
    "ADDRESS bf_eight, ax\n"
    "jmp 2f\n"
    "1: ADDRESS bf_seven, ax\n"
    "2: FINISH 0\n"
    ".endm\n"
    "CASE bf_o_false, jo, 0, 0\n CASE bf_o_true, jo, 32, 1\n"
    "CASE bf_no_false, jno, 32, 0\n CASE bf_no_true, jno, 0, 1\n"
    "CASE bf_b_false, jb, 0, 0\n CASE bf_b_true, jb, 1, 1\n"
    "CASE bf_ae_false, jae, 1, 0\n CASE bf_ae_true, jae, 0, 1\n"
    "CASE bf_e_false, je, 0, 0\n CASE bf_e_true, je, 8, 1\n"
    "CASE bf_ne_false, jne, 8, 0\n CASE bf_ne_true, jne, 0, 1\n"
    "CASE bf_be_false, jbe, 0, 0\n CASE bf_be_true, jbe, 1, 1\n"
    "CASE bf_a_false, ja, 1, 0\n CASE bf_a_true, ja, 0, 1\n"
    "CASE bf_s_false, js, 0, 0\n CASE bf_s_true, js, 16, 1\n"
    "CASE bf_ns_false, jns, 16, 0\n CASE bf_ns_true, jns, 0, 1\n"
    "CASE bf_p_false, jp, 0, 0\n CASE bf_p_true, jp, 2, 1\n"
    "CASE bf_np_false, jnp, 2, 0\n CASE bf_np_true, jnp, 0, 1\n"
    "CASE bf_l_false, jl, 0, 0\n CASE bf_l_true, jl, 16, 1\n"
    "CASE bf_ge_false, jge, 16, 0\n CASE bf_ge_true, jge, 0, 1\n"
    "CASE bf_le_false, jle, 0, 0\n CASE bf_le_true, jle, 8, 1\n"
    "CASE bf_g_false, jg, 8, 0\n CASE bf_g_true, jg, 0, 1\n"
    "CASE bf_memory_false, jc, 0, 0, 1\n CASE bf_memory_true, jc, 1, 1, 1\n"
    "CASE bf_stack_false, jc, 0, 0, 2\n CASE bf_stack_true, jc, 1, 1, 2\n"
    "DYNAMIC bf_o_dynamic, jo\n DYNAMIC bf_no_dynamic, jno\n"
    "DYNAMIC bf_b_dynamic, jb\n DYNAMIC bf_ae_dynamic, jae\n"
    "DYNAMIC bf_e_dynamic, je\n DYNAMIC bf_ne_dynamic, jne\n"
    "DYNAMIC bf_be_dynamic, jbe\n DYNAMIC bf_a_dynamic, ja\n"
    "DYNAMIC bf_s_dynamic, js\n DYNAMIC bf_ns_dynamic, jns\n"
    "DYNAMIC bf_p_dynamic, jp\n DYNAMIC bf_np_dynamic, jnp\n"
    "DYNAMIC bf_l_dynamic, jl\n DYNAMIC bf_ge_dynamic, jge\n"
    "DYNAMIC bf_le_dynamic, jle\n DYNAMIC bf_g_dynamic, jg\n"
    ".macro COMPOUND name, second\n"
    "START \\name\n"
#ifdef __i386__
    "movl 4(%esp), %ecx\n"
#else
    "movl %edi, %ecx\n"
#endif
    "testl %ecx, %ecx\n"
    "jz 1f\n"
    "FLAGS 1\n"
    "jmp 2f\n"
    "1: FLAGS \\second\n"
    "2: jbe 3f\n"
    "ADDRESS bf_eight, ax\n"
    "jmp 4f\n"
    "3: ADDRESS bf_seven, ax\n"
    "4: FINISH 0\n"
    ".endm\n"
    "COMPOUND bf_compound, 8\n"
    "COMPOUND bf_compound_dynamic, 0\n"
    "START bf_loop\n"
    "stc\n"
    "1: jnc 2f\n"
    "clc\n"
    "jmp 1b\n"
    "2: ADDRESS bf_eight, ax\n"
    "FINISH 0\n"
    "START bf_seven\n movl $7, %eax\n ret\n"
    "START bf_eight\n movl $8, %eax\n ret\n"
    "START bf_stack_seven\n"
#ifdef __i386__
    "addl $4, %esp\n"
#else
    "addq $8, %rsp\n"
#endif
    "movl $7, %eax\n ret\n"
    "START bf_stack_eight\n"
#ifdef __i386__
    "addl $4, %esp\n"
#else
    "addq $8, %rsp\n"
#endif
    "movl $8, %eax\n ret\n"
    ".data\n .p2align 3\n bf_cell: .quad 0\n"
#ifndef __APPLE__
    ".section .note.GNU-stack,\"\",@progbits\n"
#endif
);
