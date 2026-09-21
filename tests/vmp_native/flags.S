/* Original instruction semantics are executed separately by x86_abstract_tests.
 * These functions exercise the production IDA adapter and CFG consumer. */
.section __TEXT,__text,regular,pure_instructions
.p2align 4
.globl _main
_main:
    xorl %eax, %eax
    retq

.macro VF_BEGIN name
.p2align 4
.globl _\name
_\name:
.endm

.macro VF_END branch
    \branch 1f
    movl $3, %eax
    retq
1:
    movl $7, %eax
    retq
.endm

.macro VF_ZERO name, branch
VF_BEGIN \name
    xorl %eax, %eax
VF_END \branch
.endm

VF_ZERO vf_o, jo
VF_ZERO vf_no, jno
VF_ZERO vf_b, jb
VF_ZERO vf_ae, jae
VF_ZERO vf_e, je
VF_ZERO vf_ne, jne
VF_ZERO vf_be, jbe
VF_ZERO vf_a, ja
VF_ZERO vf_s, js
VF_ZERO vf_ns, jns
VF_ZERO vf_p, jp
VF_ZERO vf_np, jnp
VF_ZERO vf_l, jl
VF_ZERO vf_ge, jge
VF_ZERO vf_le, jle
VF_ZERO vf_g, jg

VF_BEGIN vf_cmc
    clc
    cmc
VF_END jb

VF_BEGIN vf_inc_cf
    stc
    incl %edi
VF_END jb

VF_BEGIN vf_bswap
    xorl %eax, %eax
    bswapl %edi
VF_END je

VF_BEGIN vf_long_window
    xorl %eax, %eax
    .rept 40
    nop
    .endr
VF_END je

VF_BEGIN vf_stc_zf
    xorl %eax, %eax
    stc
VF_END je

VF_BEGIN vf_overflow
    movb $127, %al
    addb $1, %al
VF_END jo

VF_BEGIN vf_ah
    xorl %eax, %eax
    movb $128, %ah
    testw %ax, %ax
VF_END js

VF_BEGIN vf_zero_extend
    movq $-1, %rax
    movl $1, %eax
    testq %rax, %rax
VF_END jns

VF_BEGIN vf_set_false
    xorl %eax, %eax
    setnz %al
    testb %al, %al
VF_END je

VF_BEGIN vf_set_true
    xorl %eax, %eax
    setz %al
    cmpb $1, %al
VF_END je

VF_BEGIN vf_cmov_false32
    movq $-1, %rax
    xorl %ecx, %ecx
    cmovnz %ecx, %eax
    testq %rax, %rax
VF_END jns

VF_BEGIN vf_unknown_input
    testl %edi, %edi
VF_END je

VF_BEGIN vf_unknown_carry
    cmc
VF_END jb

VF_BEGIN vf_unknown_count
    xorl %eax, %eax
    shll %cl, %eax
VF_END je

VF_BEGIN vf_alias_unknown
    xorl %eax, %eax
    movb %dl, %ah
    testw %ax, %ax
VF_END je

VF_BEGIN vf_call_barrier
    xorl %eax, %eax
    callq _vf_clobber
VF_END je

VF_BEGIN vf_clobber
    addl $1, %eax
    retq

VF_BEGIN vf_alternate_entry
    testl %edi, %edi
    jnz 2f
    xorl %eax, %eax
2:
    /* The second Jcc must not inherit XOR facts from only one predecessor. */
VF_END je

.subsections_via_symbols
