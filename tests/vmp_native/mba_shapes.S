/* Independent native shapes for typed MBA/canonicalization review. */
.text
.p2align 4
.globl _mba_demorgan32
_mba_demorgan32:
    movl %edi, %eax
    notl %eax
    movl %esi, %ecx
    notl %ecx
    orl %ecx, %eax
    notl %eax
    ret
.globl _mba_carry32
_mba_carry32:
    movl %edi, %eax
    andl %esi, %eax
    orl %esi, %edi
    addl %edi, %eax
    ret
.globl _mba_carry64
_mba_carry64:
    movq %rdi, %rax
    andq %rsi, %rax
    orq %rsi, %rdi
    addq %rdi, %rax
    ret
.globl _mba_stack32
_mba_stack32:
    subq $16, %rsp
    movl %edi, (%rsp)
    movl %esi, 4(%rsp)
    movl (%rsp), %eax
    andl 4(%rsp), %eax
    movl (%rsp), %ecx
    orl 4(%rsp), %ecx
    addl %ecx, %eax
    addq $16, %rsp
    ret
.globl _mba_truncate8
_mba_truncate8:
    movl %edi, %eax
    addb %sil, %al
    movzbl %al, %eax
    ret
.globl _mba_extend_not
_mba_extend_not:
    movl %edi, %eax
    notb %al
    movzbl %al, %eax
    ret
.globl _mba_not_extend
_mba_not_extend:
    movzbl %dil, %eax
    notl %eax
    ret
.globl _mba_alias_write
_mba_alias_write:
    movl (%rdi), %eax
    movl %esi, (%rdi)
    xorl (%rdi), %eax
    ret
.globl _mba_alias_partial
_mba_alias_partial:
    movl (%rdi), %eax
    movw %si, (%rdi)
    xorl (%rdi), %eax
    ret
.globl _mba_order32
_mba_order32:
    movl %edi, %eax
    xorl %esi, %eax
    movl %edi, %ecx
    andl %esi, %ecx
    addl %ecx, %ecx
    addl %ecx, %eax
    xorl %edx, %eax
    xorl %edx, %eax
    ret
