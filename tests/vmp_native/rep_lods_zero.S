#ifdef __APPLE__
#define NAME(x) _##x
#else
#define NAME(x) x
#endif

.text
.p2align 4
.globl NAME(rep_lods_zero_target)
NAME(rep_lods_zero_target):
#ifdef __i386__
    movl $NAME(rep_lods_result), %eax
    xorl %ecx, %ecx
    xorl %esi, %esi
    rep lodsb
    pushl %eax
#else
    leaq NAME(rep_lods_result)(%rip), %rax
    xorl %ecx, %ecx
    xorl %esi, %esi
    rep lodsb
    pushq %rax
#endif
    ret

.p2align 4
.globl NAME(rep_lods_result)
NAME(rep_lods_result):
    movl $73, %eax
    ret

#ifdef __APPLE__
.subsections_via_symbols
#endif
