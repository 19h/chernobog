/* Inspection limits: 140 independent local CF facts and a 64-instruction prefix. */
.section __TEXT,__text,regular,pure_instructions
.p2align 4
.globl _main
_main:
    xorl %eax, %eax
    retq

.p2align 4
.globl _ve_many
_ve_many:
    .rept 140
    stc
    jc 1f
    nop
1:
    nop
    .endr
    retq

.p2align 4
.globl _ve_deep
_ve_deep:
    stc
    .rept 63
    nop
    .endr
    jc 2f
    nop
2:
    retq
.subsections_via_symbols
