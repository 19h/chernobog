// ARM64 Mach-O fixture for a writable dispatch slot and an inherited frame.
.text
.globl _main
.p2align 2
_main:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str w0, [x29, #16]
    adrp x8, _dispatch_table@PAGE
    ldr x8, [x8, _dispatch_table@PAGEOFF]
    adrp x9, Ldispatch_bias@PAGE
    ldr x9, [x9, Ldispatch_bias@PAGEOFF]
    sub x8, x8, x9
.globl _dispatch_site
_dispatch_site:
    br x8

.globl _dispatch_fragment
.p2align 2
_dispatch_fragment:
    ldr w8, [x29, #16]
    cmp w8, #17
    cset w0, eq
    ldp x29, x30, [sp], #32
    ret

.globl _independent_target
.p2align 2
_independent_target:
    mov w0, #42
    ret

.data
.p2align 3
.globl _dispatch_table
_dispatch_table:
    .quad _dispatch_fragment + 4
Ldispatch_bias:
    .quad 4
