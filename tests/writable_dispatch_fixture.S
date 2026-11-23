// ARM64 Mach-O fixture for a writable dispatch slot and an inherited frame.
.text
.globl _main
.p2align 2
_main:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str w0, [x29, #16]
    adrp x10, Ldispatch_index@PAGE
    ldr w10, [x10, Ldispatch_index@PAGEOFF]
    str w10, [x29, #20]
    // The visible store keeps both predecessors of the dispatch live.
    cbz w0, Ldispatch_join
    adrp x11, Ldispatch_marker@PAGE
    str w0, [x11, Ldispatch_marker@PAGEOFF]
Ldispatch_join:
    ldr w10, [x29, #20]
    adrp x8, _dispatch_table@PAGE
    add x8, x8, _dispatch_table@PAGEOFF
    ldr x8, [x8, w10, uxtw #3]
    adrp x9, Ldispatch_bias@PAGE
    ldr x9, [x9, Ldispatch_bias@PAGEOFF]
    sub x8, x8, x9
.globl _dispatch_site
_dispatch_site:
    br x8

.globl _dispatch_fragment
.p2align 2
_dispatch_fragment:
    // The continuation first uses the inherited frame after a returning call.
    bl _independent_target
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
Ldispatch_index:
    .long 0
Ldispatch_marker:
    .long 0
