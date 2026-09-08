/* x86-64 macOS recurrent-switch guards; local labels preserve function extents.
 * decode(s) = ((s ^ 0x9e3779b9) + 0x13579bdf) ^ 0x2468ace0 (mod 2^32).
 * Eight cases give seven distinct recurrent edges and one terminal edge.
 */
.section __TEXT,__text,regular,pure_instructions

.macro RG_FUNCTION name, mode
.p2align 4
.globl _\name
_\name:
.cfi_startproc
    pushq %rbp
    movq %rsp, %rbp
    subq $16, %rsp
    movl %edi, -8(%rbp)
    xorl %esi, %esi
.if \mode >= 10
    movl $0x9e3779b9, %r10d
.else
    xorl %r10d, %r10d
.endif
    xorl %r11d, %r11d
.if \mode == 5
    leaq -4(%rbp), %rdx
    movq %rdx, _rg_escape_ptr(%rip)
.endif
.if \mode == 9
L_\name\()_entry_cycle:
    incl %r10d
    cmpl %edi, %r10d
    jl L_\name\()_entry_cycle
.endif
    movl $(((0 ^ 0x2468ace0) - 0x13579bdf) ^ 0x9e3779b9), -4(%rbp)
L_\name\()_dispatcher:
.if \mode == 4
    incl _rg_guard_hits(%rip)
.endif
.if \mode == 8
    incl %r11d
.endif
.if \mode == 9
    cmpl $1, %r10d
    ja L_\name\()_dispatcher
.endif
    movl -4(%rbp), %eax
.if \mode >= 10
    xorl %r10d, %eax
.else
    xorl $0x9e3779b9, %eax
.endif
    addl $0x13579bdf, %eax
    xorl $0x2468ace0, %eax
L_\name\()_guard:
    cmpl $8, %eax
    ja L_\name\()_dispatcher
    cmpl $7, %eax
    ja L_\name\()_dispatcher
L_\name\()_switch:
    leaq L_\name\()_table(%rip), %rdx
    movslq (%rdx,%rax,4), %rcx
    addq %rdx, %rcx
    jmpq *%rcx
.irp state,0,1,2,3,4,5,6,7
L_\name\()_case\state:
.if \mode == 8
    addl %r11d, %esi
.else
    addl $(1 << \state), %esi
.endif
.if \state == 7
    movl %esi, %eax
    leave
    retq
.else
.if \mode >= 10 && \state == 3
    /* Separate blocks retain a real save/overwrite/use/restore at LOCOPT. */
    movl %r10d, %r9d
    testl %edi, %edi
    jnz L_\name\()_overwrite_nonzero
    movl $1, %r10d
    jmp L_\name\()_restore
L_\name\()_overwrite_nonzero:
    movl $2, %r10d
L_\name\()_restore:
    addl %r10d, %esi
    movl %r9d, %r10d
.if \mode == 11
    /* Good key XOR 15 makes the next encoded state 4 decode to 9. */
    xorl $15, %r10d
.endif
.endif
.if \mode == 6 && \state == 0
    movl $1, %r10d
.endif
.if \mode == 6 && \state == 1
    testl %r10d, %r10d
    jnz L_\name\()_register_ok
    movl $(((9 ^ 0x2468ace0) - 0x13579bdf) ^ 0x9e3779b9), -4(%rbp)
    jmp L_\name\()_dispatcher
L_\name\()_register_ok:
.endif
.if \mode == 2 && \state == 3
    movl $(((9 ^ 0x2468ace0) - 0x13579bdf) ^ 0x9e3779b9), -4(%rbp)
.elseif \mode == 3 && \state == 3
    movl -8(%rbp), %edx
    movl %edx, -4(%rbp)
.elseif \mode == 5 && \state == 3
    movq _rg_escape_ptr(%rip), %rdx
    movl $(((4 ^ 0x2468ace0) - 0x13579bdf) ^ 0x9e3779b9), (%rdx)
.else
    movl $((((\state + 1) ^ 0x2468ace0) - 0x13579bdf) ^ 0x9e3779b9), -4(%rbp)
.endif
.if \mode == 7 && \state == 3
    jmp L_\name\()_guard
.else
    jmp L_\name\()_dispatcher
.endif
.endif
.endr
.cfi_endproc
.p2align 2
L_\name\()_table:
.irp state,0,1,2,3,4,5,6,7
    .long L_\name\()_case\state - L_\name\()_table
.endr
.section __TEXT,__const
.globl _\name\()_offsets
_\name\()_offsets:
    .long L_\name\()_dispatcher - _\name
    .long L_\name\()_guard - _\name
    .long L_\name\()_switch - _\name
.irp state,0,1,2,3,4,5,6,7
    .long L_\name\()_case\state - _\name
.endr
.section __TEXT,__text,regular,pure_instructions
.endm

RG_FUNCTION rg_positive, 1
RG_FUNCTION rg_late_guard, 2
RG_FUNCTION rg_unknown_guard, 3
RG_FUNCTION rg_global_effect, 4
RG_FUNCTION rg_escaped_state, 5
RG_FUNCTION rg_recurrence_register, 6
RG_FUNCTION rg_middle_entry, 7
RG_FUNCTION rg_register_effect, 8
RG_FUNCTION rg_entry_cycle, 9
RG_FUNCTION rg_restored_selector, 10
RG_FUNCTION rg_corrupted_restore, 11

.section __DATA,__data
.p2align 3
.globl _rg_escape_ptr
_rg_escape_ptr:
    .quad 0
.globl _rg_guard_hits
_rg_guard_hits:
    .long 0
.subsections_via_symbols
