/* Register inputs: RDI destination, RSI source, RDX writable byte pointer.
 * Only caller-saved registers are modified. Each function returns full RAX. */
.section __TEXT,__text,regular,pure_instructions
.macro BEGIN name
.p2align 4
.globl _\name
_\name:
    movq %rdi, %rax
    xorl %ecx, %ecx
.endm
.macro SET name, cc
BEGIN \name
    set\cc %al
    retq
.endm
SET vc_o, o
SET vc_no, no
SET vc_b, b
SET vc_ae, ae
SET vc_e, e
SET vc_ne, ne
SET vc_be, be
SET vc_a, a
SET vc_s, s
SET vc_ns, ns
SET vc_p, p
SET vc_np, np
SET vc_l, l
SET vc_ge, ge
SET vc_le, le
SET vc_g, g

.macro CMOV name, cc
BEGIN \name
    cmov\cc %rsi, %rax
    retq
.endm
CMOV vc_cm_o, o
CMOV vc_cm_no, no
CMOV vc_cm_b, b
CMOV vc_cm_ae, ae
CMOV vc_cm_e, e
CMOV vc_cm_ne, ne
CMOV vc_cm_be, be
CMOV vc_cm_a, a
CMOV vc_cm_s, s
CMOV vc_cm_ns, ns
CMOV vc_cm_p, p
CMOV vc_cm_np, np
CMOV vc_cm_l, l
CMOV vc_cm_ge, ge
CMOV vc_cm_le, le
CMOV vc_cm_g, g

BEGIN vc_ah_true
    sete %ah
    retq
BEGIN vc_ah_false
    setne %ah
    retq
BEGIN vc_mem_true
    sete (%rdx)
    retq
BEGIN vc_mem_false
    setne (%rdx)
    retq
BEGIN vc_cm16_true
    cmove %si, %ax
    retq
BEGIN vc_cm16_false
    cmovne %si, %ax
    retq
BEGIN vc_cm32_true
    cmove %esi, %eax
    retq
BEGIN vc_cm32_false
    cmovne %esi, %eax
    retq
BEGIN vc_cm_mem_true
    cmove (%rdx), %rax
    retq
BEGIN vc_cm_mem_false
    cmovne (%rdx), %rax
    retq
BEGIN vc_cm_mem16_true
    cmove (%rdx), %ax
    retq
BEGIN vc_cm_mem16_false
    cmovne (%rdx), %ax
    retq
BEGIN vc_cm_mem32_true
    cmove (%rdx), %eax
    retq
BEGIN vc_cm_mem32_false
    cmovne (%rdx), %eax
    retq
BEGIN vc_cm_order_true
    movl $0x11223344, (%rdx)
    cmove (%rdx), %eax
    movl $0x55667788, (%rdx)
    retq
BEGIN vc_cm_order_false
    movl $0x11223344, (%rdx)
    cmovne (%rdx), %eax
    movl $0x55667788, (%rdx)
    retq

/* Decode-only rejection controls; deliberately absent from the C call table. */
BEGIN vc_cm_segment
    cmove %gs:(%rdx), %rax
    retq
BEGIN vc_cm_address
    .byte 0x67
    cmove (%rdx), %rax
    retq

.p2align 4
.globl _vc_unknown
_vc_unknown:
    movq %rdi, %rax
    testq %rsi, %rsi
    sete %al
    retq

.p2align 4
.globl _vc_invoke
_vc_invoke:
    pushq %r12
    movq %r8, %r12
    movq %rdi, %rax
    movq %rsi, %rdi
    movq %rdx, %rsi
    movq %rcx, %rdx
    callq *%rax
    pushfq
    popq (%r12)
    popq %r12
    retq
BEGIN vc_depth
    .rept 8
    nop
    .endr
    sete %al
    retq

.p2align 4
.globl _vc_alternate
_vc_alternate:
    movq %rdi, %rax
    testq %rsi, %rsi
    jz 1f
    xorl %ecx, %ecx
1:
    sete %al
    retq
