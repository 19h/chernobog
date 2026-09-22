/* i386 cdecl version of conditions.S; no callee-saved fixture registers. */
.text
.macro BEGIN name
.p2align 4
.globl \name
.type \name,@function
\name:
    movl 4(%esp), %eax
    movl 8(%esp), %edx
    xorl %ecx, %ecx
.endm
.macro END name
    ret
.size \name, .-\name
.endm
.macro SET name, cc
BEGIN \name
    set\cc %al
END \name
.endm
.macro CMOV name, cc
BEGIN \name
    cmov\cc %edx, %eax
END \name
.endm
.irp cc,o,no,b,ae,e,ne,be,a,s,ns,p,np,l,ge,le,g
SET vc_\cc, \cc
CMOV vc_cm_\cc, \cc
.endr
BEGIN vc_ah_true
    sete %ah
END vc_ah_true
BEGIN vc_ah_false
    setne %ah
END vc_ah_false
BEGIN vc_mem_true
    movl 12(%esp), %ecx
    sete (%ecx)
END vc_mem_true
BEGIN vc_mem_false
    movl 12(%esp), %ecx
    setne (%ecx)
END vc_mem_false
BEGIN vc_cm16_true
    cmove %dx, %ax
END vc_cm16_true
BEGIN vc_cm16_false
    cmovne %dx, %ax
END vc_cm16_false
BEGIN vc_cm32_true
    cmove %edx, %eax
END vc_cm32_true
BEGIN vc_cm32_false
    cmovne %edx, %eax
END vc_cm32_false
BEGIN vc_cm_mem_true
    movl 12(%esp), %ecx
    cmove (%ecx), %eax
END vc_cm_mem_true
BEGIN vc_cm_mem_false
    movl 12(%esp), %ecx
    cmovne (%ecx), %eax
END vc_cm_mem_false
BEGIN vc_cm_mem16_true
    movl 12(%esp), %ecx
    cmove (%ecx), %ax
END vc_cm_mem16_true
BEGIN vc_cm_mem16_false
    movl 12(%esp), %ecx
    cmovne (%ecx), %ax
END vc_cm_mem16_false
BEGIN vc_cm_mem32_true
    movl 12(%esp), %ecx
    cmove (%ecx), %eax
END vc_cm_mem32_true
BEGIN vc_cm_mem32_false
    movl 12(%esp), %ecx
    cmovne (%ecx), %eax
END vc_cm_mem32_false
BEGIN vc_cm_order_true
    movl 12(%esp), %ecx
    movl $0x11223344, (%ecx)
    cmove (%ecx), %eax
    movl $0x55667788, (%ecx)
END vc_cm_order_true
BEGIN vc_cm_order_false
    movl 12(%esp), %ecx
    movl $0x11223344, (%ecx)
    cmovne (%ecx), %eax
    movl $0x55667788, (%ecx)
END vc_cm_order_false
BEGIN vc_cm_segment
    movl 12(%esp), %ecx
    cmove %gs:(%ecx), %eax
END vc_cm_segment
BEGIN vc_cm_address
    .byte 0x67, 0x0f, 0x44, 0x00 /* CMOVE EAX,[BX+SI]. */
END vc_cm_address
BEGIN vc_unknown
    testl %edx, %edx
    sete %al
END vc_unknown
BEGIN vc_depth
    .rept 8
    nop
    .endr
    sete %al
END vc_depth
BEGIN vc_alternate
    testl %edx, %edx
    jz 1f
    xorl %ecx, %ecx
1:
    sete %al
END vc_alternate

.p2align 4
.globl vc_invoke
.type vc_invoke,@function
vc_invoke:
    pushl %ebx
    movl 8(%esp), %ebx
    pushl 20(%esp)
    pushl 20(%esp)
    pushl 20(%esp)
    call *%ebx
    pushfl
    popl %edx
    movl 36(%esp), %ecx
    movl %edx, (%ecx)
    addl $12, %esp
    popl %ebx
    ret
.size vc_invoke, .-vc_invoke
.section .note.GNU-stack,"",@progbits
