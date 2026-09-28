// Executed ELF32 PUSH imm32; RET target with two unentered decoding controls.
.code32
.text
.p2align 4
.globl _start
.type _start,@function
_start:
    call pi32_immediate
    cmpl $7, %eax
    jne pi32_fail
    movl $1, %eax
    xorl %ebx, %ebx
    int $0x80
pi32_fail:
    movl $1, %eax
    movl $1, %ebx
    int $0x80

.p2align 4
.globl pi32_immediate
.type pi32_immediate,@function
pi32_immediate:
    .byte 0x68
    .long pi32_target
    ret

.p2align 4
.globl pi32_target
.type pi32_target,@function
pi32_target:
    movl $7, %eax
    ret

.p2align 4
.globl pi32_negative_byte
.type pi32_negative_byte,@function
pi32_negative_byte:
    .byte 0x6a, 0x80
    ret

.p2align 4
.globl pi32_operand_override
.type pi32_operand_override,@function
pi32_operand_override:
    .byte 0x66, 0x6a, 0x80
    ret

.section .note.GNU-stack,"",@progbits
