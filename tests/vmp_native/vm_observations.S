// Independently authored x64 fixture: repeated visits to one keyed dispatcher.
// Not a protector-generated binary or an inferred VM execution region.
.text
.globl _main
_main:
    xorl %eax, %eax
    retq

.globl _vm_observe, _vm_observe_end, _vm_observe_dispatch
_vm_observe:
    pushq %rbx
    leaq _vm_observe_bytes(%rip), %rsi
    leaq _vm_observe_table(%rip), %rdi
    movl $0x5a, %ebx
    xorl %edx, %edx
    jmp _vm_observe_dispatch
    nop
_vm_observe_dispatch:
    movzbl (%rsi), %eax
    addq $1, %rsi
    xorb %bl, %al
    rolb $3, %al
    addb $7, %al
    xorb %al, %bl
    jmpq *(%rdi,%rax,8)
    nop
Lagain:
    incq %rdx
    jmp _vm_observe_dispatch
    nop
Ldone:
    popq %rbx
    xorl %eax, %eax
    retq
_vm_observe_end:
    nop

.globl _vm_observe_boundary, _vm_observe_boundary_end, _vm_observe_boundary_dispatch
_vm_observe_boundary:
    pushq %rbx
    leaq _vm_observe_boundary_byte(%rip), %rsi
    leaq _vm_observe_table(%rip), %rdi
    movl $0x5a, %ebx
    jmp _vm_observe_boundary_dispatch
    nop
_vm_observe_boundary_dispatch:
    movzbl (%rsi), %eax
    addq $1, %rsi
    xorb %bl, %al
    rolb $3, %al
    addb $7, %al
    xorb %al, %bl
    jmpq *(%rdi,%rax,8)
_vm_observe_boundary_end:
    nop
.globl _vm_observe_outside, _vm_observe_outside_end
_vm_observe_outside:
    movb $1, _vm_observe_marker(%rip)
    popq %rbx
    retq
_vm_observe_outside_end:
    nop

.globl _vm_observe_relative, _vm_observe_relative_end, _vm_observe_relative_dispatch
_vm_observe_relative:
    pushq %rbx
    movabsq $0x112233445566775a, %rbx
    leaq _vm_observe_relative_bytes(%rip), %rsi
    leaq Lrelative_done+32(%rip), %rdi
    jmp _vm_observe_relative_dispatch
    nop
_vm_observe_relative_dispatch:
    movl (%rsi), %eax
    addq $4, %rsi
    xorl %ebx, %eax
    roll $3, %eax
    addl $7, %eax
    pushq %rbx
    xorl %eax, (%rsp)
    popq %rbx
    movslq %eax, %rax
    addq %rax, %rdi
    jmpq *%rdi
    nop
Lrelative_done:
    popq %rbx
    xorl %eax, %eax
    retq
_vm_observe_relative_end:
    nop

.data
.globl _vm_observe_bytes, _vm_observe_boundary_byte, _vm_observe_marker
_vm_observe_bytes:
    .byte 0x25, 0x67, 0x07
_vm_observe_boundary_byte:
    .byte 0xc5
_vm_observe_marker:
    .byte 0
_vm_observe_relative_bytes:
    .long 0x6a9988a1
.p2align 3
_vm_observe_table:
    .quad Lagain, Ldone, Lagain, _vm_observe_outside
