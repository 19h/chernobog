/* Large owned functions with bounded joins, loops and transfer sources. */
#ifdef __APPLE__
#define NAME(x) _##x
#else
#define NAME(x) x
#endif

.text
.macro START name, padding
.p2align 4
.globl \name
\name:
.rept \padding
    nop
.endr
#ifdef __i386__
    movl 4(%esp), %ecx
#else
    movl %edi, %ecx
#endif
.endm
.macro END name, condition
    \condition %al
    movzbl %al, %eax
    ret
.globl \name
\name:
.endm
.macro DIAMOND name, end, padding, other
START \name, \padding
    testl %ecx, %ecx
    jz 1f
    movl $42, %eax
    jmp 2f
1:  movl $\other, %eax
2:  cmpl $42, %eax
END \end, sete
.endm

DIAMOND NAME(slice_equal192), NAME(slice_equal192_end), 192, 42
DIAMOND NAME(slice_different192), NAME(slice_different192_end), 192, 41
DIAMOND NAME(slice_inventory4096), NAME(slice_inventory4096_end), 4086, 42
DIAMOND NAME(slice_inventory4097), NAME(slice_inventory4097_end), 4087, 42

START NAME(slice_flags192), 192
    testl %ecx, %ecx
    jz 1f
    stc
    jmp 2f
1:  stc
2:
END NAME(slice_flags192_end), setb

START NAME(slice_loop192), 192
    stc
1:  decl %ecx
    jnz 1b
END NAME(slice_loop192_end), setb

START NAME(slice_cut192), 0
    stc
.rept 192
    nop
.endr
    decl %ecx
    jz 1f
    nop
    jmp 2f
1:  nop
2:
END NAME(slice_cut192_end), setb

.macro DESTINATION
#ifdef __i386__
    movl $NAME(slice_destination), %eax
#else
    leaq NAME(slice_destination)(%rip), %rax
#endif
.endm
.macro STORE
#ifdef __i386__
    movl %eax, NAME(slice_cell)
#else
    movq %rax, NAME(slice_cell)(%rip)
#endif
.endm
START NAME(slice_target192), 192
    testl %ecx, %ecx
    jz 1f
    DESTINATION
    jmp 2f
1:  DESTINATION
2:
#ifdef __i386__
    pushl %eax
#else
    pushq %rax
#endif
    ret
.globl NAME(slice_target192_end)
NAME(slice_target192_end):

START NAME(slice_memory192), 192
    testl %ecx, %ecx
    jz 1f
    DESTINATION
    STORE
    jmp 2f
1:  DESTINATION
    STORE
2:
#ifdef __i386__
    pushl NAME(slice_cell)
#else
    pushq NAME(slice_cell)(%rip)
#endif
    ret
.globl NAME(slice_memory192_end)
NAME(slice_memory192_end):

.p2align 4
.globl NAME(slice_destination)
NAME(slice_destination):
    movl $7, %eax
    ret
.globl NAME(slice_destination_end)
NAME(slice_destination_end):

.p2align 4
.globl NAME(slice_external)
NAME(slice_external):
    ret

START NAME(slice_prefix8), 192
    stc
.rept 7
    nop
.endr
END NAME(slice_prefix8_end), setb

.data
.p2align 3
.globl NAME(slice_cell)
NAME(slice_cell):
#ifdef __i386__
    .long 0
#else
    .quad 0
#endif

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
