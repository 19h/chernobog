// Independent, freestanding i386 oracle. QEMU's multiboot loader supplies flat
// protected mode. Every stub runs under all 64 arithmetic status-flag profiles.
.code32
.section .multiboot,"a"
.align 4
.long 0x1badb002, 0, -(0x1badb002)
.text
.globl _start
.type _start,@function
_start:
    cli
    cld
    movl $stack_top, %esp
    movl $cases, cursor
next_case:
    movl cursor, %eax
    cmpl $0, (%eax)
    je success
    movl $0, profile
next_profile:
    leal -64(%esp), %edi
    movl $16, %ecx
    movl $0xa5a5a5a5, %eax
    rep stosl
    movl profile, %eax
    movl flags(,%eax,4), %eax
    pushl %eax
    popfl
    movl %esp, original_sp
    movl $0x11111111, %eax
    movl $0x22222222, %ecx
    movl $0x33333333, %edx
    movl $0x44444444, %ebx
    movl $0x55555555, %ebp
    movl $0x66666666, %esi
    movl $0x77777777, %edi
    // PUSH/POP and MOV leave the selected arithmetic flags unchanged.
    pushl cursor
    popl current
    // Call through a dedicated cell so every general register has known input.
    // current initially points at the table; resolve it before reseeding EAX.
    movl current, %eax
    movl (%eax), %eax
    movl %eax, current
    movl $0x11111111, %eax
    call *current
    pushfl
    popl actual_flags
    movl %eax, actual_regs
    movl %ecx, actual_regs+4
    movl %edx, actual_regs+8
    movl %ebx, actual_regs+12
    movl %ebp, actual_regs+16
    movl %esi, actual_regs+20
    movl %edi, actual_regs+24
    cmpl original_sp, %esp
    jne failure
    movl profile, %eax
    movl flags(,%eax,4), %eax
    xorl actual_flags, %eax
    testl $0x8d5, %eax
    jne failure
    movl $7, %ecx
    movl $actual_regs, %esi
    movl $expected_regs, %edi
    repe cmpsl
    jne failure
    leal -64(%esp), %edi
    movl $12, %ecx
    movl $0xa5a5a5a5, %eax
    repe scasl
    jne failure
    movl cursor, %eax
    movl 4(%eax), %edx
    cmpl %edx, -8(%esp)
    jne failure
    movl 8(%eax), %edx
    cmpl $0, 16(%eax)
    jne exchange_slots
    cmpl %edx, -16(%esp)
    jne failure
    movl 12(%eax), %edx
    cmpl %edx, -12(%esp)
    jne failure
    jmp checked
exchange_slots:
    cmpl %edx, -12(%esp)
    jne failure
    cmpl $0xa5a5a5a5, -16(%esp)
    jne failure
checked:
    incl profile
    cmpl $64, profile
    jne next_profile
    addl $20, cursor
    jmp next_case
success:
    movl $0x10, %eax
    outl %eax, $0xf4
    hlt
failure:
    movl $0x11, %eax
    outl %eax, $0xf4
    hlt
.size _start, .-_start

.macro SAVE reg, expanded
 .if \expanded
    leal -4(%esp), %esp
    movl %\reg, (%esp)
 .else
    pushl %\reg
 .endif
.endm
.macro STUB name, reg, mask, exchange
 .p2align 4
 .globl \name, \name\()_return, \name\()_handler, \name\()_continuation
 .type \name,@function
\name:
    SAVE \reg, (\mask & 1)
    SAVE \reg, (\mask & 2)
    leal (\name\()_continuation-48), %\reg
    leal 48(%\reg), %\reg
    movl %\reg, 4(%esp)
    leal (\name\()_handler-48), %\reg
    leal 48(%\reg), %\reg
 .if \exchange
    xchgl %\reg, (%esp)
\name\()_return:
    ret
 .else
    SAVE \reg, (\mask & 4)
    movl 4(%esp), %\reg
\name\()_return:
    ret $4
 .endif
 .if (\mask & 1)
    .fill 16,1,0x90
 .endif
\name\()_handler:
    ret
\name\()_continuation:
 #ifdef STACK_STUB_NEGATIVE_CONTROL
    stc
 #endif
 #ifdef STACK_STUB_NEGATIVE_STACK
    movl $0, -60(%esp)
 #endif
    ret
 .size \name, .-\name
.endm
.irp r,eax,ecx,edx,ebx,ebp,esi,edi
 .irp m,0,1,2,3,4,5,6,7
    STUB ss_\r\()_ret_\m, \r, \m, 0
 .endr
 .irp m,0,1,2,3
    STUB ss_\r\()_xchg_\m, \r, \m, 1
 .endr
.endr
.section .rodata
.align 4
expected_regs:
.long 0x11111111,0x22222222,0x33333333,0x44444444,0x55555555,0x66666666,0x77777777
flags:
.set f,0
.rept 64
.long 2 | ((f & 1)) | ((f & 2)<<1) | ((f & 4)<<2) | ((f & 8)<<3) | ((f & 16)<<3) | ((f & 32)<<6)
.set f,f+1
.endr
.macro CASE name, saved, exchange
.long \name, \name\()_continuation, \name\()_handler, \saved, \exchange
.endm
cases:
.set saved,0
.irp r,eax,ecx,edx,ebx,ebp,esi,edi
 .ifc \r,eax
 .set saved,0x11111111
 .endif
 .ifc \r,ecx
 .set saved,0x22222222
 .endif
 .ifc \r,edx
 .set saved,0x33333333
 .endif
 .ifc \r,ebx
 .set saved,0x44444444
 .endif
 .ifc \r,ebp
 .set saved,0x55555555
 .endif
 .ifc \r,esi
 .set saved,0x66666666
 .endif
 .ifc \r,edi
 .set saved,0x77777777
 .endif
 .irp m,0,1,2,3,4,5,6,7
    CASE ss_\r\()_ret_\m, saved, 0
 .endr
 .irp m,0,1,2,3
    CASE ss_\r\()_xchg_\m, saved, 1
 .endr
.endr
.long 0
.data
cursor: .long 0
current: .long 0
profile: .long 0
original_sp: .long 0
actual_flags: .long 0
actual_regs: .space 28
.bss
.align 16
stack: .space 16384
stack_top:
.section .note.GNU-stack,"",@progbits
