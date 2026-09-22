/* Independent direct-CFG fixtures; IDA ownership is removed only by the probe. */
#ifdef __APPLE__
#define NAME(x) _##x
#else
#define NAME(x) x
#endif

.text
.macro LABEL name
.globl \name
\name:
.endm
.macro BEGIN name
.p2align 4
LABEL \name
#ifdef __i386__
    movl 4(%esp), %ecx
#else
    movl %edi, %ecx
#endif
.endm
.macro GAP name
LABEL \name
    .byte 0xcc, 0xcc, 0xcc
.endm
.macro RESULT
    setb %al
    movzbl %al, %eax
    ret
.endm

/* Eleven instructions plus padding, irrespective of architecture. Both arms
 * and the join are separated by nonexecuted bytes and explicit direct jumps. */
.macro DIAMOND name, conflict, padding
BEGIN \name
    testl %ecx, %ecx
LABEL \name\()_branch
    jz \name\()_right
    jmp \name\()_left
GAP \name\()_root_end
LABEL \name\()_left
    stc
    .rept \padding
    nop
    .endr
    jmp \name\()_join
GAP \name\()_left_end
LABEL \name\()_right
    .if \conflict
    clc
    .else
    stc
    .endif
    jmp \name\()_join
GAP \name\()_right_end
LABEL \name\()_join
    RESULT
GAP \name\()_end
.endm

DIAMOND NAME(od_equal), 0, 0
DIAMOND NAME(od_conflict), 1, 0
DIAMOND NAME(od_budget64), 0, 53
DIAMOND NAME(od_budget65), 0, 54

.p2align 4
LABEL NAME(od_adjacent_root)
    stc
    jmp NAME(od_adjacent_join)
GAP NAME(od_adjacent_root_end)
LABEL NAME(od_adjacent_external)
    clc
LABEL NAME(od_adjacent_join)
    RESULT
GAP NAME(od_adjacent_end)

.p2align 4
LABEL NAME(od_call_root)
#ifdef __i386__
    subl $12, %esp
#else
    subq $8, %rsp
#endif
    stc
    call NAME(od_call_callee)
#ifdef __i386__
    leal 12(%esp), %esp
#else
    leaq 8(%rsp), %rsp
#endif
LABEL NAME(od_call_join)
    RESULT
GAP NAME(od_call_root_end)
LABEL NAME(od_call_callee)
    clc
    ret
GAP NAME(od_call_end)

/* Encoding-only frontier control: BSWAP AX has no portable native result. */
BEGIN NAME(od_frontier_root)
    testl %ecx, %ecx
    jz NAME(od_frontier_unsupported)
    clc
    jmp NAME(od_frontier_join)
GAP NAME(od_frontier_root_end)
LABEL NAME(od_frontier_unsupported)
    .byte 0x66, 0x0f, 0xc8
LABEL NAME(od_frontier_join)
    RESULT
GAP NAME(od_frontier_end)

/* Encoding-only sign-extension controls, deliberately never executed. */
.p2align 4
LABEL NAME(od_negative8)
    .byte 0x6a, 0xff, 0xc3
GAP NAME(od_negative8_end)
.p2align 4
LABEL NAME(od_negative32)
    .byte 0x68, 0xff, 0xff, 0xff, 0xff, 0xc3
GAP NAME(od_negative32_end)

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
