.text
.p2align 4
.globl _rep_lods_two_forward
_rep_lods_two_forward:
    leaq _rep_lods_source+8(%rip), %rsi
    leaq _rep_lods_result(%rip), %rax
    movb $0x5a, (%rsi)
    movb %al, 1(%rsi)
    movb $0x13, %al
    movl $2, %ecx
    cld
    rep lodsb
    pushq %rax
    retq

.p2align 4
.globl _rep_lods_three_reverse
_rep_lods_three_reverse:
    leaq _rep_lods_source+16(%rip), %rsi
    leaq _rep_lods_result(%rip), %rax
    movb %al, -2(%rsi)
    movb $0x33, -1(%rsi)
    movb $0x55, (%rsi)
    movb $0x13, %al
    movl $3, %ecx
    std
    rep lodsb
    cld
    pushq %rax
    retq

.p2align 4
.globl _rep_lods_unknown_df
_rep_lods_unknown_df:
    leaq _rep_lods_source+24(%rip), %rsi
    leaq _rep_lods_result(%rip), %rax
    movb %al, -1(%rsi)
    movb %al, 1(%rsi)
    movb $0x22, (%rsi)
    movb $0x13, %al
    movl $2, %ecx
    rep lodsb
    pushq %rax
    retq

.p2align 4
.globl _rep_lods_unknown_df_forward
_rep_lods_unknown_df_forward:
    cld
    callq _rep_lods_unknown_df
    retq

.p2align 4
.globl _rep_lods_unknown_df_reverse
_rep_lods_unknown_df_reverse:
    std
    callq _rep_lods_unknown_df
    cld
    retq

.p2align 4
.globl _rep_lods_ambiguous_count
_rep_lods_ambiguous_count:
    leaq _rep_lods_source+32(%rip), %rsi
    leaq _rep_lods_result(%rip), %rax
    movb %al, (%rsi)
    movl %edi, %ecx
    andl $1, %ecx
    cld
    rep lodsb
    pushq %rax
    retq

.p2align 4
.globl _rep_lods_eight
_rep_lods_eight:
    leaq _rep_lods_source+56(%rip), %rsi
    leaq _rep_lods_result(%rip), %rax
    movb %al, 7(%rsi)
    movb $0x13, %al
    movl $8, %ecx
    cld
    rep lodsb
    pushq %rax
    retq

.p2align 4
.globl _rep_lods_two_word
_rep_lods_two_word:
    leaq _rep_lods_source+72(%rip), %rsi
    leaq _rep_lods_result(%rip), %rax
    movw %ax, 2(%rsi)
    movw $0x13, %ax
    movl $2, %ecx
    cld
    rep lodsw
    pushq %rax
    retq

.p2align 4
.globl _rep_lods_two_qword
_rep_lods_two_qword:
    leaq _rep_lods_source+80(%rip), %rsi
    leaq _rep_lods_result(%rip), %rax
    movq %rax, 8(%rsi)
    movl $0x13, %eax
    movl $2, %ecx
    cld
    rep lodsq
    pushq %rax
    retq

.p2align 4
.globl _rep_lods_two_dword_value
_rep_lods_two_dword_value:
    leaq _rep_lods_source+104(%rip), %rsi
    movl $0x12345678, 4(%rsi)
    movl $2, %ecx
    cld
    rep lodsl
    cmpl $0x12345678, %eax
    sete %al
    movzbl %al, %eax
    retq

.p2align 4
.globl _rep_lods_nine
_rep_lods_nine:
    leaq _rep_lods_source+40(%rip), %rsi
    leaq _rep_lods_result(%rip), %rax
    movb %al, 8(%rsi)
    movb $0x13, %al
    movl $9, %ecx
    cld
    rep lodsb
    pushq %rax
    retq

.p2align 4
.globl _rep_lods_result
_rep_lods_result:
    movl $73, %eax
    retq

.data
.p2align 4
.globl _rep_lods_source
_rep_lods_source:
    .space 128

.subsections_via_symbols
