// Independent i386 SysV fixture. Only the two transform bodies are protected.
.text
.globl corpus_transform
.type corpus_transform,@function
corpus_transform:
    movl 12(%esp), %edx
    movl (%edx), %eax
    xorl 4(%esp), %eax
    roll $5, %eax
    addl 8(%esp), %eax
    movl %eax, (%edx)
    ret
.size corpus_transform, .-corpus_transform
.globl corpus_transform_end
corpus_transform_end:
    nop

.globl corpus_branch
.type corpus_branch,@function
corpus_branch:
    movl 12(%esp), %edx
    movl 4(%esp), %ecx
    cmpl 8(%esp), %ecx
    jb .Lless
    movl (%edx), %eax
    xorl %ecx, %eax
    jmp .Ljoin
.Lless:
    movl (%edx), %eax
    xorl 8(%esp), %eax
.Ljoin:
    roll $5, %eax
    addl 8(%esp), %eax
    movl %eax, (%edx)
    ret
.size corpus_branch, .-corpus_branch
.globl corpus_branch_end
corpus_branch_end:
    nop

// capture(function, x, y, memory, observation), cdecl. Three arguments leave
// ESP 16-byte aligned before CALL. Observe flags before caller arithmetic.
.globl corpus_capture
.type corpus_capture,@function
corpus_capture:
    pushl %ebx
    pushl %esi
    pushl %edi
    pushl %ebp
    movl %esp, %ebp
    movl 20(%ebp), %ebx
    movl 36(%ebp), %edi
    pushl 32(%ebp)
    pushl 28(%ebp)
    pushl 24(%ebp)
    call *%ebx
    pushfl
    popl %ecx
    movl %eax, 0(%edi)
    movl $0, 4(%edi)
    movl %ecx, 8(%edi)
    movl $0, 12(%edi)
    movl %esp, %eax
    subl %ebp, %eax
    addl $12, %eax
    cltd
    movl %eax, 16(%edi)
    movl %edx, 20(%edi)
    movl %ebp, %esp
    popl %ebp
    popl %edi
    popl %esi
    popl %ebx
    ret
.size corpus_capture, .-corpus_capture
.section .note.GNU-stack,"",@progbits
