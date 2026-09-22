// Independent native oracle: decrypt, read individual bytes, erase and release.
// The probe joins observed read sites to exact source-expression addresses.
.section __TEXT,__text,regular,pure_instructions
.p2align 4
.globl _native_read_strings
_native_read_strings:
    pushq %rbx
    pushq %r12
    pushq %r13
    xorl %r12d, %r12d
    xorl %r13d, %r13d
    movl $16, %edi
    callq _malloc
    movq %rax, %rbx
    movabsq $0x5a7b2e3f28393f29, %rdx
    movq %rdx, (%rbx)
    movq Lnative_key(%rip), %rdx
    xorq %rdx, (%rbx)
    xorl %eax, %eax
Lnative_read_first:
    movzbl (%rbx,%rax), %edx
    testb %dl, %dl
    je Lfirst_done
    movl %eax, %ecx
    shll $3, %ecx
    shlq %cl, %rdx
    orq %rdx, %r12
    incq %rax
    jmp Lnative_read_first
Lfirst_done:
    movq %rbx, %rdi
    xorl %esi, %esi
    movl $16, %edx
    callq _memset
    movq %rbx, %rdi
    callq _free
    movl $16, %edi
    callq _malloc
    movq %rax, %rbx
    movabsq $0x5a7b3e3435393f29, %rdx
    movq %rdx, (%rbx)
    movq Lnative_key(%rip), %rdx
    xorq %rdx, (%rbx)
    xorl %eax, %eax
Lnative_read_second:
    movzbl (%rbx,%rax), %edx
    testb %dl, %dl
    je Lsecond_done
    movl %eax, %ecx
    shll $3, %ecx
    shlq %cl, %rdx
    orq %rdx, %r13
    incq %rax
    jmp Lnative_read_second
Lsecond_done:
    movq %rbx, %rdi
    xorl %esi, %esi
    movl $16, %edx
    callq _memset
    movq %rbx, %rdi
    callq _free
    movq %r12, %rax
    movq %r13, %rdx
    popq %r13
    popq %r12
    popq %rbx
    retq

.p2align 4
.globl _main
_main:
    subq $8, %rsp
    callq _native_read_strings
    // Check all consumed bytes, not just lengths or a hash. Re-encrypt the
    // register-packed native reads so plaintext constants stay out of the file.
    movabsq $0x5a5a5a5a5a5a5a5a, %rcx
    xorq %rcx, %rax
    xorq %rcx, %rdx
    movabsq $0x5a7b2e3f28393f29, %rcx
    cmpq %rcx, %rax
    setne %al
    movabsq $0x5a7b3e3435393f29, %rcx
    cmpq %rcx, %rdx
    setne %cl
    orb %al, %cl
    movzbl %cl, %eax
    addq $8, %rsp
    retq

.section __DATA,__const
.p2align 3
.globl _native_read_key
_native_read_key:
Lnative_key:
    .quad 0x5a5a5a5a5a5a5a5a
.subsections_via_symbols
