/* Capture lies outside the admitted sequence. The indirect jump is executed
 * and reaches the capture label through a table or signed relative offset. */
.text
.globl _vm_semantic_run, _vm_semantic_capture
_vm_semantic_run:
  pushq %rbx
  pushq %r12
  movq %rdi, %r12
  movq 8(%r12), %rbx
  leaq 0(%r12), %rsi
  testl $2, %edx
  jnz Lrelative_setup
  movq 24(%r12), %rdi
  testl $1, %edx
  jz Ltable_forward_setup
  addq $1, %rsi
  movq %rsi, 32(%r12)
  movq %rdi, 40(%r12)
  movq %rsp, 48(%r12)
Ltable_backward:
  subq $1, %rsi
  movzbl (%rsi), %eax
  xorb %bl, %al
  rolb $3, %al
  addb $7, %al
  xorb %al, %bl
  jmpq *(%rdi,%rax,8)
Ltable_forward_setup:
  movq %rsi, 32(%r12)
  movq %rdi, 40(%r12)
  movq %rsp, 48(%r12)
Ltable_forward:
  movzbl (%rsi), %eax
  addq $1, %rsi
  xorb %bl, %al
  rolb $3, %al
  addb $7, %al
  xorb %al, %bl
  jmpq *(%rdi,%rax,8)
Lrelative_setup:
  leaq _vm_semantic_capture(%rip), %rdi
  subq 16(%r12), %rdi
  testl $1, %edx
  jz Lrelative_forward_setup
  addq $4, %rsi
  movq %rsi, 32(%r12)
  movq %rdi, 40(%r12)
  movq %rsp, 48(%r12)
Lrelative_backward:
  subq $4, %rsi
  movl (%rsi), %eax
  xorl %ebx, %eax
  roll $3, %eax
  addl $7, %eax
  pushq %rbx
  xorl %eax, (%rsp)
  popq %rbx
  movslq %eax, %rax
  addq %rax, %rdi
  jmpq *%rdi
Lrelative_forward_setup:
  movq %rsi, 32(%r12)
  movq %rdi, 40(%r12)
  movq %rsp, 48(%r12)
Lrelative_forward:
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
_vm_semantic_capture:
  movq -8(%rsp), %rdx
  movq %rdx, 104(%r12)
  movq %rsp, 88(%r12)
  pushfq
  popq %rdx
  movq %rdx, 96(%r12)
  movq %rsi, 56(%r12)
  movq %rax, 64(%r12)
  movq %rbx, 72(%r12)
  movq %rdi, 80(%r12)
  leaq _vm_semantic_capture(%rip), %rdx
  movq %rdx, 112(%r12)
  popq %r12
  popq %rbx
  retq
