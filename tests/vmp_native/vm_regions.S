/* Independent local dispatch motifs, not a complete interpreter or protected
 * program. No dispatcher is executed by the inspection probes. */
.text
.globl _vm_table_forward, _vm_table_forward_end
_vm_table_forward:
  movzbl (%rsi), %eax
  addq $1, %rsi
  xorb %bl, %al
  rolb $3, %al
  addb $7, %al
  xorb %al, %bl
  jmpq *(%rdi,%rax,8)
_vm_table_forward_end:
  retq

.globl _vm_table_clone, _vm_table_clone_end
_vm_table_clone:
  movzbl (%r13), %r9d
  addq $1, %r13
  xorb %r8b, %r9b
  rolb $3, %r9b
  addb $7, %r9b
  xorb %r9b, %r8b
  jmpq *(%r10,%r9,8)
_vm_table_clone_end:
  retq

.globl _vm_table_backward, _vm_table_backward_end
_vm_table_backward:
  subq $1, %rsi
  movzbl (%rsi), %eax
  jmpq *(%rdi,%rax,8)
_vm_table_backward_end:
  retq

.globl _vm_relative_backward, _vm_relative_backward_end
_vm_relative_backward:
  subq $4, %r12
  movl (%r12), %r9d
  xorl %r8d, %r9d
  notl %r9d
  pushq %r8
  xorl %r9d, (%rsp)
  popq %r8
  movslq %r9d, %r9
  addq %r9, %r10
  jmpq *%r10
_vm_relative_backward_end:
  retq

.globl _vm_relative_forward, _vm_relative_forward_end
_vm_relative_forward:
  movl (%rsi), %eax
  addq $4, %rsi
  movslq %eax, %rax
  addq %rax, %rdi
  jmpq *%rdi
_vm_relative_forward_end:
  retq

.globl _vm_bad_stride, _vm_bad_stride_end
_vm_bad_stride:
  movzbl (%rsi), %eax
  addq $2, %rsi
  jmpq *(%rdi,%rax,8)
_vm_bad_stride_end:
  retq

.globl _vm_bad_alias, _vm_bad_alias_end
_vm_bad_alias:
  movzbl (%rsi), %eax
  addq $1, %rsi
  xorb %sil, %al
  xorb %al, %sil
  jmpq *(%rdi,%rax,8)
_vm_bad_alias_end:
  retq

.globl _vm_bad_extension, _vm_bad_extension_end
_vm_bad_extension:
  movl (%rsi), %eax
  addq $4, %rsi
  movl %eax, %eax
  addq %rax, %rdi
  jmpq *%rdi
_vm_bad_extension_end:
  retq

.globl _vm_quota, _vm_quota_end
_vm_quota:
.rept 70
  movzbl (%rsi), %eax
  addq $(1), %rsi
  jmpq *(%rdi,%rax,8)
.endr
_vm_quota_end:
  retq

.globl _vm_scan_limit, _vm_scan_limit_end
_vm_scan_limit:
.rept 1030
  nop
.endr
  movzbl (%rsi), %eax
  addq $1, %rsi
  jmpq *(%rdi,%rax,8)
_vm_scan_limit_end:
  retq

.globl _main
.globl _vm_semantic_groups, _vm_semantic_groups_end
_vm_semantic_groups:
  movzbl (%rsi), %eax
  addq $1, %rsi
  xorb %bl, %al
  rolb $3, %al
  addb $7, %al
  xorb %al, %bl
  jmpq *(%rdi,%rax,8)
  movzbl (%r13), %r9d
  addq $1, %r13
  xorb %r8b, %r9b
  rolb $3, %r9b
  addb $7, %r9b
  xorb %r9b, %r8b
  jmpq *(%r10,%r9,8)
  movzbl (%rsi), %eax
  addq $1, %rsi
  xorb %bl, %al
  rolb $3, %al
  xorb $0, %al
  addb $7, %al
  xorb %al, %bl
  jmpq *(%rdi,%rax,8)
  movzbl (%rsi), %eax
  addq $1, %rsi
  xorb %bl, %al
  rolb $3, %al
  addb $8, %al
  xorb %al, %bl
  jmpq *(%rdi,%rax,8)
_vm_semantic_groups_end:
  retq
_main:
  xorl %eax, %eax
  retq
