/* Independent ELF32 decoder/dispatch motifs; inspected, not executed. */
.text
.globl _vm_table_forward, _vm_table_forward_end
_vm_table_forward:
  movzbl (%esi), %eax
  addl $1, %esi
  xorb %bl, %al
  rolb $3, %al
  addb $7, %al
  xorb %al, %bl
  jmpl *_table(,%eax,4)
_vm_table_forward_end: ret
.globl _vm_table_clone, _vm_table_clone_end
_vm_table_clone:
  movzbl (%edi), %ecx
  addl $1, %edi
  xorb %dl, %cl
  rolb $3, %cl
  addb $7, %cl
  xorb %cl, %dl
  jmpl *_table(,%ecx,4)
_vm_table_clone_end: ret
.globl _vm_table_backward, _vm_table_backward_end
_vm_table_backward:
  subl $1, %esi
  movzbl (%esi), %eax
  jmpl *_table(,%eax,4)
_vm_table_backward_end: ret
.globl _vm_relative_backward, _vm_relative_backward_end
_vm_relative_backward:
  subl $4, %esi
  movl (%esi), %eax
  xorl %ebx, %eax
  notl %eax
  xorl %eax, %ebx
  addl %eax, %edi
  jmpl *%edi
_vm_relative_backward_end: ret
.globl _vm_relative_forward, _vm_relative_forward_end
_vm_relative_forward:
  movl (%esi), %eax
  addl $4, %esi
  addl %eax, %edi
  jmpl *%edi
_vm_relative_forward_end: ret
.globl _vm_bad_stride, _vm_bad_stride_end
_vm_bad_stride:
  movzbl (%esi), %eax
  addl $2, %esi
  jmpl *_table(,%eax,4)
_vm_bad_stride_end: ret
.globl _vm_bad_alias, _vm_bad_alias_end
_vm_bad_alias:
  movzbl (%ebx), %eax
  addl $1, %ebx
  xorb %bl, %al
  xorb %al, %bl
  jmpl *_table(,%eax,4)
_vm_bad_alias_end: ret
.globl _vm_bad_extension, _vm_bad_extension_end
_vm_bad_extension:
  movl (%esi), %eax
  addl $4, %esi
  movw %ax, %di
  addl %eax, %edi
  jmpl *%edi
_vm_bad_extension_end: ret
.globl _vm_quota, _vm_quota_end
_vm_quota:
.rept 70
  movzbl (%esi), %eax
  addl $1, %esi
  jmpl *_table(,%eax,4)
.endr
_vm_quota_end: ret
.globl _vm_scan_limit, _vm_scan_limit_end
_vm_scan_limit:
.rept 1030
  nop
.endr
  movzbl (%esi), %eax
  addl $1, %esi
  jmpl *_table(,%eax,4)
_vm_scan_limit_end: ret
.globl _main
.globl _vm_semantic_groups, _vm_semantic_groups_end
_vm_semantic_groups:
  movzbl (%esi), %eax
  addl $1, %esi
  xorb %bl, %al
  rolb $3, %al
  addb $7, %al
  xorb %al, %bl
  jmpl *_table(,%eax,4)
  movzbl (%edi), %ecx
  addl $1, %edi
  xorb %dl, %cl
  rolb $3, %cl
  addb $7, %cl
  xorb %cl, %dl
  jmpl *_table(,%ecx,4)
  movzbl (%esi), %eax
  addl $1, %esi
  xorb %bl, %al
  rolb $3, %al
  xorb $0, %al
  addb $7, %al
  xorb %al, %bl
  jmpl *_table(,%eax,4)
  movzbl (%esi), %eax
  addl $1, %esi
  xorb %bl, %al
  rolb $3, %al
  addb $8, %al
  xorb %al, %bl
  jmpl *_table(,%eax,4)
_vm_semantic_groups_end: ret
_main:
  xorl %eax, %eax
  ret
.section .rodata
.p2align 2
_table:
  .fill 256,4,0
.section .note.GNU-stack,"",@progbits
