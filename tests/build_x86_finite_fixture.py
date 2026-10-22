"""Build synthetic AMD64 correlated lookups, shared frames and outlined calls."""

import argparse
from pathlib import Path
import subprocess

ASSEMBLY = r"""
.text
.p2align 4
.globl _fragment_false
_fragment_false:
    movl -32(%rbp), %eax
    addl %ebx, %eax
    addl -36(%rbp), %eax
    addq $64, %rsp
    popq %r12
    popq %rbx
    popq %rbp
    retq
.p2align 4
.globl _main
_main:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    subq $64, %rsp
    leaq -32(%rbp), %r12
    movl $42, %ebx
    movl $0, -32(%rbp)
    leaq -40(%rbp), %rax
    addq _runtime(%rip), %rax
    imull $109, %eax, %eax
    movzbl %al, %ecx
    leaq _table1(%rip), %rdx
    movzbl (%rdx,%rcx), %edx
    xorl $132, %edx
    leaq _table2(%rip), %rsi
    xorb (%rsi,%rdx), %al
    movzbl %al, %eax
    leaq _call_table(%rip), %rdx
    movq (%rdx,%rax,8), %rax
    subq $0x12345678, %rax
    movl %ebx, %edi
.globl _call_site
_call_site:
    callq *%rax
    movl %eax, -36(%rbp)
    movq %r12, %rdi
.globl _inline_call_site
_inline_call_site:
    callq _outlined_helper
    cmpl $7, _runtime(%rip)
    sete %cl
    movzbl %cl, %ecx
    leaq _relative_table(%rip), %rdx
    movslq (%rdx,%rcx,4), %rax
    leaq _main(%rip), %rdx
    addq %rdx, %rax
    movl $0, _runtime(%rip)
.globl _dispatch_site
_dispatch_site:
    jmpq *%rax
.p2align 4
.globl _fragment_true
_fragment_true:
    movl -32(%rbp), %ecx
    leaq _register_fragment(%rip), %rax
.globl _single_site
_single_site:
    jmpq *%rax
.p2align 4
.globl _register_fragment
_register_fragment:
    movl (%r12), %ecx
    leaq _fragment_final(%rip), %rax
.globl _register_site
_register_site:
    jmpq *%rax
.p2align 4
.globl _fragment_final
_fragment_final:
    movl -32(%rbp), %eax
    addl %ebx, %eax
    addl -36(%rbp), %eax
    addl $2, %eax
    addq $64, %rsp
    popq %r12
    popq %rbx
    popq %rbp
    retq
.p2align 4
.globl _outlined_helper
_outlined_helper:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    movl $99, %ebx
    leaq _table1(%rip), %r12
    movl $7, (%rdi)
    leaq _call_barrier(%rip), %rax
    callq *%rax
    movl $3, %eax
    popq %r12
    popq %rbx
    popq %rbp
    retq
.p2align 4
.globl _typed_helper
_typed_helper:
    leal 1(%rdi), %eax
    retq
.p2align 4
.globl _call_barrier
_call_barrier:
    incq _touch_counter(%rip)
    retq
.p2align 4
.globl _address_identity
_address_identity:
    pushq %rbp
    movq %rsp, %rbp
    subq $16, %rsp
    leaq -8(%rbp), %rax
    movl %eax, %ecx
    orl $0x168c3279, %eax
    andl $0x168c3279, %ecx
    addl %ecx, %eax
    addq $16, %rsp
    popq %rbp
    retq
.p2align 4
.globl _recovery_root
_recovery_root:
    pushq %rbp
    movq %rsp, %rbp
    subq $16, %rsp
    movl $42, -4(%rbp)
    cmpl $7, _runtime(%rip)
    sete %cl
    movzbl %cl, %ecx
    leaq _recovery_table(%rip), %rdx
    movl (%rdx,%rcx,4), %eax
    subl $0x13579bdf, %eax
    cltq
    leaq _recovery_root(%rip), %rdx
    addq %rdx, %rax
.globl _recovery_dispatch
_recovery_dispatch:
    jmpq *%rax
.p2align 4
.globl _recovery_clean
_recovery_clean:
    movl -4(%rbp), %eax
    addq $16, %rsp
    popq %rbp
    retq
.p2align 4
.globl _recovery_old_head
_recovery_old_head:
    .byte 0xb8, 0x90, 0x90
.globl _recovery_overlap
_recovery_overlap:
    movl -4(%rbp), %eax
    addq $16, %rsp
    popq %rbp
    retq
.p2align 4
.globl _stack_disjoint
_stack_disjoint:
    pushq %rbp
    movq %rsp, %rbp
    subq $16, %rsp
    movl $0, -4(%rbp)
    callq _call_barrier
    jmp L_stack_disjoint_load
L_stack_disjoint_load:
    movslq -4(%rbp), %rax
    leaq _stack_calls(%rip), %rdx
    movq (%rdx,%rax,8), %rax
    movl $41, %edi
.globl _stack_disjoint_site
_stack_disjoint_site:
    callq *%rax
    leave
    retq
.p2align 4
.globl _stack_escaped
_stack_escaped:
    pushq %rbp
    movq %rsp, %rbp
    subq $16, %rsp
    movl $0, -4(%rbp)
    leaq -4(%rbp), %rdi
    callq _mutate_stack
    movslq -4(%rbp), %rax
    leaq _stack_calls(%rip), %rdx
    movq (%rdx,%rax,8), %rax
    movl $41, %edi
.globl _stack_escaped_site
_stack_escaped_site:
    callq *%rax
    leave
    retq
.p2align 4
.globl _mutate_stack
_mutate_stack:
    movl $1, (%rdi)
    retq
.p2align 4
.globl _alternate_helper
_alternate_helper:
    leal 3(%rdi), %eax
    retq
"""


def assembly(runtime=7):
    result = ASSEMBLY
    for name, custom, overwrite in (
        ("custom", True, False),
        ("overwritten_save", False, True),
        ("mismatched_pop", False, False),
        ("external_tail", False, False),
        ("sp_saved_overwrite", False, True),
    ):
        body = "    movq $77, -8(%rbp)\n" if overwrite else "    movl $77, %ebx\n"
        if name == "sp_saved_overwrite":
            body = "    movq $77, (%rsp)\n"
        restore = "%rbx" if custom or overwrite else "%r12"
        if name == "external_tail":
            body = """    testl %edi, %edi
    jz L_external_normal
    popq %rbx
    popq %rbp
    jmp _typed_helper
L_external_normal:
"""
            restore = "%rbx"
        result += f"""
.p2align 4
.globl _{name}_caller
_{name}_caller:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    subq $8, %rsp
    movl $31, %ebx
    callq _{name}_outline
    movl %ebx, %eax
    addq $8, %rsp
    popq %rbx
    popq %rbp
    retq
.p2align 4
.globl _{name}_outline
_{name}_outline:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
{body}    xorl %eax, %eax
    popq {restore}
    popq %rbp
    retq
"""
    result += "\n.section __TEXT,__const\n_relative_table:\n"
    result += ".long _fragment_false - _main, _fragment_true - _main\n"
    result += ".globl _recovery_table\n_recovery_table:\n"
    result += ".long _recovery_clean - _recovery_root + 0x13579bdf\n"
    result += ".long _recovery_overlap - _recovery_root + 0x13579bdf\n"
    result += ".section __DATA_CONST,__const\n.p2align 3\n_call_table:\n"
    result += "\n".join(
        "    .quad _typed_helper + 0x12345678" if i == 0xE5 else "    .quad 0" for i in range(256)
    )
    result += "\n_stack_calls:\n.quad _typed_helper, _alternate_helper\n"
    first = [(73 * i + 19) & 255 for i in range(256)]
    second = [0] * 256
    for index, value in enumerate(first):
        second[value ^ 132] = index ^ 0xE5
    for name, values in (("table1", first), ("table2", second)):
        result += f"\n.globl _{name}\n_{name}:\n"
        result += "\n".join(
            "    .byte " + ",".join(str(v) for v in values[i : i + 16]) for i in range(0, 256, 16)
        )
    result += f"\n.data\n.globl _runtime\n_runtime:\n.quad {runtime}\n_touch_counter:\n.quad 0\n"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--runtime", type=int, default=7, choices=(0, 7))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    source = args.output.with_suffix(".s")
    source.write_text(assembly(args.runtime))
    compiler = subprocess.check_output(["xcrun", "--find", "clang"], text=True).strip()
    sdk = subprocess.check_output(
        ["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True
    ).strip()
    subprocess.run(
        [compiler, "-isysroot", sdk, "-arch", "x86_64", str(source), "-o", str(args.output)],
        check=True,
    )


if __name__ == "__main__":
    main()
