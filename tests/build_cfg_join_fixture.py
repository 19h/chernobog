"""Build synthetic late-discovery joins with caller-dependent dispatch state."""

import argparse
from pathlib import Path
import subprocess

ARM = r"""
.text
.globl _main
.p2align 2
_main:
    pacibsp
    stp x29, x30, [sp, #-48]!
    mov x29, sp
    stp x19, x27, [sp, #16]
    str x26, [sp, #32]
    adrp x26, _observed@PAGE
    add x26, x26, _observed@PAGEOFF
    cmp w0, #1
    b.eq L_first
    mov w27, #1
    adrp x8, _runtime@PAGE
    ldrb w9, [x8, _runtime@PAGEOFF]
    adrp x10, _seed_table@PAGE
    add x10, x10, _seed_table@PAGEOFF
    ldrb w11, [x10, w9, uxtw]
    mov w12, #0x5a
    eor w11, w11, w12
    eor w9, w9, w11
    adrp x8, _join_table@PAGE
    add x8, x8, _join_table@PAGEOFF
    ldr x8, [x8, w9, uxtw #3]
    mov x10, #0x4321
    sub x8, x8, x10
    mov x17, #0x1234
    pacia x8, x17
.globl _late_site
_late_site:
    braa x8, x17
L_first:
    mov w27, #0
    b _shared
.globl _shared
_shared:
    str w27, [x26]
    sub w19, w27, #5
    adrp x8, _exit_table@PAGE
    add x8, x8, _exit_table@PAGEOFF
    ldr x8, [x8, w27, uxtw #3]
    mov x17, #0x5678
    pacia x8, x17
.globl _shared_site
_shared_site:
    braa x8, x17
.globl _exit_false
_exit_false:
    mov w0, #71
    ldr x26, [sp, #32]
    ldp x19, x27, [sp, #16]
    ldp x29, x30, [sp], #48
    retab
.globl _exit_true
_exit_true:
    mov w0, #83
    ldr x26, [sp, #32]
    ldp x19, x27, [sp, #16]
    ldp x29, x30, [sp], #48
    retab
.globl _fixture_end
_fixture_end:
    nop
"""

X86 = r"""
.text
.globl _main
.p2align 4
_main:
    pushq %rbp
    movq %rsp, %rbp
    pushq %r12
    subq $24, %rsp
    cmpl $1, %edi
    je L_first
    movl $1, %r12d
    STATE_ONE
    movzbl _runtime(%rip), %ecx
    leaq _seed_table(%rip), %rsi
    movzbl (%rsi,%rcx), %eax
    xorl $0x5a, %eax
    xorl %eax, %ecx
    leaq _join_table(%rip), %rdx
    movq (%rdx,%rcx,8), %rax
    subq $0x4321, %rax
.globl _late_site
_late_site:
    jmpq *%rax
L_first:
    xorl %r12d, %r12d
    STATE_ZERO
    jmp _shared
.globl _shared
_shared:
    STATE_READ
    movl %r12d, _observed(%rip)
    leaq _exit_table(%rip), %rdx
    movq (%rdx,%r12,8), %rax
.globl _shared_site
_shared_site:
    jmpq *%rax
.globl _exit_false
_exit_false:
    movl $71, %eax
    addq $24, %rsp
    popq %r12
    popq %rbp
    retq
.globl _exit_true
_exit_true:
    movl $83, %eax
    addq $24, %rsp
    popq %r12
    popq %rbp
    retq
.globl _fixture_end
_fixture_end:
    nop
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--arch", choices=("arm64", "x86_64"), default="arm64")
    parser.add_argument("--stack", action="store_true")
    parser.add_argument("--authenticated", action="store_true")
    parser.add_argument(
        "--raw-auth",
        action="store_true",
        help="Model relocated authentication origins for analysis only",
    )
    args = parser.parse_args()
    if args.stack and args.arch != "x86_64":
        parser.error("--stack requires x86_64")
    source = ARM if args.arch == "arm64" else X86
    if args.arch == "arm64" and not args.authenticated:
        source = source.replace("    pacia x8, x17\n", "")
        if not args.raw_auth:
            source = source.replace("    braa x8, x17", "    br x8")
    source = source.replace("STATE_ONE", "movl $1, -16(%rbp)" if args.stack else "")
    source = source.replace("STATE_ZERO", "movl $0, -16(%rbp)" if args.stack else "")
    source = source.replace("STATE_READ", "movl -16(%rbp), %r12d" if args.stack else "")
    source += "\n.data\n_runtime:\n.byte 17\n.p2align 2\n.globl _observed\n_observed:\n.long 0\n.section __DATA_CONST,__const\n.p2align 3\n_join_table:\n"
    source += "".join(
        "    .quad _shared + 0x4321\n" if i == 0x5A else "    .quad 0\n" for i in range(256)
    )
    source += "_exit_table:\n.quad _exit_false, _exit_true\n"
    source += "_seed_table:\n" + "".join(f".byte {i}\n" for i in range(256))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    assembly = args.output.with_suffix(".s")
    assembly.write_text(source)
    compiler = subprocess.check_output(["xcrun", "--find", "clang"], text=True).strip()
    sdk = subprocess.check_output(
        ["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True
    ).strip()
    subprocess.run(
        [
            compiler,
            "-isysroot",
            sdk,
            "-arch",
            args.arch,
            "-march=armv8.3-a" if args.arch == "arm64" else "-msse2",
            str(assembly),
            "-o",
            str(args.output),
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
