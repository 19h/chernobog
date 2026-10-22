"""Build an arm64 Mach-O fixture with correlated tables and authenticated dispatch."""

import argparse
from pathlib import Path
import subprocess

ASSEMBLY = r"""
.text
.globl _main
.p2align 2
_main:
    pacibsp
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str w0, [x29, #16]
    str x28, [x29, #24]
    adrp x8, _runtime@PAGE
    ldr w9, [x8, _runtime@PAGEOFF]
    mov w11, #0xa6
    eor w9, w9, w11
    mov w10, #0xd4cf
    movk w10, #0xa5c, lsl #16
    mul w9, w9, w10
    and w9, w9, #255
    adrp x10, _table1@PAGE
    add x10, x10, _table1@PAGEOFF
    ldrb w10, [x10, w9, uxtw]
    mov w11, #0x9a
    eor w10, w10, w11
    adrp x11, _table2@PAGE
    add x11, x11, _table2@PAGEOFF
    ldrb w10, [x11, w10, uxtw]
    eor w9, w9, w10
    adrp x28, _pointer_table@PAGE
    add x28, x28, _pointer_table@PAGEOFF
    ldr x28, [x28, w9, uxtw #3]
    ldr w8, [x29, #16]
    cmp w8, #7
    cset w9, eq
    mov w10, #0x5dc0
    mul w9, w9, w10
    mov w10, #0x38e4
    eor w9, w9, w10
    ldr x9, [x28, w9, uxtw #3]
    mov x17, #0x8b6c
.globl _dispatch_site
_dispatch_site:
    braa x9, x17

.p2align 2
.globl _fragment_false
_fragment_false:
    ldr w0, [x29, #16]
    add w0, w0, #3
    ldr x28, [x29, #24]
    ldp x29, x30, [sp], #32
    retab
.p2align 2
.globl _fragment_true
_fragment_true:
    ldr w0, [x29, #16]
    add w0, w0, #5
    ldr x28, [x29, #24]
    ldp x29, x30, [sp], #32
    retab

.data
.p2align 3
.globl _runtime
_runtime:
    .long 17

.section __DATA_CONST,__const
.p2align 3
.globl _table1
_table1:
.set counter, 0
.rept 256
    .byte counter
    .set counter, counter + 1
.endr
.globl _table2
_table2:
.set counter, 0
.rept 256
    .byte counter ^ 0x7f
    .set counter, counter + 1
.endr
.p2align 3
_pointer_table:
    .space 8 * 0xe5
    .quad _target_table
_target_table:
    .space 8 * 0x38e4
    .quad _fragment_false
    .space 8 * (0x6524 - 0x38e4 - 1)
    .quad _fragment_true
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    source = args.output.with_suffix(".s")
    source.write_text(ASSEMBLY)
    compiler = subprocess.check_output(["xcrun", "--find", "clang"], text=True).strip()
    sdk = subprocess.check_output(
        ["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True
    ).strip()
    subprocess.run(
        [compiler, "-isysroot", sdk, "-arch", "arm64e", str(source), "-o", str(args.output)],
        check=True,
    )


if __name__ == "__main__":
    main()
