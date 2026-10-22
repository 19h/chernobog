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
    ldr w0, [x29, #16]
    ldr x8, [x28]
    mov x17, #0x1234
.globl _call_site
_call_site:
    blraa x8, x17
    str w0, [x29, #16]
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

.p2align 2
.globl _identity_helper
_identity_helper:
    add w0, w0, #0
    ret

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
    .quad _identity_helper
    .space 8 * (0x38e4 - 1)
    .quad _fragment_false
    .space 8 * (0x6524 - 0x38e4 - 1)
    .quad _fragment_true
"""


def nested_assembly():
    """Put a child dispatch before its parent and consume SP as a value."""
    start = ASSEMBLY.index(".p2align 2\n.globl _fragment_true")
    end = ASSEMBLY.index(".p2align 2\n.globl _identity_helper", start)
    result = ASSEMBLY[:start] + ASSEMBLY[end:]
    child = r"""
.p2align 2
.globl _fragment_true
_fragment_true:
    movz x12, #0xdef0
    movk x12, #0x9abc, lsl #16
    movk x12, #0x5678, lsl #32
    movk x12, #0x1234, lsl #48
    add x10, sp, #16
    ldr w8, [x10]
    adrp x10, _runtime@PAGE
    ldr w8, [x10, _runtime@PAGEOFF]
    cmp w8, #11
    cset w9, eq
    cset w10, eq
    orr w9, w9, w10, lsl #3
    add w9, w9, #0x100
    ldr x9, [x28, w9, uxtw #3]
    mov x17, #0x4321
.globl _nested_dispatch_site
_nested_dispatch_site:
    braa x9, x17
"""
    terminals = ""
    for name, addend in (("false", 7), ("true", 9)):
        body = f"    ldr w0, [x29, #16]\n    add w0, w0, #{addend}\n"
        ending = "    ldr x28, [x29, #24]\n    ldp x29, x30, [sp], #32\n    retab\n"
        if name == "false":
            body = ""
            ending = """    ldr x9, [x28, #0x858]
    mov x17, #0x789a
.globl _register_dispatch_site
_register_dispatch_site:
    braa x9, x17
"""
        if name == "true":
            ending = """    str w0, [x29, #16]
    ldr x9, [x28, #0x850]
    mov x17, #0x6789
.globl _single_dispatch_site
_single_dispatch_site:
    braa x9, x17
"""
        terminals += f"""
.p2align 2
.globl _fragment_nested_{name}
_fragment_nested_{name}:
{body}{ending}
"""
    terminals += """
.p2align 2
.globl _fragment_final
_fragment_final:
    ldr w0, [x29, #16]
    ldr x28, [x29, #24]
    ldp x29, x30, [sp], #32
    retab
.p2align 2
.globl _fragment_final_false
_fragment_final_false:
    ldr w0, [x29, #16]
    add w0, w0, #7
    ldr x28, [x29, #24]
    ldp x29, x30, [sp], #32
    retab
.p2align 2
.globl _stack_barrier_probe
_stack_barrier_probe:
    pacibsp
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    adrp x8, _identity_helper@PAGE
    add x8, x8, _identity_helper@PAGEOFF
    str x8, [x29, #16]
    add x0, x29, #16
    bl _slot_writer
    ldr x8, [x29, #16]
    mov x17, #0x2468
.globl _stack_barrier_site
_stack_barrier_site:
    blraa x8, x17
    ldp x29, x30, [sp], #32
    retab
.p2align 2
.globl _slot_writer
_slot_writer:
    str x1, [x0]
    ret
.p2align 2
.globl _partial_main
_partial_main:
    pacibsp
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str w0, [x29, #16]
    str x28, [x29, #24]
    cmp w0, #0
    cset w8, eq
    adrp x9, _partial_table@PAGE
    add x9, x9, _partial_table@PAGEOFF
    ldr x8, [x9, w8, uxtw #3]
    mov x17, #0x9876
.globl _partial_site
_partial_site:
    braa x8, x17
.p2align 2
.globl _independent_target
_independent_target:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov w0, #0
    ldp x29, x30, [sp], #16
    ret
"""
    result = result.replace(".text\n", ".text\n" + child, 1)
    result = result.replace(".globl _fragment_false", terminals + "\n.globl _fragment_false", 1)
    result = result.replace(
        "    eor w9, w9, w10\n    adrp x28",
        "    eor w9, w9, w10\n    str w9, [x29, #20]\n    adrp x28",
    )
    result = result.replace(
        "    .space 8 * (0x38e4 - 1)",
        "    .space 8 * (0x100 - 1)\n"
        "    .quad _fragment_nested_false\n    .space 8 * 8\n"
        "    .quad _fragment_nested_true\n    .quad _fragment_final\n"
        "    .quad _fragment_final_false\n    .space 8 * (0x38e4 - 0x10C)",
    )
    return result + "\n.p2align 3\n_partial_table:\n.quad _fragment_false, _independent_target\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--nested", action="store_true")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    source = args.output.with_suffix(".s")
    source.write_text(nested_assembly() if args.nested else ASSEMBLY)
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
