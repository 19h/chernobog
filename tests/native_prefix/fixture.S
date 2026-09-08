/* x86-64 decoder controls. Only main executes natively; all other entries are
 * decoded by the IDA probe, including string operations with no input memory.
 * Build: xcrun clang -arch x86_64 -g0 tests/native_prefix/fixture.S -o /tmp/native_prefix_fixture
 */
.section __TEXT,__text,regular,pure_instructions
.p2align 4
.globl _main
_main:
    xorl %eax, %eax
    retq

.macro NP_CASE name, bytes:vararg
.p2align 4
.globl _\name
_\name:
    .byte \bytes
    retq
.endm

NP_CASE np_plain_add, 0x83, 0xc0, 0x01
NP_CASE np_plain_nop, 0x90
NP_CASE np_rep_add, 0xf3, 0x83, 0xc0, 0x01
NP_CASE np_repne_add, 0xf2, 0x83, 0xc0, 0x01
NP_CASE np_pause, 0xf3, 0x90
NP_CASE np_rep_ret, 0xf3, 0xc3
NP_CASE np_rep_movsb, 0xf3, 0xa4
NP_CASE np_repne_cmpsb, 0xf2, 0xa6
NP_CASE np_mandatory_sse, 0xf2, 0x0f, 0x58, 0xc0
NP_CASE np_rex_train, 0xf3, 0x48, 0x83, 0xc0, 0x01
NP_CASE np_operand_train, 0xf3, 0x66, 0x83, 0xc0, 0x01
.subsections_via_symbols
