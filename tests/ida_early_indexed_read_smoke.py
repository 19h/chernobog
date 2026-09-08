"""Assert that an indexed-read xref is not an effective-address proof.

Compile the two tests/early_constants C files as x86-64 without LTO. The probe
adds one read xref to the table base in the disposable IDB and checks both an
unknown-index load and fixed/known-index loads in the preoptimized microcode.
"""

import os
from pathlib import Path

import ida_auto
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_name
import ida_pro
import ida_ua
import ida_xref
import idautils


def finish(code, message):
    line = "[chernobog][early-indexed-read-smoke] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


def symbol(name):
    for spelling in (name, "_" + name):
        address = ida_name.get_name_ea(ida_idaapi.BADADDR, spelling)
        if address != ida_idaapi.BADADDR:
            return address
    raise RuntimeError("missing fixture symbol: %s" % name)


def instructions(mba):
    def nested(instruction):
        yield instruction
        for operand in (instruction.l, instruction.r, instruction.d):
            if operand.t == ida_hexrays.mop_d:
                yield from nested(operand.d)
    for index in range(mba.qty):
        instruction = mba.get_mblock(index).head
        while instruction is not None:
            yield from nested(instruction)
            instruction = instruction.next


def microcode(address):
    function = ida_funcs.get_func(address)
    failure = ida_hexrays.hexrays_failure_t()
    mba = ida_hexrays.gen_microcode(
        ida_hexrays.mba_ranges_t(function), failure, None,
        ida_hexrays.DECOMP_NO_CACHE, ida_hexrays.MMAT_PREOPTIMIZED,
    )
    if mba is None:
        raise RuntimeError("microcode failed: %s" % failure.desc())
    return mba


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")
    indexed = symbol("early_indexed_read")
    fixed = symbol("early_fixed_read")
    known_index = symbol("early_known_index_read")
    table = symbol("early_constant_table")
    indexed_reads = []
    for address in idautils.FuncItems(indexed):
        instruction = ida_ua.insn_t()
        if ida_ua.decode_insn(instruction, address) <= 0:
            continue
        if (instruction.get_canon_mnem() == "mov"
                and instruction.ops[0].type == ida_ua.o_reg
                and instruction.ops[1].type in (ida_ua.o_phrase, ida_ua.o_displ)):
            indexed_reads.append(address)
    if len(indexed_reads) != 1:
        finish(3, "expected one indexed x86 memory read, found %r" % indexed_reads)
    indexed_read = indexed_reads[0]
    if not ida_xref.add_dref(indexed_read, table, ida_xref.dr_R | ida_xref.XREF_USER):
        finish(4, "could not add table-base read xref")
    reads = [xref.to for xref in idautils.XrefsFrom(indexed_read, ida_xref.XREF_DATA)
             if (xref.type & ida_xref.XREF_MASK) == ida_xref.dr_R]
    if reads != [table]:
        finish(5, "fixture does not have exactly one table-base read xref: %r" % reads)
    indexed_mba = microcode(indexed)
    fixed_mba = microcode(fixed)
    known_index_mba = microcode(known_index)
    indexed_instructions = list(instructions(indexed_mba))
    fixed_instructions = list(instructions(fixed_mba))
    known_index_instructions = list(instructions(known_index_mba))
    lines = ["indexed:"] + [instruction.dstr() for instruction in indexed_instructions]
    lines += ["fixed:"] + [instruction.dstr() for instruction in fixed_instructions]
    lines += ["known-index:"] + [instruction.dstr() for instruction in known_index_instructions]
    output = Path(os.environ["IDAUSR"]).parent / "early_indexed_microcode.txt"
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if not any(instruction.opcode == ida_hexrays.m_ldx
               and instruction.ea == indexed_read for instruction in indexed_instructions):
        finish(6, "unknown-index load was replaced using its table-base xref")
    if any(instruction.opcode == ida_hexrays.m_ldx for instruction in fixed_instructions):
        finish(7, "fixed-address load did not fold")
    if not any(instruction.opcode == ida_hexrays.m_mov
               and instruction.l.t == ida_hexrays.mop_n
               and instruction.l.nnn.value == 0x3456789A
               for instruction in fixed_instructions):
        finish(8, "fixed-address load did not retain the expected scalar")
    if any(instruction.opcode == ida_hexrays.m_ldx for instruction in known_index_instructions):
        finish(9, "proven-index load did not fold")
    if not any(instruction.opcode == ida_hexrays.m_mov
               and instruction.l.t == ida_hexrays.mop_n
               and instruction.l.nnn.value == 0x3456789A
               for instruction in known_index_instructions):
        finish(10, "proven-index load did not retain the expected scalar")
    finish(0, "PASS indexed=dynamic fixed=0x3456789A known-index=0x3456789A")
except BaseException as error:
    finish(99, "exception: %r" % error)
