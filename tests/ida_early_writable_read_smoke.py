"""Require writable globals to remain loads after indirect stores and calls.

Compile the independent early_constants/writable_*.c files as x86-64 without
LTO. No xrefs or permissions are edited by this probe. The native executable
also checks the store/call results independently of decompilation.
"""

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_lines
import ida_name
import ida_pro
import ida_segment
import ida_ua
import ida_xref
import idautils


def finish(code, message):
    line = "[chernobog][early-writable-read-smoke] %s" % message
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


def native_scalar_reads(function):
    result = []
    for address in idautils.FuncItems(function):
        instruction = ida_ua.insn_t()
        if ida_ua.decode_insn(instruction, address) <= 0:
            continue
        if (instruction.get_canon_mnem() == "mov"
                and instruction.ops[0].type == ida_ua.o_reg
                and ida_idp.get_reg_name(instruction.ops[0].reg, 4) == "eax"
                and instruction.ops[1].type in (ida_ua.o_mem, ida_ua.o_phrase, ida_ua.o_displ)
                and ida_ua.get_dtype_size(instruction.ops[0].dtype) == 4):
            result.append(address)
    return result


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")
    output = Path(os.environ["IDAUSR"]).parent
    report = {}
    text = []
    retained_mbas = []
    cases = (
        ("alias", "early_alias_store_then_read", "early_alias_global", 7),
        ("call", "early_call_then_read", "early_call_global", 9),
        ("readonly", "early_readonly_read", "early_readonly_control", 0x23456789),
        ("stack", "early_stack_constant", None, 0x3456789A),
    )
    for label, function_name, global_name, expected_initial in cases:
        function = symbol(function_name)
        reads = native_scalar_reads(function)
        if len(reads) != 1:
            finish(3, "%s expected one native scalar load, found %r" % (label, reads))
        load_address = reads[0]
        metadata = {"function": function, "native_load": load_address}
        if global_name is not None:
            address = symbol(global_name)
            segment = ida_segment.getseg(address)
            if segment is None or not all(ida_bytes.is_loaded(address + i) for i in range(4)):
                finish(4, "%s global is not fully loaded" % label)
            write_references = [
                {"from": xref.frm, "to": xref.to}
                for offset in range(4)
                for xref in idautils.XrefsTo(address + offset, ida_xref.XREF_DATA)
                if (xref.type & ida_xref.XREF_MASK) == ida_xref.dr_W
            ]
            metadata.update({"global": address, "permissions": segment.perm,
                             "initial_value": ida_bytes.get_dword(address),
                             "write_xrefs": write_references})
            if metadata["initial_value"] != expected_initial or write_references:
                finish(5, "%s requires unchanged initial bytes and no recorded writes: %r"
                       % (label, metadata))
            if label in ("alias", "call"):
                if not (segment.perm & ida_segment.SEGPERM_WRITE):
                    finish(5, "%s global must be writable" % label)
            elif not (segment.perm & ida_segment.SEGPERM_READ) or (segment.perm & ida_segment.SEGPERM_WRITE):
                finish(5, "readonly control must be read-permitted and nonwritable")
        mba = microcode(function)
        retained_mbas.append(mba)
        items = list(instructions(mba))
        metadata["loads_at_native_read"] = sum(
            item.opcode == ida_hexrays.m_ldx and item.ea == load_address for item in items)
        metadata["constants_at_native_read"] = [
            item.l.nnn.value for item in items
            if item.ea == load_address and item.opcode == ida_hexrays.m_mov
            and item.l.t == ida_hexrays.mop_n
        ]
        report[label] = metadata
        text += [label + ":"] + [item.dstr() for item in items]
    (output / "early_writable_microcode.txt").write_text("\n".join(text) + "\n", encoding="utf-8")
    (output / "early_writable_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    failed_writable = [label for label in ("alias", "call")
                       if report[label]["loads_at_native_read"] != 1]
    if failed_writable:
        finish(6, "writable loads were replaced after store/call: %s" % ",".join(failed_writable))
    if os.environ.get("CHERNOBOG_IDA_EARLY_CONSTANTS") != "0":
        for label, value in (("readonly", 0x23456789),):
            if (report[label]["loads_at_native_read"] != 0
                    or value not in report[label]["constants_at_native_read"]):
                finish(7, "%s constant forwarding was not preserved" % label)
    stack_function = ida_hexrays.decompile(symbol("early_stack_constant"))
    if stack_function is None:
        finish(8, "stack control decompilation failed")
    stack_text = "\n".join(ida_lines.tag_remove(line.line)
                           for line in stack_function.get_pseudocode())
    (output / "early_writable_stack_pseudocode.txt").write_text(stack_text + "\n", encoding="utf-8")
    if "0x3456789A" not in stack_text and "878082202" not in stack_text:
        finish(8, "stack control lost its exact scalar result")
    finish(0, "PASS writable-alias=load writable-call=load readonly=0x23456789 stack=0x3456789A")
except BaseException as error:
    finish(99, "exception: %r" % error)
