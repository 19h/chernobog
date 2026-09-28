"""Check the executed ELF32 immediate PUSH/RET in the production IDA adapter."""

import json
import os
from pathlib import Path
import struct

import ida_allins
import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_name
import ida_pro
import ida_ua
import ida_xref


def address(name):
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    if ea == ida_idaapi.BADADDR:
        raise RuntimeError("missing " + name)
    return ea


def decode(ea):
    instruction = ida_ua.insn_t()
    if ida_ua.decode_insn(instruction, ea) <= 0:
        raise RuntimeError("undecoded instruction")
    return instruction


def jump_targets(ea):
    result = set()
    xref = ida_xref.xrefblk_t()
    ok = xref.first_from(ea, ida_xref.XREF_ALL)
    while ok:
        if xref.iscode and (xref.type & ida_xref.XREF_MASK) == ida_xref.fl_JN:
            result.add(int(xref.to))
        ok = xref.next_from()
    return result


def finish(code, message):
    text = "[chernobog][push-immediate32] " + message
    print(text, flush=True)
    ida_kernwin.msg("%s\n" % text)
    ida_pro.qexit(code)


try:
    ida_auto.auto_wait()
    root, target = address("pi32_immediate"), address("pi32_target")
    push = decode(root)
    ret_ea = root + push.size
    ret = decode(ret_ea)
    negative = decode(address("pi32_negative_byte"))
    prefixed = decode(address("pi32_operand_override"))
    comment = ida_bytes.get_cmt(ret_ea, True) or ""
    checks = {
        "ELF32 database": ida_ida.inf_is_32bit_exactly(),
        "loaded immediate bytes": ida_bytes.get_bytes(root, 5)
        == b"\x68" + struct.pack("<I", target),
        "decoded immediate operand": push.itype == ida_allins.NN_push
        and push.Op1.type == ida_ua.o_imm
        and (int(push.Op1.value) & 0xFFFFFFFF) == target,
        "adjacent near return": push.size == 5 and ret.itype == ida_allins.NN_retn,
        "exact published target": jump_targets(ret_ea) == {target},
        "exact annotation": "exact push/return target" in comment and "width=32 bits" in comment,
        "target ownership retained": ida_funcs.get_func_start(target) == target,
        "negative imm8 bytes": ida_bytes.get_bytes(negative.ea, 2) == b"\x6a\x80",
        "override bytes": ida_bytes.get_bytes(prefixed.ea, 3) == b"\x66\x6a\x80",
        "negative immediate decoder": (int(negative.Op1.value) & 0xFFFFFFFF) == 0xFFFFFF80,
        "negative target unpublished": not jump_targets(negative.ea + negative.size),
        "operand override unpublished": not jump_targets(prefixed.ea + prefixed.size),
    }
    report = {
        "checks": checks,
        "root": hex(root),
        "target": hex(target),
        "push_operand": hex(int(push.Op1.value)),
        "return": hex(ret_ea),
        "targets": [hex(value) for value in sorted(jump_targets(ret_ea))],
        "annotation": comment,
        "negative_code_head": ida_bytes.is_code(ida_bytes.get_full_flags(negative.ea)),
        "negative_operand": hex(int(negative.Op1.value)),
        "negative_return_annotation": ida_bytes.get_cmt(negative.ea + negative.size, True) or "",
        "override_code_head": ida_bytes.is_code(ida_bytes.get_full_flags(prefixed.ea)),
        "override_return_annotation": ida_bytes.get_cmt(prefixed.ea + prefixed.size, True) or "",
    }
    (Path(os.environ["IDAUSR"]).parent / "push_immediate32.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    if not all(checks.values()):
        finish(2, "FAIL " + ", ".join(name for name, passed in checks.items() if not passed))
    finish(0, "PASS checks=" + str(len(checks)))
except BaseException as error:
    finish(9, "exception: %r" % (error,))
