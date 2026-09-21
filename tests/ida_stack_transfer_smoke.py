"""Validate exact native push/return targets and conservative boundary cases."""
import json
import os
from pathlib import Path

import ida_allins
import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_name
import ida_pro
import ida_ua
import ida_xref

CASES = {
    "vt_reg": "exact", "vt_mem": "exact", "vt_indexed": "exact",
    "vt_unknown_reg": "unresolved", "vt_alias": "unresolved",
    "vt_writable": "unresolved", "vt_unknown_index": "unresolved",
    "vt_load_writable": "unresolved", "vt_adjust": "rejected",
    "vt_far": "rejected", "vt_width": "rejected", "vt_alternate": "rejected",
}


def address(name):
    for candidate in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return ea
    raise RuntimeError("missing " + name)


def pair(name):
    ea = address(name)
    for _ in range(12):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) <= 0:
            raise RuntimeError("decode " + name)
        if insn.itype == ida_allins.NN_push:
            return insn, ea + insn.size
        ea += insn.size
    raise RuntimeError("push absent " + name)


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
    line = "[chernobog][stack-transfer] " + message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


try:
    ida_auto.auto_wait()
    target = address("vt_target")
    records, errors = [], []
    for name, expected in CASES.items():
        push, ret = pair(name)
        edges = jump_targets(ret)
        comment = "\n".join(filter(None, (
            ida_bytes.get_cmt(ret, False), ida_bytes.get_cmt(ret, True))))
        if edges != ({target} if expected == "exact" else set()):
            errors.append("%s: target set %r" % (name, edges))
        if ("exact push/return target" in comment) != (expected == "exact"):
            errors.append("%s: exact annotation mismatch %r" % (name, comment))
        if expected == "unresolved" and "unresolved target" not in comment:
            errors.append("%s: unresolved annotation absent %r" % (name, comment))
        if expected == "rejected" and "stack-mediated transfer candidate" in comment:
            errors.append("%s: unsupported pair admitted" % name)
        records.append({"name": name, "expected": expected, "push": int(push.ea),
                        "return": int(ret), "targets": sorted(edges), "comment": comment})
    if ida_funcs.get_func_start(target) != target:
        errors.append("target function was merged")
    (Path(os.environ["IDAUSR"]).parent / "stack_transfer.json").write_text(
        json.dumps({"records": records, "errors": errors}, indent=2) + "\n")
    if errors:
        finish(2, "FAIL " + "; ".join(errors))
    finish(0, "PASS cases=%d" % len(records))
except BaseException as error:
    finish(9, "exception: %r" % (error,))
