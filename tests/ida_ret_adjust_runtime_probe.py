"""Verify static stack metadata on the same x86-64 image used by the process oracle."""

import json
import os
from pathlib import Path

import ida_allins
import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_name
import ida_pro
import ida_ua
import ida_xref


def address(name):
    for candidate in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return int(ea)
    raise AssertionError("missing symbol " + name)


def decode(ea):
    instruction = ida_ua.insn_t()
    assert ida_ua.decode_insn(instruction, ea) > 0
    return instruction


def jumps(ea):
    result = []
    xref = ida_xref.xrefblk_t()
    more = xref.first_from(ea, ida_xref.XREF_ALL)
    while more:
        if xref.iscode and (xref.type & ida_xref.XREF_MASK) == ida_xref.fl_JN:
            result.append((int(xref.to), bool(xref.user)))
        more = xref.next_from()
    return sorted(result)


def evidence(ea):
    result = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(
        result, ida_idaapi.BADADDR, f"chernobog_native_evidence({ea})"
    )
    return json.loads(result.c_str())


checks = []
errors = []


def check(label, passed):
    checks.append({"case": label, "passed": bool(passed)})
    if not passed:
        errors.append(label)


try:
    ida_auto.auto_wait()
    root = address("adjust")
    target = address("target")
    first = decode(root)
    push = decode(root + first.size)
    ret = decode(push.ea + push.size)
    check(
        "full-width PUSH and near RET",
        push.itype == ida_allins.NN_push and ret.itype == ida_allins.NN_retn,
    )
    check("exact RET eight encoding", ida_bytes.get_bytes(ret.ea, ret.size) == b"\xc2\x08\x00")
    comment = ida_bytes.get_cmt(ret.ea, True) or ""
    check(
        "adjusted target and stack annotation",
        all(
            token in comment
            for token in (
                "exact target",
                "width=64 bits",
                "net SP delta=+8 bytes",
                "stack write=8 bytes retained",
                "adjusted RET edge withheld",
            )
        ),
    )
    check("no plugin jump", not any(user for _, user in jumps(ret.ea)))
    check("target function separate", ida_funcs.get_func_start(target) == target)
    before = (ida_bytes.get_bytes(root, ret.ea + ret.size - root), comment, jumps(ret.ea))
    view = evidence(root)
    after = (
        ida_bytes.get_bytes(root, ret.ea + ret.size - root),
        ida_bytes.get_cmt(ret.ea, True) or "",
        jumps(ret.ea),
    )
    rows = [
        row
        for row in view["records"]
        if row["kind"] == "stack-transfer" and int(row["source"], 0) == push.ea
    ]
    check("evidence query read-only", before == after)
    check(
        "fresh exact stack fact without plugin edge",
        len(rows) == 1
        and rows[0]["fresh"] == "true"
        and rows[0]["target"] == hex(target)
        and rows[0]["stack_delta_bytes"] == "8"
        and rows[0]["stack_write_offset_bytes"] == "-8"
        and rows[0]["stack_write_bytes"] == "8"
        and rows[0]["edge"] == "false",
    )
except BaseException as error:
    errors.append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "ret_adjust_runtime.json").write_text(
    json.dumps({"checks": checks, "errors": errors}, indent=2) + "\n"
)
line = "[chernobog][ret-adjust-runtime] " + (
    "FAIL " + "; ".join(errors) if errors else "PASS checks=%d" % len(checks)
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
