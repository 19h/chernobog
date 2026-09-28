"""Check read-only RET imm16 facts after removing the fixture's function owner."""

import json
import os
from pathlib import Path

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


def references(ea):
    result = []
    xref = ida_xref.xrefblk_t()
    ok = xref.first_from(ea, ida_xref.XREF_ALL)
    while ok:
        result.append((int(xref.to), int(xref.type), bool(xref.user)))
        ok = xref.next_from()
    return sorted(result)


def inspect(root):
    result = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(
        result, ida_idaapi.BADADDR, f"chernobog_native_region_facts({root})"
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
    root = address("vt_adjust")
    target = address("vt_target")
    push = root + decode(root).size
    ret = push + decode(push).size
    check("fixture has function owner", ida_funcs.get_func(root) is not None)
    check("function owner removed", ida_funcs.del_func(root))
    check("query root is ownerless", ida_funcs.get_func(root) is None)
    before = (
        ida_bytes.get_bytes(root, ret + decode(ret).size - root),
        ida_bytes.get_cmt(ret, True),
        references(ret),
    )
    result = inspect(root)
    after = (
        ida_bytes.get_bytes(root, ret + decode(ret).size - root),
        ida_bytes.get_cmt(ret, True),
        references(ret),
    )
    rows = [
        row
        for row in result["records"]
        if row["kind"] == "push-return" and int(row["site"], 0) == push
    ]
    check("read-only ownerless query", before == after and not result["published"])
    check("ownerless graph converged", result["available"] and result["converged"])
    check(
        "adjusted return fact",
        len(rows) == 1
        and rows[0]["status"] == "proved"
        and rows[0]["target"] == hex(target)
        and rows[0]["width_bits"] == "64"
        and rows[0]["stack_delta_bytes"] == "8"
        and rows[0]["stack_write_bytes"] == "8"
        and rows[0]["stack_write_offset_bytes"] == "-8",
    )
except BaseException as error:
    errors.append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "ret_adjust_ownerless.json").write_text(
    json.dumps({"checks": checks, "errors": errors}, indent=2) + "\n"
)
line = "[chernobog][ret-adjust-ownerless] " + (
    "FAIL " + "; ".join(errors) if errors else "PASS checks=%d" % len(checks)
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
