"""32-bit decoded get-PC and stack-transfer integration, not execution evidence."""

import json
import os
from pathlib import Path

import ida_allins
import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_name
import ida_pro
import ida_ua
import ida_xref


def address(name):
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    assert ea != ida_idaapi.BADADDR, "missing " + name
    return ea


def instruction(ea):
    decoded = ida_ua.insn_t()
    assert ida_ua.decode_insn(decoded, ea) > 0
    return decoded


def nth(name, count):
    ea = address(name)
    for _ in range(count):
        ea += instruction(ea).size
    return ea


def comment(ea):
    return ida_bytes.get_cmt(ea, True) or ""


def jumps(ea):
    result = set()
    xref = ida_xref.xrefblk_t()
    ok = xref.first_from(ea, ida_xref.XREF_ALL)
    while ok:
        if xref.iscode and (xref.type & ida_xref.XREF_MASK) in (ida_xref.fl_JN, ida_xref.fl_F):
            result.add(int(xref.to))
        ok = xref.next_from()
    return result


records, errors, diagnostics = [], [], []
baseline = os.environ.get("CHERNOBOG_GET_PC32_BASELINE") == "1"


def check(label, condition, **evidence):
    if baseline and not (
        label.endswith(" rejected") or label in ("32-bit database", "target function retained")
    ):
        return
    records.append({"case": label, "passed": bool(condition), **evidence})
    if not condition:
        errors.append(label)


try:
    ida_auto.auto_wait()
    check("32-bit database", ida_ida.inf_is_32bit_exactly())
    target = address("gp32_target")
    text = comment(address("gp32_materialize"))
    check(
        "PUSH-next materialization",
        all(
            s in text
            for s in (
                "stack address materialization",
                "width=32 bits",
                "net SP delta=-4 bytes",
                "flags preserved",
                "stack write retained",
            )
        ),
        comment=text,
    )
    check(
        "arbitrary literal has no get-PC claim",
        "stack address materialization" not in comment(address("gp32_literal")),
    )
    for name, index in (("gp32_materialize", 4), ("gp32_reg", 2), ("gp32_mem", 1)):
        site = nth(name, index)
        check(
            name + " exact target",
            jumps(site) == {target} and "width=32 bits" in comment(site),
            targets=sorted(jumps(site)),
            comment=comment(site),
        )
    for name in ("gp32_unknown", "gp32_writable"):
        site = nth(name, 1)
        check(
            name + " unresolved",
            not jumps(site) and "unresolved target" in comment(site),
            targets=sorted(jumps(site)),
            comment=comment(site),
        )
    for name, index in (
        ("gp32_width", 1),
        ("gp32_far", 1),
        ("gp32_extra", 1),
        ("gp32_alternate", 3),
    ):
        site = nth(name, index)
        check(
            name + " rejected",
            "stack-mediated transfer" not in comment(site)
            and "exact push/return" not in comment(site),
            targets=sorted(jumps(site)),
            comment=comment(site),
        )
    for name in ("gp32_call", "gp32_next"):
        root = address(name)
        decoded = instruction(root)
        check(
            name + " exact entry",
            jumps(root) == {int(decoded.Op1.addr)} and "width=32 bits" in comment(root),
            targets=sorted(jumps(root)),
            comment=comment(root),
        )
    call = instruction(address("gp32_call"))
    site = call.Op1.addr
    for _ in range(2):
        site += instruction(site).size
    check(
        "32-bit call-context return",
        jumps(site) == {int(call.ea + call.size)},
        targets=sorted(jumps(site)),
        comment=comment(site),
    )
    check("target function retained", ida_funcs.get_func_start(target) == target)
    for index in range(5):
        ea = nth("gp32_materialize", index)
        decoded = instruction(ea)
        incoming = []
        xref = ida_xref.xrefblk_t()
        ok = xref.first_to(ea, ida_xref.XREF_ALL)
        while ok:
            incoming.append(
                {"source": int(xref.frm), "type": int(xref.type), "code": bool(xref.iscode)}
            )
            ok = xref.next_to()
        diagnostics.append(
            {
                "ea": int(ea),
                "itype": int(decoded.itype),
                "auxpref": int(decoded.auxpref),
                "call": bool(ida_idp.is_call_insn(decoded)),
                "block_end": bool(ida_idp.is_basic_block_end(decoded, False)),
                "owner": int(ida_funcs.get_func_start(ea)),
                "incoming": incoming,
                "value": int(decoded.Op1.value),
                "bytes": ida_bytes.get_bytes(ea, decoded.size).hex(),
            }
        )
except BaseException as error:
    errors.append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "get_pc32.json").write_text(
    json.dumps(
        {"records": records, "errors": errors, "diagnostics": diagnostics, "baseline": baseline},
        indent=2,
    )
    + "\n"
)
message = "FAIL " + "; ".join(errors) if errors else "PASS assertions=%d" % len(records)
line = "[chernobog][get-pc32] " + message
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
