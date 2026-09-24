"""Inspect the same ELF32 transfer fixture used by the independent process oracle."""

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_name
import ida_pro
import ida_segment
import ida_ua
import ida_xref


def address(name):
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    assert ea != ida_idaapi.BADADDR, "missing " + name
    return ea


def nth(name, count):
    ea = address(name)
    for _ in range(count):
        insn = ida_ua.insn_t()
        assert ida_ua.decode_insn(insn, ea) > 0
        ea += insn.size
    return ea


def code_targets(ea):
    targets = set()
    xref = ida_xref.xrefblk_t()
    more = xref.first_from(ea, ida_xref.XREF_ALL)
    while more:
        if xref.iscode and (xref.type & ida_xref.XREF_MASK) in (ida_xref.fl_JN, ida_xref.fl_F):
            targets.add(int(xref.to))
        more = xref.next_from()
    return sorted(targets)


def writes_to(ea):
    sources = set()
    xref = ida_xref.xrefblk_t()
    more = xref.first_to(ea, ida_xref.XREF_ALL)
    while more:
        if (xref.type & ida_xref.XREF_MASK) == ida_xref.dr_W:
            sources.add(int(xref.frm))
        more = xref.next_to()
    return sorted(sources)


baseline = os.environ.get("CHERNOBOG_GET_PC32_REJECTION_BASELINE") == "1"
records, errors = [], []


def check(label, passed, **evidence):
    records.append({"case": label, "passed": bool(passed), **evidence})
    if not passed:
        errors.append(label)


try:
    ida_auto.auto_wait()
    check("ELF32 database", ida_ida.inf_is_32bit_exactly())
    target7, target8 = address("gp32_target7"), address("gp32_target8")
    check("distinct target addresses", target7 != target8, targets=[target7, target8])
    rw = address("gp32_rw")
    segment = ida_segment.getseg(rw)
    check(
        "writable target object",
        segment is not None and bool(segment.perm & ida_segment.SEGPERM_WRITE),
    )
    check("initial object target", ida_bytes.get_dword(rw) == target7)
    writes = writes_to(rw)
    check("two source writes", len(writes) == 2, write_sources=writes)

    for name in ("gp32_unknown", "gp32_writable"):
        site = nth(name, 1)
        comment = ida_bytes.get_cmt(site, True) or ""
        targets = code_targets(site)
        check(name + " has no unique edge", not targets, targets=targets)
        check(
            name + " ownership",
            (
                "[chernobog][ida-analysis]" not in comment
                if baseline
                else "unresolved target" in comment
            ),
            comment=comment,
        )

    for name, index in (("gp32_alternate", 3), ("gp32_extra", 1)):
        site = nth(name, index)
        comment = ida_bytes.get_cmt(site, True) or ""
        check(
            name + " rejected summary",
            "[chernobog][ida-analysis]" not in comment,
            targets=code_targets(site),
            comment=comment,
        )
except BaseException as error:
    errors.append(type(error).__name__ + ": " + str(error))

report = {"records": records, "errors": errors, "baseline": baseline}
(Path(os.environ["IDAUSR"]).parent / "get_pc32_rejections.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
line = "[chernobog][get-pc32-rejections] " + (
    "FAIL " + "; ".join(errors) if errors else "PASS assertions=%d" % len(records)
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
