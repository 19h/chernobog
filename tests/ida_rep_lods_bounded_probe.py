"""Inspect bounded repeated LODS targets and a missing-final-byte mutation."""

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

ROOTS = (
    "rep_lods_two_forward",
    "rep_lods_three_reverse",
    "rep_lods_unknown_df",
    "rep_lods_ambiguous_count",
    "rep_lods_eight",
    "rep_lods_two_word",
    "rep_lods_two_qword",
    "rep_lods_nine",
)
baseline = os.environ.get("CHERNOBOG_REP_LODS_BOUNDED_BASELINE") == "1"
checks = []
errors = []
observed = {}


def check(label, passed):
    checks.append({"case": label, "passed": bool(passed)})
    if not passed:
        errors.append(label)


def address(name):
    for candidate in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return int(ea)
    raise AssertionError("missing symbol " + name)


def instructions(root):
    rows = []
    cursor = root
    for _ in range(64):
        insn = ida_ua.insn_t()
        assert ida_ua.decode_insn(insn, cursor) > 0
        rows.append(insn)
        cursor += insn.size
        if insn.get_canon_mnem() in ("ret", "retn"):
            return rows
    raise AssertionError("missing bounded RET")


def evidence(root):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(
        value, ida_idaapi.BADADDR, f"chernobog_native_evidence({root})"
    )
    return json.loads(value.c_str())


def user_edges(site):
    edges = []
    xref = ida_xref.xrefblk_t()
    more = xref.first_from(site, ida_xref.XREF_ALL)
    while more:
        if xref.iscode and xref.user:
            edges.append(int(xref.to))
        more = xref.next_from()
    return sorted(edges)


def reanalyze(root):
    function = ida_funcs.get_func(root)
    assert function is not None and function.start_ea == root
    assert ida_auto.plan_and_wait(function.start_ea, function.end_ea)
    ida_auto.auto_wait()


def inspect(name, target):
    root = address(name)
    listing = instructions(root)
    rows = [
        row
        for row in evidence(root)["records"]
        if row["kind"] == "stack-transfer" and row["fresh"] == "true"
    ]
    check(name + " has one transfer", len(rows) == 1)
    opcode = (
        b"\xf3\x66\xad"
        if name == "rep_lods_two_word"
        else b"\xf3\x48\xad" if name == "rep_lods_two_qword" else b"\xf3\xac"
    )
    check(
        name + " has REP LODS bytes",
        any(ida_bytes.get_bytes(insn.ea, insn.size) == opcode for insn in listing),
    )
    if rows:
        row = rows[0]
        site = int(row["site"], 0)
        expected_proof = not baseline and name != "rep_lods_nine"
        check(
            name + " target status",
            row["truth"] == ("native-proof" if expected_proof else "candidate")
            and row["target_basis"] == ("register-definition" if expected_proof else "unresolved")
            and row.get("target", "unknown") == (hex(target) if expected_proof else "unknown")
            and row["edge"] == ("true" if expected_proof else "false"),
        )
        edges = user_edges(site)
        check(name + " user edges", edges == ([target] if expected_proof else []))
        observed[name] = {
            "root": hex(root),
            "instruction_bytes": [
                ida_bytes.get_bytes(insn.ea, insn.size).hex() for insn in listing
            ],
            "record": row,
            "user_edges": [hex(ea) for ea in edges],
        }
    return root, listing


try:
    ida_auto.auto_wait()
    target = address("rep_lods_result")
    first_root = None
    first_listing = None
    for name in ROOTS:
        root, listing = inspect(name, target)
        if name == "rep_lods_two_forward":
            first_root, first_listing = root, listing
    value_root = address("rep_lods_two_dword_value")
    value_listing = instructions(value_root)
    check(
        "dword REP LODS encoding",
        any(ida_bytes.get_bytes(insn.ea, insn.size) == b"\xf3\xad" for insn in value_listing),
    )
    value_rows = [
        row
        for row in evidence(value_root)["records"]
        if row["kind"] == "setcc-value" and row["fresh"] == "true"
    ]
    check(
        "dword final value reaches SETcc",
        (
            not value_rows
            if baseline
            else len(value_rows) == 1
            and value_rows[0]["truth"] == "native-proof"
            and value_rows[0]["value"] == "0x1"
        ),
    )
    observed["rep_lods_two_dword_value"] = {
        "root": hex(value_root),
        "records": value_rows,
    }
    if not baseline and first_root is not None and first_listing is not None:
        stores = [
            insn
            for insn in first_listing
            if ida_bytes.get_bytes(insn.ea, insn.size) == b"\x88\x46\x01"
        ]
        check("final-byte store encoding", len(stores) == 1)
        if len(stores) == 1:
            store = stores[0]
            try:
                ida_bytes.patch_bytes(store.ea, b"\x88\x46\x02")
                assert ida_bytes.get_bytes(store.ea, store.size) == b"\x88\x46\x02"
                reanalyze(first_root)
                changed = [
                    row
                    for row in evidence(first_root)["records"]
                    if row["kind"] == "stack-transfer" and row["fresh"] == "true"
                ]
                check(
                    "missing final local byte revokes target",
                    len(changed) == 1
                    and changed[0]["truth"] == "candidate"
                    and changed[0].get("target", "unknown") == "unknown"
                    and changed[0]["edge"] == "false"
                    and user_edges(int(changed[0]["site"], 0)) == [],
                )
            finally:
                ida_bytes.patch_bytes(store.ea, b"\x88\x46\x01")
                assert ida_bytes.get_bytes(store.ea, store.size) == b"\x88\x46\x01"
                reanalyze(first_root)
            restored = [
                row
                for row in evidence(first_root)["records"]
                if row["kind"] == "stack-transfer" and row["fresh"] == "true"
            ]
            check(
                "final local byte restores target",
                len(restored) == 1
                and restored[0]["truth"] == "native-proof"
                and restored[0]["target"] == hex(target)
                and user_edges(int(restored[0]["site"], 0)) == [target],
            )
except BaseException as error:
    errors.append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "rep_lods_bounded.json").write_text(
    json.dumps({"checks": checks, "errors": errors, "observed": observed}, indent=2) + "\n"
)
line = "[chernobog][rep-lods-bounded] " + (
    "FAIL " + "; ".join(errors) if errors else "PASS checks=%d" % len(checks)
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
