"""Check zero-count REP LODS target proof on an executed x86 fixture."""

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


def evidence(root):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(
        value, ida_idaapi.BADADDR, f"chernobog_native_evidence({root})"
    )
    return json.loads(value.c_str())


def user_edge(site, target):
    xref = ida_xref.xrefblk_t()
    more = xref.first_from(site, ida_xref.XREF_ALL)
    while more:
        if xref.iscode and xref.to == target and xref.user:
            return True
        more = xref.next_from()
    return False


def reanalyze(root):
    function = ida_funcs.get_func(root)
    assert function is not None
    assert ida_auto.plan_and_wait(function.start_ea, function.end_ea)
    ida_auto.auto_wait()


checks = []
errors = []
observed = {}
baseline = os.environ.get("CHERNOBOG_REP_LODS_ZERO_BASELINE") == "1"


def check(label, passed):
    checks.append({"case": label, "passed": bool(passed)})
    if not passed:
        errors.append(label)


try:
    ida_auto.auto_wait()
    root = address("rep_lods_zero_target")
    target = address("rep_lods_result")
    cursor = root
    instructions = []
    for _ in range(8):
        instruction = ida_ua.insn_t()
        assert ida_ua.decode_insn(instruction, cursor) > 0
        instructions.append(instruction)
        cursor += instruction.size
        if instruction.get_canon_mnem() in ("ret", "retn"):
            break
    observed["mnemonics"] = [instruction.get_canon_mnem() for instruction in instructions]
    check(
        "exact fixture shape",
        len(instructions) == 6 and instructions[3].get_canon_mnem() in ("lods", "lodsb"),
    )
    view = evidence(root)
    rows = [
        row for row in view["records"] if row["kind"] == "stack-transfer" and row["fresh"] == "true"
    ]
    observed["records"] = rows
    check(
        "zero-count accumulator target",
        len(rows) == 1
        and (
            rows[0]["truth"] == "candidate"
            and rows[0].get("target", "unknown") == "unknown"
            and rows[0]["edge"] == "false"
            if baseline
            else rows[0]["truth"] == "native-proof"
            and rows[0]["target"] == hex(target)
            and rows[0]["target_basis"] == "register-definition"
            and rows[0]["edge"] == "true"
        ),
    )
    if rows:
        site = int(rows[0]["site"], 0)
        check("exact user edge", user_edge(site, target) == (not baseline))
        count_ea = instructions[1].ea
        original = ida_bytes.get_bytes(count_ea, 2)
        check("exact zero-count encoding", original == b"\x31\xc9")
        if original == b"\x31\xc9" and not baseline:
            try:
                ida_bytes.patch_bytes(count_ea, b"\xb1\x01")
                assert ida_bytes.get_bytes(count_ea, 2) == b"\xb1\x01"
                reanalyze(root)
                changed = evidence(root)
                changed_rows = [
                    row
                    for row in changed["records"]
                    if row["kind"] == "stack-transfer" and row["fresh"] == "true"
                ]
                check(
                    "nonzero or unknown count abstains",
                    len(changed_rows) == 1
                    and changed_rows[0]["truth"] == "candidate"
                    and changed_rows[0].get("target", "unknown") == "unknown"
                    and changed_rows[0]["edge"] == "false"
                    and not user_edge(site, target),
                )
            finally:
                ida_bytes.patch_bytes(count_ea, original)
                assert ida_bytes.get_bytes(count_ea, 2) == original
                reanalyze(root)
            restored = evidence(root)
            restored_rows = [
                row
                for row in restored["records"]
                if row["kind"] == "stack-transfer" and row["fresh"] == "true"
            ]
            check(
                "zero-count proof restores",
                len(restored_rows) == 1
                and restored_rows[0]["truth"] == "native-proof"
                and restored_rows[0]["target"] == hex(target)
                and user_edge(site, target),
            )
except BaseException as error:
    errors.append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "rep_lods_zero.json").write_text(
    json.dumps({"checks": checks, "errors": errors, "observed": observed}, indent=2) + "\n"
)
line = "[chernobog][rep-lods-zero] " + (
    "FAIL " + "; ".join(errors) if errors else "PASS checks=%d" % len(checks)
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
