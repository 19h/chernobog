"""Owned-function dataflow, source provenance, and join topology invalidation."""

import json
import os
from pathlib import Path
import sys

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_loader
import ida_name
import ida_pro
import ida_ua
import ida_xref
import idautils

sys.dont_write_bytecode = True
records, errors, captures = [], [], {}


def check(label, condition):
    records.append({"case": label, "passed": bool(condition)})
    if not condition:
        errors.append(label)


def address(name):
    for candidate in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return ea
    raise AssertionError("fixture symbol missing")


def inspect(ea):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"chernobog_native_evidence({ea})")
    return json.loads(value.c_str())


def reanalyze(ea):
    function = ida_funcs.get_func(ea)
    assert function
    ida_auto.plan_and_wait(function.start_ea, function.end_ea)
    ida_auto.auto_wait()


def current_set(snapshot):
    return [r for r in snapshot["records"] if r["kind"] == "setcc-value" and r["fresh"] == "true"]


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    expected = {
        "df_equal": True,
        "df_different": False,
        "df_flags": True,
        "df_loop": True,
        "df_loop_changes": False,
        "df_stack": True,
        "df_stack_changes": False,
        "df_jump": True,
    }
    for name, proved in expected.items():
        ea = address(name)
        reanalyze(ea)
        snapshot = inspect(ea)
        snapshot["native_inventory"] = [
            {
                "site": hex(site),
                "bytes": (ida_bytes.get_bytes(site, ida_bytes.get_item_size(site)) or b"").hex(),
                "disassembly": idautils.DecodeInstruction(site).get_canon_mnem(),
                "incoming": [
                    {"source": hex(x.frm), "type": int(x.type)} for x in idautils.XrefsTo(site)
                ],
            }
            for site in idautils.FuncItems(ea)
            if ida_bytes.is_code(ida_bytes.get_flags(site))
        ]
        captures[name] = snapshot
        rows = current_set(snapshot)
        check(name + " exact admission", bool(rows) == proved)
        if rows:
            check(name + " proven one", len(rows) == 1 and rows[0]["value"] == "0x1")
            check(name + " graph source dependencies", int(rows[0]["dependency_count"]) >= 4)
    target_ea = address("df_target")
    reanalyze(target_ea)
    captures["df_target"] = inspect(target_ea)
    target_rows = [
        r
        for r in captures["df_target"]["records"]
        if r["kind"] == "stack-transfer"
        and r["fresh"] == "true"
        and r["truth"] == "native-proof"
        and r["edge"] == "true"
        and r["target_basis"] == "register-definition"
    ]
    check("equal predecessor pointers recover register PUSH/RET", bool(target_rows))
    if target_rows:
        check(
            "recovered transfer preserves stack effects",
            all(
                r["stack_delta_bytes"] == "0"
                and int(r["stack_write_bytes"]) * 8 == int(r["width_bits"])
                for r in target_rows
            ),
        )
    changing_ea = address("df_target_changes")
    reanalyze(changing_ea)
    captures["df_target_changes"] = inspect(changing_ea)
    changing_rows = [
        r for r in captures["df_target_changes"]["records"] if r["kind"] == "stack-transfer"
    ]
    check(
        "different predecessor pointers remain unresolved",
        changing_rows
        and all(
            r["truth"] == "candidate" and r["edge"] == "false" and r["target_basis"] == "unresolved"
            for r in changing_rows
        ),
    )
    ea = address("df_equal")
    instructions = []
    for site in idautils.FuncItems(ea):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, site) > 0:
            instructions.append(insn)
    join = next(insn.ea for insn in instructions if insn.get_canon_mnem() == "cmp")
    source = address("df_external")
    assert ida_xref.add_cref(source, join, ida_xref.fl_JN | ida_xref.XREF_USER)
    reanalyze(ea)
    captures["external_entry"] = inspect(ea)
    check(
        "external join entry revokes exact condition", not current_set(captures["external_entry"])
    )
    ida_xref.del_cref(source, join, False)
    reanalyze(ea)
    check("removed external entry allows recomputation", bool(current_set(inspect(ea))))
    defining = next(
        insn
        for insn in instructions
        if insn.get_canon_mnem() == "mov" and insn.Op2.type == ida_ua.o_imm
    )
    raw = ida_bytes.get_bytes(defining.ea, defining.size)
    assert raw[-4:] == bytes((42, 0, 0, 0))
    ida_bytes.patch_byte(defining.ea + defining.size - 4, 41)
    reanalyze(ea)
    captures["changed_predecessor"] = inspect(ea)
    check(
        "one changed predecessor removes join consensus",
        not current_set(captures["changed_predecessor"]),
    )
    ida_bytes.patch_bytes(defining.ea, raw)
    reanalyze(ea)
    check("exact predecessor restoration recomputes", bool(current_set(inspect(ea))))
except BaseException as error:
    errors.append(type(error).__name__)

(Path(os.environ["IDAUSR"]).parent / "dataflow.json").write_text(
    json.dumps({"records": records, "errors": errors, "captures": captures}, indent=2) + "\n"
)
print("[chernobog][dataflow] " + ("FAIL" if errors else "PASS"), flush=True)
ida_pro.qexit(2 if errors else 0)
