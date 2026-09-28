"""Capture the same early-stop target sites with preceding and current plugins."""

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
import idautils

sys.dont_write_bytecode = True
NAMES = (
    "df_repne_cmps_two_count_target",
    "df_repe_scas_two_count_target",
    "df_repe_cmps_one_count_target",
    "df_repne_scas_one_count_target",
)
report = {"schema": 1, "passed": False, "errors": [], "sites": {}}


def address(name):
    for candidate in ("_" + name, name):
        result = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if result != ida_idaapi.BADADDR:
            return result
    raise RuntimeError("fixture symbol absent: " + name)


def evidence(ea):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"chernobog_native_evidence({ea})")
    return json.loads(value.c_str())


try:
    ida_auto.auto_wait()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    target = address("df_memory_target")
    for name in NAMES:
        root = address(name)
        function = ida_funcs.get_func(root)
        assert function and function.start_ea == root
        ida_auto.plan_and_wait(root, function.end_ea)
        ida_auto.auto_wait()
        span = min(function.end_ea - root, 128)
        before = {
            "bytes": (ida_bytes.get_bytes(root, span) or b"").hex(),
            "flags": ida_bytes.get_full_flags(root),
        }
        snapshot = evidence(root)
        rows = [
            row
            for row in snapshot["records"]
            if row["kind"] == "stack-transfer" and row["fresh"] == "true"
        ]
        assert len(rows) == 1
        row = rows[0]
        edges = sorted(
            {hex(x.to) for x in idautils.XrefsFrom(int(row["site"], 0)) if x.iscode and x.user}
        )
        after = {
            "bytes": (ida_bytes.get_bytes(root, span) or b"").hex(),
            "flags": ida_bytes.get_full_flags(root),
        }
        assert before == after
        report["sites"][name] = {
            "root": hex(root),
            "site": row["site"],
            "source": row["source"],
            "truth": row["truth"],
            "edge": row["edge"],
            "target": row.get("target", "unknown"),
            "target_basis": row["target_basis"],
            "target_proof": row.get("target_proof", "not recorded"),
            "user_edges": edges,
            "expected_target": hex(target),
            "source_bytes": before["bytes"],
            "source_flags": before["flags"],
        }
    report["passed"] = True
except Exception as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
finally:
    (Path(os.environ["IDAUSR"]).parent / "rep_compare_early_delta.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n"
    )
    print("[chernobog][rep-compare-early-delta] " + ("PASS" if report["passed"] else "FAIL"))
    ida_pro.qexit(0 if report["passed"] else 1)
