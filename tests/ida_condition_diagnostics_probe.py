"""Check read-only condition diagnostics against exact protected instruction sites."""

import importlib.util
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
import ida_pro
import idautils

sys.dont_write_bytecode = True
cases = json.loads(os.environ["CHERNOBOG_CONDITION_CASES"])
report = {"passed": False, "errors": [], "cases": []}


def query(name, root):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"{name}({root})")
    return json.loads(value.c_str())


def inventory(root):
    return [
        (
            int(ea),
            int(ida_bytes.get_full_flags(ea)),
            int(ida_bytes.get_item_end(ea)),
            ida_bytes.get_bytes(ea, ida_bytes.get_item_size(ea)),
            ida_bytes.get_cmt(ea, True),
            ida_bytes.get_cmt(ea, False),
            sorted((int(ref.to), int(ref.type)) for ref in idautils.XrefsFrom(ea)),
        )
        for ea in idautils.FuncItems(root)
    ]


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    ida_expr.eval_idc_expr(
        ida_expr.idc_value_t(), ida_idaapi.BADADDR, "chernobog_native_analysis()"
    )
    module_path = os.environ.get("CHERNOBOG_VIEW_MODULE")
    module = None
    if module_path:
        spec = importlib.util.spec_from_file_location("condition_diagnostics_view", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    for case in cases:
        root = int(case["root"], 0)
        owner = ida_funcs.get_func(root)
        assert owner is not None and owner.start_ea == root
        before = inventory(root)
        proof_before = query("chernobog_native_evidence", root)
        view = query("chernobog_native_condition_diagnostics", root)
        repeat = query("chernobog_native_condition_diagnostics", root)
        proof_after = query("chernobog_native_evidence", root)
        after = inventory(root)
        assert view == repeat and proof_before == proof_after and before == after
        assert view["available"] and view["function"] == hex(root)
        assert not view["truncated"] and view["omitted"] == 0
        assert view["condition_sites"] == len(view["records"])
        rows = {row["site"]: row for row in view["records"]}
        for expected in case["sites"]:
            row = rows[expected["site"]]
            for key in ("kind", "decision", "status", "site_bytes"):
                assert row[key] == expected[key], (key, row[key], expected[key])
            assert row["scope"] and row["support_count"]
        if module is not None:
            matched = module.matching_condition_sources(view)
            assert matched >= {expected["site"] for expected in case["sites"]}
            altered = dict(view, records=[dict(row) for row in view["records"]])
            for row in altered["records"]:
                if row["site"] == case["sites"][0]["site"]:
                    row["site_bytes"] = "00" + row["site_bytes"][2:]
            assert case["sites"][0]["site"] not in module.matching_condition_sources(altered)
        report["cases"].append(
            {
                "root": hex(root),
                "expected_sites": case["sites"],
                "heads_examined": view["heads_examined"],
                "condition_sites": view["condition_sites"],
                "omitted": view["omitted"],
                "truncated": view["truncated"],
                "records": view["records"],
                "native_proof_count": len(proof_before["records"]),
                "read_only": True,
                "repeat_equal": True,
                "view_source_match_checked": module is not None,
            }
        )
    report["passed"] = True
except Exception as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
finally:
    (Path(os.environ["IDAUSR"]).parent / "condition_diagnostics.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print("[chernobog][condition-diagnostics] " + ("PASS" if report["passed"] else "FAIL"))
    ida_pro.qexit(0 if report["passed"] else 1)
