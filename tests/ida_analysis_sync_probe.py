"""Check synchronized inspection and bounded caller collection in isolated IDA."""

import json
import os
from pathlib import Path

import ida_auto
import ida_expr
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro


def evaluate(expression):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    if value.vtype == ida_expr.VT_STR:
        return value.c_str()
    if value.vtype == ida_expr.VT_INT64:
        return value.i64
    return value.num


def address(name):
    for candidate in (name, "_" + name):
        result = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if result != ida_idaapi.BADADDR:
            return result
    raise AssertionError("fixture symbol missing: " + name)


try:
    ida_auto.auto_wait()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    target = address("analysis_target")
    evaluate(f"chernobog_rax_explore({target})")
    summary = f"chernobog_rax_summary({target})"
    assert evaluate(summary + ".entry_inputs_truncated") == 1
    assert evaluate(summary + ".entry_sites_visited") == 256

    prefix = address("analysis_prefix")
    evaluate(f"chernobog_rax_explore({prefix})")
    snapshot = json.loads(evaluate(f"chernobog_evidence_view({prefix})"))
    assert snapshot["fresh"]
    uses = [
        row
        for row in snapshot["use_strings"]
        if row["producer"] == "call-boundary-argument" and row["value"] == "prefix-stack"
    ]
    assert uses and all(row["callee_executed"] == "false" for row in uses)
    assert all(row["temporal_ledger"] == "call_prefix" for row in snapshot["runs"])
    assert all(row["returned"] == "false" for row in snapshot["runs"])
    count = evaluate(f"chernobog_rax_use_string_count({prefix})")
    assert count > 0
    values = [
        evaluate(f"chernobog_rax_use_string({prefix}, {index}).value") for index in range(count)
    ]
    assert "prefix-stack" in values
    (Path(os.environ["IDAUSR"]).parent / "analysis_sync.json").write_text(
        json.dumps(snapshot, indent=2) + "\n", encoding="utf-8"
    )
    message = "[chernobog][analysis-sync] PASS caller bound and prefix inspection"
    print(message, flush=True)
    ida_kernwin.msg("%s\n" % message)
    ida_pro.qexit(0)
except BaseException as error:
    message = "[chernobog][analysis-sync] FAIL " + repr(error)
    print(message, flush=True)
    ida_kernwin.msg("%s\n" % message)
    ida_pro.qexit(1)
