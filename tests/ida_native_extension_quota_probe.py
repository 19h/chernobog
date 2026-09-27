"""Check a joined native target at the existing 4096-head bound without IDB edits."""

import json
import os
from pathlib import Path
import traceback

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_loader
import ida_name
import ida_pro
import idautils

records, errors = [], []
captures = {}


def check(name, condition):
    records.append({"case": name, "passed": bool(condition)})
    if not condition:
        errors.append(name)


def api(ea):
    value = ida_expr.idc_value_t()
    request = json.dumps(json.dumps({"args": [], "objects": []}))
    assert not ida_expr.eval_idc_expr(
        value, ida_idaapi.BADADDR, f"chernobog_vm_trace_walk({ea}, 0, {request})"
    )
    return json.loads(value.c_str())


def inventory():
    return {
        "heads": [(int(ea), int(ida_bytes.get_full_flags(ea))) for ea in idautils.Heads()],
        "functions": [
            (int(ea), int(ida_funcs.get_func(ea).flags), list(idautils.Chunks(ea)))
            for ea in idautils.Functions()
        ],
    }


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    ida_auto.enable_auto(False)
    entry = ida_name.get_name_ea(ida_idaapi.BADADDR, "_native_extension_quota")
    assert entry != ida_idaapi.BADADDR
    before = inventory()
    initial = int(os.environ["CHERNOBOG_EXPECT_INITIAL_HEADS"])
    complete = os.environ["CHERNOBOG_EXPECT_EXTENDED_RETURN"] == "1"
    for run in range(2):
        trace = api(entry)
        captures[str(run)] = trace
        check("bounded native walk available", trace["available"] and trace["ran"])
        check(
            "ordinary publication excluded",
            not trace["function_evidence_published"] and not trace["vm_identity_proved"],
        )
        check(
            "one observed indirect destination",
            len(trace["native_admissions"]) == 1
            and trace["native_admissions"][0]["admitted"] == "true",
        )
        admission = trace["native_admissions"][0]
        added = int(admission["added_heads"])
        check("initial head inventory", trace["planned_heads"] - added == initial)
        check("full head bound", trace["planned_heads"] <= 4096)
        check("completion oracle", trace["reached_sentinel"] == complete)
        if complete:
            check(
                "complete joined path and exact quota",
                added == 4
                and trace["planned_heads"] == 4096
                and not trace["plan_truncated"]
                and trace["instruction_count"] == 8
                and trace["sp_valid"]
                and trace["sp_delta"] == 8,
            )
            check(
                "native result oracle",
                any(
                    int(row["reg"]) == 0x100 and int(row["value"], 16) == 42
                    for row in trace["final_registers"]
                ),
            )
        else:
            check(
                "unfinished path remains explicit",
                trace["plan_truncated"] and trace["region_boundary"],
            )
        check("IDB inventory unchanged", inventory() == before)
except Exception as error:
    errors.append(type(error).__name__)
    errors.extend(
        Path(frame.filename).name + ":" + str(frame.lineno)
        for frame in traceback.extract_tb(error.__traceback__)
    )

(Path(os.environ["IDAUSR"]).parent / "native_extension_quota.json").write_text(
    json.dumps({"records": records, "errors": errors, "captures": captures}, indent=2) + "\n"
)
print("[chernobog][native-extension-quota] " + ("FAIL" if errors else "PASS"))
ida_pro.qexit(1 if errors else 0)
