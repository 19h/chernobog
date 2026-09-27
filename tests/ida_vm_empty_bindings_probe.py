"""Check empty native temporal model contracts on a supplied static ELF."""

import json
import os
from pathlib import Path
import sys

import ida_auto
import ida_bytes
import ida_expr
import ida_idaapi
import ida_loader
import ida_pro

sys.dont_write_bytecode = True
report = {"passed": False, "errors": [], "checks": []}


def evaluate(name, *arguments):
    expression = name + "(" + ",".join(json.dumps(arg) for arg in arguments) + ")"
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    assert value.vtype == ida_expr.VT_STR
    return json.loads(value.c_str())


def check(label, condition):
    report["checks"].append({"case": label, "passed": bool(condition)})
    if not condition:
        report["errors"].append(label)


try:
    ida_auto.auto_wait()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    entry = int(os.environ.get("CHERNOBOG_VM_ENTRY", "0x40025b"), 0)
    request = json.dumps({"args": [], "objects": []})
    before = {
        "bytes": (ida_bytes.get_bytes(entry, 16) or b"").hex(),
        "flags": ida_bytes.get_full_flags(entry),
    }
    traces = {}
    for name in ("chernobog_vm_trace_temporal", "chernobog_vm_trace_temporal_check"):
        trace = evaluate(name, entry, 0, request, "[]")
        traces[name] = {
            key: trace.get(key)
            for key in (
                "available",
                "ran",
                "reason",
                "stop_reason",
                "instruction_count",
                "native_temporal_requested",
                "native_temporal_prefix_complete",
                "function_evidence_published",
                "vm_identity_proved",
                "environment_bindings",
            )
        }
        check(
            name + " accepts empty contract",
            trace.get("available")
            and trace.get("ran")
            and trace.get("native_temporal_requested")
            and trace.get("environment_bindings") == [],
        )
        check(
            name + " preserves proof boundary",
            not trace.get("function_evidence_published") and not trace.get("vm_identity_proved"),
        )
    report["traces"] = traces
    for models in ("", "{}", "[{}]", '["unknown"]'):
        trace = evaluate("chernobog_vm_trace_temporal_check", entry, 0, request, models)
        check(
            "malformed contract rejected: " + repr(models),
            not trace.get("available")
            and trace.get("reason") == "invalid named environment bindings",
        )
    strings = evaluate("chernobog_vm_temporal_strings", entry, request, "[]")
    check(
        "string consensus retains named-model requirement",
        not strings.get("available")
        and strings.get("reason") == "invalid named environment bindings",
    )
    after = {
        "bytes": (ida_bytes.get_bytes(entry, 16) or b"").hex(),
        "flags": ida_bytes.get_full_flags(entry),
    }
    check("selected source unchanged", before == after)
    report["source"] = before
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
finally:
    (Path(os.environ["IDAUSR"]).parent / "vm_empty_bindings.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n"
    )
    print("[chernobog][vm-empty-bindings] " + ("PASS" if report["passed"] else "FAIL"))
    ida_pro.qexit(0 if report["passed"] else 1)
