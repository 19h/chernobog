"""Check native read-stream projection across writes to a separate heap object."""

import json
import os
from pathlib import Path

import ida_auto
import ida_expr
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_lines
import ida_name
import ida_pro


def evaluate(expression):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    if value.vtype == ida_expr.VT_STR:
        return value.c_str()
    if value.vtype == ida_expr.VT_INT64:
        return value.i64
    if value.vtype == ida_expr.VT_LONG:
        return value.num
    raise ValueError("unsupported IDC result")


report = {"schema": 1, "passed": False, "checks": {}, "errors": []}


def check(name, condition):
    report["checks"][name] = bool(condition)
    if not condition:
        report["errors"].append(name)


try:
    expected = int(os.environ["CHERNOBOG_HEAP_WRITE_EXPECT"])
    assert expected in (0, 1)
    shared = os.environ.get("CHERNOBOG_HEAP_WRITE_SHARED") == "1"
    ida_auto.auto_wait()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    target = ida_name.get_name_ea(ida_idaapi.BADADDR, "_native_interleaved_strings")
    assert target != ida_idaapi.BADADDR
    report["target"] = hex(target)
    report["explore_result"] = int(evaluate(f"chernobog_rax_explore({target})"))
    summary = f"chernobog_rax_summary({target})"
    report["summary"] = {
        field: int(evaluate(summary + "." + field))
        for field in (
            "fresh",
            "runs",
            "returned_runs",
            "allocation_lifetimes",
            "use_snapshots",
            "temporal_capture_complete_runs",
            "temporal_capture_truncated_runs",
        )
    }
    fields = report["summary"]
    check(
        "all executions and temporal captures complete",
        fields["fresh"] == 1
        and fields["runs"] > 0
        and fields["returned_runs"] == fields["runs"]
        and fields["temporal_capture_complete_runs"] == fields["runs"]
        and fields["temporal_capture_truncated_runs"] == 0
        and fields["allocation_lifetimes"] == (1 if shared else 2) * fields["runs"]
        and fields["use_snapshots"] >= 16 * fields["runs"],
    )
    count = int(evaluate(f"chernobog_rax_use_string_count({target})"))
    report["candidate_count"] = count
    report["candidates"] = []
    for index in range(count):
        expression = f"chernobog_rax_use_string({target}, {index})"
        report["candidates"].append(
            {
                field: evaluate(expression + "." + field)
                for field in ("value", "producer", "read_count", "observations", "eligible_runs")
            }
        )
    check(
        "object-scoped projection",
        count == expected
        and (
            expected == 0
            or (
                report["candidates"][0]["value"] == "second!"
                and report["candidates"][0]["producer"] == "executed-read-stream"
                and report["candidates"][0]["read_count"] == 8
                and report["candidates"][0]["observations"]
                == report["candidates"][0]["eligible_runs"]
                == fields["runs"]
            )
        ),
    )
    view = json.loads(evaluate(f"chernobog_evidence_view({target})"))
    writes = [
        row
        for row in view["events"]
        if row["kind"] == "memory" and row["access_kind"] == "1" and row["scope"] == "0x2"
    ]
    report["retained_heap_writes"] = len(writes)
    report["event_omissions"] = view["omitted"].get("events", 0)
    check("executed heap writes retained", bool(writes))
    check("no image string projection", int(evaluate(f"chernobog_rax_string_count({target})")) == 0)
    assert ida_hexrays.init_hexrays_plugin()
    cfunc = ida_hexrays.decompile(target, None, ida_hexrays.DECOMP_NO_CACHE)
    assert cfunc is not None
    annotations = [
        ida_lines.tag_remove(line.line)
        for line in cfunc.get_pseudocode()
        if "rax-use(" in ida_lines.tag_remove(line.line)
    ]
    report["annotations"] = annotations
    check(
        "transient use-site display",
        len(annotations) == expected
        and (
            expected == 0 or ('"second!"' in annotations[0] and '"secret!"' not in annotations[0])
        ),
    )
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(type(error).__name__)

(Path(os.environ["IDAUSR"]).parent / "heap_write_strings.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
line = "[chernobog][heap-write-strings] " + ("PASS" if report["passed"] else "FAIL")
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(0 if report["passed"] else 2)
