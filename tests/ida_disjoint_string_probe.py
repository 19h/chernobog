"""Check two disjoint multisite heap strings in one allocation."""

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_loader
import ida_name
import ida_pro


def evaluate(expression):
    result = ida_expr.idc_value_t()
    if ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression):
        raise RuntimeError("IDC call failed: " + expression)
    if result.vtype == ida_expr.VT_STR:
        return result.c_str()
    if result.vtype == ida_expr.VT_INT64:
        return result.i64
    if result.vtype == ida_expr.VT_LONG:
        return result.num
    raise ValueError("unsupported IDC result")


report = {"schema": 1, "checks": {}, "errors": []}


def check(name, condition):
    report["checks"][name] = bool(condition)
    if not condition:
        report["errors"].append(name)


try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    target = ida_name.get_name_ea(ida_idaapi.BADADDR, "_native_disjoint_strings")
    key = ida_name.get_name_ea(ida_idaapi.BADADDR, "_native_disjoint_key")
    assert target != ida_idaapi.BADADDR and key != ida_idaapi.BADADDR
    owner = ida_funcs.get_func(target)
    assert owner is not None and owner.start_ea == target
    original_bytes = ida_bytes.get_bytes(target, owner.end_ea - target)
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
    counts = report["summary"]
    check(
        "complete temporal corpus",
        counts["fresh"] == 1
        and counts["runs"] >= 4
        and counts["runs"] == counts["returned_runs"]
        and counts["temporal_capture_complete_runs"] == counts["runs"]
        and counts["temporal_capture_truncated_runs"] == 0
        and counts["allocation_lifetimes"] == counts["runs"]
        and counts["use_snapshots"] >= 16 * counts["runs"],
    )
    total = int(evaluate(f"chernobog_rax_use_string_count({target})"))
    report["candidates"] = []
    for index in range(total):
        expression = f"chernobog_rax_use_string({target}, {index})"
        report["candidates"].append(
            {
                field: evaluate(expression + "." + field)
                for field in (
                    "value",
                    "producer",
                    "site",
                    "first_sequence",
                    "last_sequence",
                    "read_count",
                    "observations",
                    "eligible_runs",
                )
            }
        )
    check(
        "two disjoint corroborated strings",
        total == 2
        and {row["value"] for row in report["candidates"]} == {"secret!", "second!"}
        and all(
            row["producer"] == "executed-read-stream"
            and row["read_count"] == 8
            and row["first_sequence"] < row["last_sequence"]
            and row["observations"] == row["eligible_runs"] == counts["runs"]
            for row in report["candidates"]
        ),
    )
    view = json.loads(evaluate(f"chernobog_evidence_view({target})"))
    report["streams"] = view["read_streams"]
    report["heap_reads"] = [
        row
        for row in view["events"]
        if row["kind"] == "use" and row["producer"] == "executed-read" and row["scope"] == "0x2"
    ]
    report["heap_writes"] = [
        row
        for row in view["events"]
        if row["kind"] == "memory" and row["scope"] == "0x2" and row["access_kind"] == "1"
    ]
    report["stack_writes"] = [
        row
        for row in view["events"]
        if row["kind"] == "memory"
        and row["scope"] == "0x1"
        and row["access_kind"] == "1"
        and row["run"] == "0x0"
    ]
    if os.environ.get("CHERNOBOG_EXPECT_STACK_HASH") == "1":
        reads = sorted(
            int(row["sequence"], 16) for row in report["heap_reads"] if row["run"] == "0x0"
        )
        writes = [int(row["sequence"], 16) for row in report["stack_writes"]]
        check(
            "stack hash writes separate heap reads",
            len(reads) >= 4
            and all(
                any(first < write < second for write in writes)
                for first, second in zip(reads, reads[1:])
            ),
        )
    report["view_omitted"] = view["omitted"]
    check(
        "two separate streams per run",
        len(report["streams"]) == 2 * counts["runs"]
        and {row["bytes_hex"] for row in report["streams"]}
        == {"7365637265742100", "7365636f6e642100"}
        and all(
            len({part.split(":")[0] for part in row["fragments"].split(";") if part}) == 2
            for row in report["streams"]
        ),
    )
    check("no final image strings", int(evaluate(f"chernobog_rax_string_count({target})")) == 0)
    function = ida_hexrays.decompile(target, None, ida_hexrays.DECOMP_NO_CACHE)
    assert function is not None

    def rendered():
        return [ida_lines.tag_remove(line.line) for line in function.get_pseudocode()]

    report["pseudocode"] = rendered()
    report["annotations"] = [line for line in rendered() if "rax-use(" in line]
    check(
        "two transient annotations",
        len(report["annotations"]) == 2
        and any('"secret!"' in line for line in report["annotations"])
        and any('"second!"' in line for line in report["annotations"]),
    )
    comments = function.user_cmts
    saved = ida_hexrays.restore_user_cmts(target)
    check(
        "no stored comments",
        (comments is None or comments.size() == 0) and (saved is None or saved.size() == 0),
    )
    check(
        "function bytes unchanged",
        ida_bytes.get_bytes(target, len(original_bytes)) == original_bytes,
    )
    original_key = ida_bytes.get_byte(key)
    ida_bytes.patch_byte(key, original_key ^ 1)
    function.refresh_func_ctext()
    check("key edit revokes both", not any("rax-use(" in line for line in rendered()))
    ida_bytes.patch_byte(key, original_key)
    function.refresh_func_ctext()
    check("key restoration", sum("rax-use(" in line for line in rendered()) == 2)
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

report["passed"] = not report["errors"]
(Path(os.environ["IDAUSR"]).parent / "disjoint_string.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
line = "[chernobog][disjoint-string] " + (
    "PASS" if report["passed"] else "FAIL " + "; ".join(report["errors"])
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(0 if report["passed"] else 2)
