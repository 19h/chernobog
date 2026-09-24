"""Check cross-run read-order consensus and exact evidence in IDA."""

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
import ida_loader
import ida_lines
import ida_name
import ida_pro


def evaluate(expression):
    result = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression)
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
    expected = int(os.environ["CHERNOBOG_EXPECT_COUNT"])
    assert expected in (0, 1)
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    target = ida_name.get_name_ea(ida_idaapi.BADADDR, "_native_permuted_variable")
    key = ida_name.get_name_ea(ida_idaapi.BADADDR, "_native_permuted_variable_key")
    assert target != ida_idaapi.BADADDR and key != ida_idaapi.BADADDR
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
        and counts["use_snapshots"] >= 8 * counts["runs"],
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
                    "first_sequence",
                    "last_sequence",
                    "read_count",
                    "observations",
                    "eligible_runs",
                )
            }
        )
    check(
        "cross-run consensus",
        total == expected
        and all(
            row["value"] == "secret!"
            and row["producer"] == "executed-read-stream"
            and row["read_count"] == 8
            and row["first_sequence"] < row["last_sequence"]
            and row["observations"] == row["eligible_runs"] == counts["runs"]
            for row in report["candidates"]
        ),
    )
    view = json.loads(evaluate(f"chernobog_evidence_view({target})"))
    streams = view["read_streams"]
    report["streams"] = streams
    offsets = set()
    for row in streams:
        first_fragment = row["fragments"].split(";")[0].split(":")
        offsets.add(int(first_fragment[2], 0) - int(row["address"], 0))
    report["first_read_offsets"] = sorted(offsets)
    check(
        "both read permutations witnessed",
        len(streams) == counts["runs"] * expected
        and (expected == 0 or offsets == {3, 7})
        and all(row["bytes_hex"] == "7365637265742100" for row in streams),
    )
    check("no final image strings", int(evaluate(f"chernobog_rax_string_count({target})")) == 0)
    function = ida_hexrays.decompile(target, None, ida_hexrays.DECOMP_NO_CACHE)
    assert function is not None

    def rendered():
        return [ida_lines.tag_remove(line.line) for line in function.get_pseudocode()]

    report["annotations"] = [line for line in rendered() if "rax-use(" in line]
    check(
        "transient indexed-read annotation",
        len(report["annotations"]) == expected
        and all('"secret!"' in line for line in report["annotations"]),
    )
    comments = function.user_cmts
    saved = ida_hexrays.restore_user_cmts(target)
    check(
        "no stored comments",
        (comments is None or comments.size() == 0) and (saved is None or saved.size() == 0),
    )
    owner = ida_funcs.get_func(target)
    original_function = ida_bytes.get_bytes(target, owner.end_ea - target)
    check(
        "function bytes unchanged",
        ida_bytes.get_bytes(target, len(original_function)) == original_function,
    )
    original_key = ida_bytes.get_byte(key)
    ida_bytes.patch_byte(key, original_key ^ 1)
    function.refresh_func_ctext()
    check("key edit revokes display", not any("rax-use(" in line for line in rendered()))
    ida_bytes.patch_byte(key, original_key)
    function.refresh_func_ctext()
    check("key restoration", sum("rax-use(" in line for line in rendered()) == expected)
except BaseException as error:
    report["errors"].append(type(error).__name__)

report["passed"] = not report["errors"]
(Path(os.environ["IDAUSR"]).parent / "permuted_variable.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
line = "[chernobog][permuted-variable] " + (
    "PASS" if report["passed"] else "FAIL " + "; ".join(report["errors"])
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(0 if report["passed"] else 2)
