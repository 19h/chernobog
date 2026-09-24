"""Check exact heap-string reconstruction from two native read sites."""

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
    target = ida_name.get_name_ea(ida_idaapi.BADADDR, "_native_multisite_strings")
    key = ida_name.get_name_ea(ida_idaapi.BADADDR, "_native_multisite_key")
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
        "one exact multisite candidate",
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
    first_offsets = set()
    site_counts = []
    for row in streams:
        fragments = [entry.split(":") for entry in row["fragments"].split(";") if entry]
        first_offsets.add(int(fragments[0][2], 0) - int(row["address"], 0))
        site_counts.append(len({entry[0] for entry in fragments}))
    report["first_read_offsets"] = sorted(first_offsets)
    report["site_counts"] = site_counts
    check(
        "two exact sites and both read orders",
        len(streams) == counts["runs"] * expected
        and (expected == 0 or first_offsets == {3, 7})
        and all(count == 2 for count in site_counts)
        and all(row["bytes_hex"] == "7365637265742100" for row in streams),
    )
    check("no final image strings", int(evaluate(f"chernobog_rax_string_count({target})")) == 0)
    function = ida_hexrays.decompile(target, None, ida_hexrays.DECOMP_NO_CACHE)
    assert function is not None

    def rendered():
        return [ida_lines.tag_remove(line.line) for line in function.get_pseudocode()]

    class ReadSites(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.sites = set()

        def visit_expr(self, item):
            if item.op in (ida_hexrays.cot_ptr, ida_hexrays.cot_idx):
                self.sites.add(int(item.ea))
            return 0

    visitor = ReadSites()
    visitor.apply_to(function.body, None)
    report["read_expr_sites"] = sorted(visitor.sites)
    report["pseudocode"] = rendered()
    common_fragment_sites = (
        {int(entry.split(":")[0], 0) for entry in streams[0]["fragments"].split(";") if entry}
        if streams
        else set()
    )
    check(
        "fallback uses a surviving exact fragment site",
        expected == 0
        or (
            report["candidates"][0]["site"] not in visitor.sites
            and len(common_fragment_sites & visitor.sites) == 1
        ),
    )
    report["annotations"] = [line for line in rendered() if "rax-use(" in line]
    check(
        "transient read-site annotation",
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
(Path(os.environ["IDAUSR"]).parent / "multisite_string.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
line = "[chernobog][multisite-string] " + (
    "PASS" if report["passed"] else "FAIL " + "; ".join(report["errors"])
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(0 if report["passed"] else 2)
