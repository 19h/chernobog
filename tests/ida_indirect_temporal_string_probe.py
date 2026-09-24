"""Inspect modeled temporal strings at indirect calls in a native fixture."""

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
import ida_ua


def evaluate(expression):
    result = ida_expr.idc_value_t()
    error = ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression)
    assert not error, "IDC evaluation failed"
    if result.vtype == ida_expr.VT_STR:
        return result.c_str()
    if result.vtype == ida_expr.VT_INT64:
        return result.i64
    if result.vtype == ida_expr.VT_LONG:
        return result.num
    return result


errors = []
report = {}
expected_annotations = int(os.environ.get("CHERNOBOG_INDIRECT_EXPECT_ANNOTATIONS", "2"))
assert expected_annotations in (0, 2)
try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin(), "Hex-Rays unavailable"
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]), "plugin unavailable"
    target = ida_name.get_name_ea(ida_idaapi.BADADDR, "_indirect_temporal_strings")
    key = ida_name.get_name_ea(ida_idaapi.BADADDR, "_indirect_temporal_key")
    dispatch = ida_name.get_name_ea(ida_idaapi.BADADDR, "_indirect_strlen_dispatch")
    assert all(
        address != ida_idaapi.BADADDR for address in (target, key, dispatch)
    ), "fixture symbol missing"
    report["explore"] = int(evaluate(f"chernobog_rax_explore({target})"))
    summary = f"chernobog_rax_summary({target})"
    report["summary"] = {
        field: int(evaluate(summary + "." + field))
        for field in [
            "fresh",
            "runs",
            "returned_runs",
            "allocation_lifetimes",
            "use_snapshots",
            "temporal_capture_complete_runs",
            "environment_model_failure_runs",
        ]
    }
    count = int(evaluate(f"chernobog_rax_use_string_count({target})"))
    report["candidates"] = []
    for index in range(count):
        expression = f"chernobog_rax_use_string({target}, {index})"
        candidate = {
            field: evaluate(expression + "." + field)
            for field in [
                "value",
                "site",
                "callee",
                "occurrence",
                "argument",
                "producer",
                "model_kind",
                "observations",
                "eligible_runs",
            ]
        }
        insn = ida_ua.insn_t()
        candidate["decoded"] = ida_ua.decode_insn(insn, candidate["site"])
        candidate["operand_type"] = insn.Op1.type
        candidate["itype"] = insn.itype
        report["candidates"].append(candidate)
    function = ida_hexrays.decompile(target, None, ida_hexrays.DECOMP_NO_CACHE)
    assert function is not None, "fixture decompilation failed"

    def rendered():
        return [ida_lines.tag_remove(line.line) for line in function.get_pseudocode()]

    report["pseudocode"] = rendered()

    class Calls(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.rows = []

        def visit_expr(self, expression):
            if expression.op == ida_hexrays.cot_call:
                self.rows.append(
                    {
                        "site": expression.ea,
                        "callee_op": expression.x.op if expression.x else -1,
                        "callee_ea": expression.x.ea if expression.x else -1,
                        "argument_count": expression.a.size() if expression.a else -1,
                    }
                )
            return 0

    calls = Calls()
    calls.apply_to(function.body, None)
    report["calls"] = calls.rows
    modeled = [
        candidate
        for candidate in report["candidates"]
        if candidate["producer"] == "modeled-argument"
    ]
    if (
        len(modeled) != 2
        or [candidate["value"] for candidate in modeled] != ["secret!", "second!"]
        or any(
            candidate["argument"] != 0
            or candidate["model_kind"] != 6
            or candidate["observations"] != 4
            or candidate["eligible_runs"] != 4
            or candidate["callee"] == 0
            or candidate["decoded"] != 2
            or candidate["operand_type"] != ida_ua.o_reg
            or sum(call["site"] == candidate["site"] for call in calls.rows) != 1
            for candidate in modeled
        )
    ):
        errors.append("modeled indirect-call evidence")
    annotations = [line for line in report["pseudocode"] if "rax-use(modeled" in line]
    if len(annotations) != expected_annotations or (
        expected_annotations == 2
        and (
            not any('"secret!"' in line for line in annotations)
            or not any('"second!"' in line for line in annotations)
            or any(
                "modeled strlen,arg=0,use=1,runs=4,observed-target=0x" not in line
                for line in annotations
            )
        )
    ):
        errors.append("indirect-call display")
    initial_text = str(function)
    if rendered() != report["pseudocode"] or str(function) != initial_text:
        errors.append("repeat display stability")
    current_comments = function.user_cmts
    saved_comments = ida_hexrays.restore_user_cmts(target)
    if (current_comments is not None and current_comments.size() != 0) or (
        saved_comments is not None and saved_comments.size() != 0
    ):
        errors.append("transient display persistence")
    owner = ida_funcs.get_func(target)
    original_function = ida_bytes.get_bytes(target, owner.end_ea - target)
    if ida_bytes.get_bytes(target, len(original_function)) != original_function:
        errors.append("function byte preservation")
    original_key = ida_bytes.get_byte(key)
    ida_bytes.patch_byte(key, original_key ^ 1)
    function.refresh_func_ctext()
    if any("rax-use(" in line for line in rendered()):
        errors.append("consumed key invalidation")
    ida_bytes.patch_byte(key, original_key)
    function.refresh_func_ctext()
    if sum("rax-use(modeled" in line for line in rendered()) != expected_annotations:
        errors.append("exact key restoration")
    original_dispatch = ida_bytes.get_byte(dispatch)
    ida_bytes.patch_byte(dispatch, original_dispatch ^ 1)
    function.refresh_func_ctext()
    if any("rax-use(modeled" in line for line in rendered()):
        errors.append("consumed dispatch invalidation")
    ida_bytes.patch_byte(dispatch, original_dispatch)
    function.refresh_func_ctext()
    if sum("rax-use(modeled" in line for line in rendered()) != expected_annotations:
        errors.append("exact dispatch restoration")
except BaseException as error:
    errors.append(type(error).__name__ + ": " + str(error))

report["errors"] = errors
(Path(os.environ["IDAUSR"]).parent / "indirect_temporal_strings.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
line = "[chernobog][indirect-temporal-strings] " + (
    "FAIL " + "; ".join(errors)
    if errors
    else "PASS modeled=2 annotations=%d" % expected_annotations
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
