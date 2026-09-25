"""Exercise use-string production publication and consumed-key freshness."""

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
    error = ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression)
    assert not error, "IDC evaluation failed"
    if result.vtype == ida_expr.VT_STR:
        return result.c_str()
    if result.vtype == ida_expr.VT_INT64:
        return result.i64
    if result.vtype == ida_expr.VT_LONG:
        return result.num
    return result


records, errors = [], []


def check(label, condition, **details):
    records.append({"case": label, "passed": bool(condition), **details})
    if not condition:
        errors.append(label)


try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin(), "Hex-Rays unavailable"
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]), "plugin unavailable"
    target = ida_name.get_name_ea(ida_idaapi.BADADDR, "_temporal_strings")
    key = ida_name.get_name_ea(ida_idaapi.BADADDR, "_temporal_key")
    assert target != ida_idaapi.BADADDR and key != ida_idaapi.BADADDR, "fixture symbols missing"

    def count():
        return int(evaluate(f"chernobog_rax_use_string_count({target})"))

    def explore():
        code = int(evaluate(f"chernobog_rax_explore({target})"))
        summary = f"chernobog_rax_summary({target})"
        fields = [
            "fresh",
            "runs",
            "returned_runs",
            "allocation_lifetimes",
            "use_snapshots",
            "temporal_observation_available_runs",
            "temporal_capture_complete_runs",
            "temporal_capture_truncated_runs",
            "environment_model_failure_runs",
        ]
        values = {field: int(evaluate(summary + "." + field)) for field in fields}
        check(
            "completed publication",
            values["fresh"] == 1
            and values["runs"] > 0
            and values["returned_runs"] == values["runs"]
            and values["temporal_capture_complete_runs"] == values["runs"]
            and values["allocation_lifetimes"] == 2 * values["runs"]
            and values["temporal_capture_truncated_runs"] == 0,
            result=code,
            summary=values,
        )

    explore()
    check("two temporal candidates", count() == 2, count=count())
    values = []
    candidates = []
    for index in range(count()):
        expression = f"chernobog_rax_use_string({target}, {index})"
        candidate = {
            field: evaluate(expression + "." + field)
            for field in [
                "ok",
                "value",
                "site",
                "callee",
                "occurrence",
                "argument",
                "producer",
                "model_kind",
                "object_site",
                "object_size",
                "observations",
                "eligible_runs",
            ]
        }
        candidates.append(candidate)
        values.append(candidate["value"])
        check(
            "modeled use provenance",
            candidate["ok"] == 1
            and candidate["producer"] == "modeled-argument"
            and candidate["argument"] == 0
            and candidate["model_kind"] == 6
            and candidate["object_size"] == 16
            and candidate["observations"] == candidate["eligible_runs"],
            candidate=candidate,
        )
    check("use-specific plaintext", values == ["secret!", "second!"], values=values)
    view = json.loads(evaluate(f"chernobog_evidence_view({target})"))
    bindings = view.get("model_bindings", [])
    check(
        "named model contract and call transfers",
        len(candidates) == 2
        and len(
            [
                row
                for row in bindings
                if int(row["address"], 16) == candidates[0]["callee"]
                and row["kind"] == "0x6"
                and row["name"]
                and row["truth"] == "model-contract"
            ]
        )
        == 1
        and all(
            any(
                edge["kind"] == "observed-transfer"
                and edge["transfer_kind"] == "0x1"
                and int(edge["site"], 16) == candidate["site"]
                and int(edge["target"], 16) == candidate["callee"]
                for edge in view["edges"]
            )
            for candidate in candidates
        ),
        bindings=bindings,
    )
    check("no final image projection", int(evaluate(f"chernobog_rax_string_count({target})")) == 0)
    check("invalid index", int(evaluate(f"chernobog_rax_use_string({target}, 9999).ok")) == 0)
    function = ida_funcs.get_func(target)
    original_function = ida_bytes.get_bytes(target, function.end_ea - target)
    cfunc = ida_hexrays.decompile(target, None, ida_hexrays.DECOMP_NO_CACHE)
    assert cfunc is not None, "fixture decompilation failed"
    ast = str(cfunc)

    def rendered():
        return [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]

    lines = rendered()
    annotations = [line for line in lines if "rax-use(" in line]
    check(
        "transient use display",
        len(annotations) == 2
        and any(
            '"secret!"' in line and "modeled strlen,arg=0,use=1,runs=" in line
            for line in annotations
        )
        and any('"second!"' in line for line in annotations),
        lines=annotations,
    )
    check("repeat display is stable", rendered() == lines and str(cfunc) == ast)
    active_comments = cfunc.user_cmts
    saved_comments = ida_hexrays.restore_user_cmts(target)
    check(
        "no saved or saveable use comments",
        (active_comments is None or active_comments.size() == 0)
        and (saved_comments is None or saved_comments.size() == 0),
    )
    callee = candidates[0]["callee"]
    callee_name = ida_name.get_name(callee)
    assert callee_name and ida_name.set_name(callee, callee_name + "_model_edited")
    cfunc.refresh_func_ctext()
    check(
        "callee model rename revokes uses and display",
        count() == 0 and not any("rax-use(" in line for line in rendered()),
    )
    assert ida_name.set_name(callee, callee_name)
    cfunc.refresh_func_ctext()
    restored_count = count()
    restored_annotations = [line for line in rendered() if "rax-use(" in line]
    check(
        "callee model name restoration recovers sealed display",
        restored_count == 0 and len(restored_annotations) == 2,
        count=restored_count,
        annotations=restored_annotations,
        name=ida_name.get_name(callee),
    )
    explore()
    check("callee model re-exploration restores strict uses", count() == 2)
    check(
        "display preserves function bytes",
        ida_bytes.get_bytes(target, len(original_function)) == original_function,
    )
    original_key = ida_bytes.get_byte(key)
    ida_bytes.patch_byte(key, original_key ^ 1)
    cfunc.refresh_func_ctext()
    check(
        "sealed profile lease still checks consumed key",
        not any("rax-use(" in line for line in rendered()),
    )
    ida_bytes.patch_byte(key, original_key)
    cfunc.refresh_func_ctext()
    check(
        "sealed profile lease restores only exact bytes",
        sum("rax-use(" in line for line in rendered()) == 2,
    )
    original_name = ida_name.get_name(target)
    assert ida_name.set_name(target, "_temporal_strings_profile_edited"), "rename control failed"
    cfunc.refresh_func_ctext()
    check(
        "later profile edit invalidates sealed display",
        not any("rax-use(" in line for line in rendered()),
    )
    assert ida_name.set_name(target, original_name), "rename restoration failed"
    # Decompilation may refine the entry prototype. The print lease permits
    # that refinement; the IDC API still requires exact original-profile
    # evidence, so obtain that evidence before isolating a data-only patch.
    explore()
    check("strict use API fresh before data patch", count() == 2)
    ida_bytes.patch_byte(key, original_key ^ 1)
    check("consumed key patch invalidates uses", count() == 0)
    cfunc.refresh_func_ctext()
    check(
        "stale use text removed on reprint",
        not any("rax-use(" in line for line in rendered()) and str(cfunc) == ast,
    )
    ida_bytes.patch_byte(key, original_key)
    explore()
    check("restored key revalidates exact evidence", count() == 2)
    cfunc.refresh_func_ctext()
    check(
        "restored exact evidence displays again",
        sum("rax-use(" in line for line in rendered()) == 2,
    )
    original_code = ida_bytes.get_byte(target)
    ida_bytes.patch_byte(target, original_code ^ 1)
    check("function patch invalidates uses", count() == 0)
    ida_bytes.patch_byte(target, original_code)
except BaseException as error:
    # Exception messages from host APIs can include identifying paths.
    errors.append(type(error).__name__)

(Path(os.environ["IDAUSR"]).parent / "temporal_strings.json").write_text(
    json.dumps({"records": records, "errors": errors}, indent=2) + "\n"
)
line = "[chernobog][temporal-strings] " + (
    "FAIL " + "; ".join(errors) if errors else "PASS checks=%d" % len(records)
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
