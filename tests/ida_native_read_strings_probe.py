"""Exercise executed byte-stream publication, exact ctree display and freshness."""

import json
import importlib.util
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
    interleaved = os.environ.get("CHERNOBOG_INTERLEAVED_READS")
    target = ida_name.get_name_ea(
        ida_idaapi.BADADDR, "_native_interleaved_strings" if interleaved else "_native_read_strings"
    )
    key = ida_name.get_name_ea(
        ida_idaapi.BADADDR, "_native_interleaved_key" if interleaved else "_native_read_key"
    )
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
            and values["allocation_lifetimes"]
            == (1 if interleaved == "shared" else 2) * values["runs"]
            and values["temporal_capture_truncated_runs"] == 0,
            result=code,
            summary=values,
        )

    explore()
    view = json.loads(evaluate(f"chernobog_evidence_view({target})"))
    stream_rows = view.get("read_streams", [])
    check(
        "stream timeline provenance",
        len(stream_rows) == 8
        and all(
            row["truth"] == "observation"
            and row["read_count"] == "8"
            and row["first_sequence"] != row["last_sequence"]
            and row["fragments_omitted"] == "0"
            for row in stream_rows
        ),
        rows=stream_rows,
    )
    module_path = os.environ.get("CHERNOBOG_VIEW_MODULE")
    if module_path:
        spec = importlib.util.spec_from_file_location("native_read_view_under_test", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        row = stream_rows[0]
        interval = (int(row["first_sequence"], 0), int(row["last_sequence"], 0) + 1)
        identity = (row["run"], row["seed"])
        selected = module.matching_events(view, run=identity, interval=interval)
        check(
            "stream interval filter",
            selected
            and all(
                (item["run"], item["seed"]) == identity
                and interval[0] <= int(item["sequence"], 0) <= interval[1]
                for item in selected
            )
            and {item["kind"] for item in selected} >= {"use", "memory", "read-stream"},
        )
        if ida_kernwin.is_idaq():
            from PySide6 import QtWidgets

            form = module.EvidenceForm(target, view)
            form.Show("Chernobog native read streams", options=ida_kernwin.PluginForm.WOPN_PERSIST)
            QtWidgets.QApplication.processEvents()
            table = form.tables["read_streams"]
            check("Qt stream table retains both uses", table.topLevelItemCount() == 8)
            form.tabs.setCurrentWidget(table)
            table.setCurrentItem(table.topLevelItem(0))
            QtWidgets.QApplication.processEvents()
            check(
                "Qt stream selection links interval",
                form.interval == interval
                and form.run == identity
                and form.tables["events"].topLevelItemCount() == len(selected)
                and "executed-read-stream" in form.detail.toPlainText(),
            )
            original = ida_bytes.get_byte(key)
            ida_bytes.patch_byte(key, original ^ 1)
            form.poll()
            check(
                "Qt stale stream disables navigation",
                not form.current and not form.jump.isEnabled(),
            )
            ida_bytes.patch_byte(key, original)
            form.poll()
            check("Qt exact stream restoration", form.current)
            form.parent.resize(1200, 780)
            form.parent.window().resize(1400, 900)
            QtWidgets.QApplication.processEvents()
            form.parent.grab().save(
                str(Path(os.environ["IDAUSR"]).parent / "native_read_streams.png")
            )
            form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
            QtWidgets.QApplication.processEvents()
            check("Qt stream close stops polling", form.closed and not form.timer.isActive())
    check("two temporal candidates", count() == 2, count=count())
    values = []
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
                "read_count",
                "first_sequence",
                "last_sequence",
                "observed_bytes",
                "object_site",
                "object_size",
                "observations",
                "eligible_runs",
            ]
        }
        values.append(candidate["value"])
        check(
            "native stream provenance",
            candidate["ok"] == 1
            and candidate["producer"] == "executed-read-stream"
            and candidate["argument"] in (-1, 2**64 - 1)
            and candidate["model_kind"] == 0
            and candidate["read_count"] == 8
            and candidate["observed_bytes"] == 8
            and candidate["last_sequence"] > candidate["first_sequence"]
            and candidate["object_size"] == (32 if interleaved else 16)
            and candidate["observations"] == candidate["eligible_runs"],
            candidate=candidate,
        )
    check("use-specific plaintext", values == ["secret!", "second!"], values=values)
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
            '"secret!"' in line and "executed-read-stream,reads=8,use=1,runs=" in line
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
    assert ida_name.set_name(target, "_native_read_strings_profile_edited"), "rename control failed"
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

(Path(os.environ["IDAUSR"]).parent / "native_read_strings.json").write_text(
    json.dumps({"records": records, "errors": errors}, indent=2) + "\n"
)
line = "[chernobog][native-read-strings] " + (
    "FAIL " + "; ".join(errors) if errors else "PASS checks=%d" % len(records)
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
