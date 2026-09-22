"""Actual Qt inspection of guarded summaries and captured native VSP roles.

Native rows are presented through an explicitly labeled UI-test envelope. That
envelope never creates or claims an ordinary execution-evidence publication.
"""

import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import traceback

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro
import ida_ua
import idautils

sys.dont_write_bytecode = True
checks, errors, screenshots = [], [], []
captures = {}
config = json.loads(os.environ["CHERNOBOG_VM_PUSH_CONFIG"])
destination = Path(os.environ["IDAUSR"]).parent


def check(name, condition):
    checks.append({"case": name, "passed": bool(condition)})
    if not condition:
        errors.append(name)


def evaluate(expression):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    return value.c_str() if value.vtype == ida_expr.VT_STR else value.num


def api(name, ea):
    return json.loads(evaluate(f"{name}({ea})"))


def symbol(name):
    for prefix in ("_vm_push_", "vm_push_"):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, prefix + name)
        if ea != ida_idaapi.BADADDR:
            return int(ea)
    raise AssertionError("missing GUI fixture symbol")


def first_input():
    """Independently encode the zero-key, zero-payload, fast-table fixture case."""
    assert config == {"mode": 64, "bits": 8, "backward": False, "relative": False}
    decoded = ((7 ^ 0x5A) - 9) & 255
    inverse = ((9 ^ 0x5A) - 7) & 255
    dispatch = ((inverse >> 3) | (inverse << 5)) & 255
    code = bytearray(16)
    code[1] = dispatch ^ decoded
    initial = bytes(code) + struct.pack("<7Q", 0, 0, 0, 0, 0, 0, 0)
    return {
        "args": ["0x0", "0x0"],
        "objects": [{"argument": 0, "offset": 0, "bytes": initial.hex()}],
    }


def open_form(module, target, snapshot, title):
    from PySide6 import QtWidgets

    form = module.EvidenceForm(target, snapshot)
    form.Show(title, options=ida_kernwin.PluginForm.WOPN_PERSIST)
    form.parent.window().show()
    form.parent.window().activateWindow()
    form.parent.window().resize(1700, 1100)
    form.detail.setMinimumHeight(600)
    form.detail.parentWidget().setSizes([220, 720])
    QtWidgets.QApplication.processEvents()
    form.fit_graph()
    QtWidgets.QApplication.processEvents()
    return form


def save(form, name):
    from PySide6 import QtWidgets

    QtWidgets.QApplication.processEvents()
    visible = form.status.text() + form.detail.toPlainText()
    assert "/Users/" not in visible
    check(name + " screenshot saved", form.parent.grab().save(str(destination / name)))
    screenshots.append(name)


def close(form):
    from PySide6 import QtWidgets

    form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
    QtWidgets.QApplication.processEvents()
    check("form closes its polling timer", form.closed and not form.timer.isActive())


try:
    ida_auto.auto_wait()
    assert ida_kernwin.is_idaq()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    symbols = {
        name: symbol(name) for name in ("run", "handler", "store", "stack_check", "capture", "end")
    }
    start, end = symbols["run"], symbols["end"]
    assert start < end and end - start < 4096
    # Ownership is explicit in this source fixture. Assert and classify its two
    # nonexecuted padding gaps as data, avoiding fabricated fallthrough entries.
    for ea in list(idautils.Functions(start, end)):
        ida_funcs.del_func(ea)
    gaps = {symbols["stack_check"] - 3, symbols["capture"] - 3}
    assert len(gaps) == 2
    for gap in gaps:
        assert start <= gap < gap + 3 <= end
        assert ida_bytes.get_bytes(gap, 3) == b"\xcc" * 3
        assert ida_bytes.del_items(gap, ida_bytes.DELIT_SIMPLE, 3)
        assert ida_bytes.create_data(gap, ida_bytes.FF_BYTE, 3, ida_idaapi.BADADDR)
    ea = start
    while ea < end:
        if ea in gaps:
            ea += 3
            continue
        size = ida_ua.create_insn(ea)
        assert size > 0
        ea += size
    assert ea == end and ida_funcs.add_func(start, end)
    ida_auto.auto_wait()
    evaluate("chernobog_native_analysis()")
    ida_auto.auto_wait()
    ida_auto.enable_auto(False)
    original = ida_bytes.get_bytes(start, end - start)
    publication = api("chernobog_evidence_state", start)
    module_path = os.environ["CHERNOBOG_VIEW_MODULE"]
    spec = importlib.util.spec_from_file_location("guarded_push_ui_test", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    snapshot = module.load_inspection(start)
    captures["inspection"] = snapshot
    candidates = [
        row
        for row in snapshot["vm"]["records"]
        if int(row["site"], 0) == symbols["handler"] and row.get("payload_bits") == "8"
    ]
    check("one full guarded GUI candidate", len(candidates) == 1)
    assert len(candidates) == 1
    candidate = candidates[0]
    binding = next(
        row
        for row in snapshot["vm"]["summary_bindings"]
        if row["vm_candidate"] == candidate["vm_candidate"]
    )
    summary = next(
        row for row in snapshot["vm"]["summaries"] if row["summary_id"] == binding["summary_id"]
    )
    check(
        "summary applicability is explicit and complete",
        summary["domain_complete"] == "true"
        and summary["domain"] != "true"
        and "input_virtual_stack" in summary["domain"]
        and "input_sp" in summary["domain"],
    )
    check(
        "summary is limited to fast stack check",
        summary["scope"]
        == "conditional observed fast stack-check path; relocation arm not summarized"
        and candidate["stack_check"] == "true",
    )
    form = open_form(module, start, snapshot, "Guarded push conditional summary")
    form.tabs.setCurrentWidget(form.tables["vm"])
    form.select_record(candidate)
    text = form.detail.toPlainText()
    check(
        "actual Qt detail retains domain and role metadata",
        '"domain_complete": "true"' in text
        and "input_virtual_stack" in text
        and "input_sp" in text
        and '"virtual_stack_register": "5"' in text
        and '"payload_value_register": "2"' in text
        and '"stack_check_register": "1"' in text,
    )
    check(
        "actual Qt detail retains scope limitation",
        "conditional observed fast stack-check path; relocation arm not summarized" in text,
    )
    check(
        "static candidate navigation is current without execution proof",
        form.jump.isEnabled() and not form.current and not form.edges,
    )
    before_queries = api("chernobog_solver_evidence", start)
    form.poll()
    check(
        "GUI refresh does not rerun proofs",
        before_queries == api("chernobog_solver_evidence", start),
    )
    from PySide6 import QtWidgets

    domain = form.detail.document().find('"domain":')
    complete = form.detail.document().find('"domain_complete": "true"')
    assert not domain.isNull() and not complete.isNull()
    form.detail.setTextCursor(complete)
    form.detail.centerCursor()
    QtWidgets.QApplication.processEvents()
    check(
        "domain and completeness marker are visible in Qt viewport",
        form.detail.viewport().rect().contains(form.detail.cursorRect(domain))
        and form.detail.viewport().rect().contains(form.detail.cursorRect(complete)),
    )
    save(form, "vm_push_summary_gui.png")
    scope = form.detail.document().find(
        "conditional observed fast stack-check path; relocation arm not summarized"
    )
    assert not scope.isNull()
    form.detail.setTextCursor(scope)
    form.detail.centerCursor()
    QtWidgets.QApplication.processEvents()
    check(
        "fast-path scope is visible in Qt viewport",
        form.detail.viewport().rect().contains(form.detail.cursorRect(scope)),
    )
    save(form, "vm_push_scope_gui.png")
    close(form)

    request = json.dumps(first_input(), separators=(",", ":"))
    trace = json.loads(evaluate(f"chernobog_vm_trace_check({start}, 37, {json.dumps(request)})"))
    captures["native_trace"] = trace
    check(
        "actual native capture completed",
        trace.get("available")
        and trace.get("ran")
        and trace.get("reached_sentinel")
        and not trace.get("function_evidence_published"),
    )
    native_rows = trace["native_observations"]["records"]
    full = next(
        row
        for row in native_rows
        if int(row["site"], 0) == symbols["handler"] and row.get("payload_bits") == "8"
    )
    unknown = next(row for row in native_rows if row.get("virtual_stack_register") == "-1")
    check(
        "actual full transition corroborated",
        full["semantic_validation"] == "corroborated for captured transition"
        and full["transition_queries"] == "2"
        and full["stack_check"] == "true",
    )
    check(
        "actual virtual-stack delta retained",
        int(full["entry_virtual_stack"], 0) - int(full["output_virtual_stack"], 0) == 2,
    )
    presentation = module.load_inspection(start)
    presented = [
        dict(
            row,
            revision="0x0",
            ui_projection_scope="Actual native-region capture; presentation UI test only; no ordinary publication",
        )
        for row in (full, unknown)
    ]
    presentation["vm_states"] = dict(
        presentation["vm_states"],
        revision="0x0",
        states=presented,
        states_available=True,
        states_reason="Projection UI test: actual native-region capture, ordinary publication absent",
    )
    form = open_form(module, start, presentation, "Native capture presentation test")
    form.timer.stop()
    form.tabs.setCurrentWidget(form.tables["vm_states"])
    form.tables["vm_states"].setCurrentItem(form.tables["vm_states"].topLevelItem(0))
    label = "PROJECTION UI TEST: actual native capture; no ordinary publication\n"
    form.status.setText(label + form.status.text())
    detail = form.detail.toPlainText()
    check(
        "actual Qt VSP hypothesis text uses captured values",
        "Virtual stack register hypothesis GPR5: entry "
        + full["entry_virtual_stack"]
        + ", output "
        + full["output_virtual_stack"]
        in detail
        and "VM context and memory epoch: unknown" in detail,
    )
    check(
        "VSP presentation retains partial identity",
        '"logical_state_complete": "false"' in detail
        and '"merge": "not admitted"' in detail
        and "presentation UI test only; no ordinary publication" in detail,
    )
    check(
        "native presentation does not borrow ordinary freshness",
        not form.current and not form.vm_states_current and not form.jump.isEnabled(),
    )
    save(form, "vm_push_vsp_gui.png")
    form.tables["vm_states"].setCurrentItem(form.tables["vm_states"].topLevelItem(1))
    check(
        "actual suffix preserves original unknown-role text",
        "Virtual stack, VM context and memory epoch: unknown" in form.detail.toPlainText()
        and "Virtual stack register hypothesis" not in form.detail.toPlainText(),
    )
    save(form, "vm_push_unknown_gui.png")
    close(form)
    check(
        "UI and native capture leave ordinary publication unchanged",
        api("chernobog_evidence_state", start) == publication,
    )
    check(
        "fixture instruction bytes unchanged", ida_bytes.get_bytes(start, end - start) == original
    )
except Exception as error:
    errors.append(type(error).__name__)
    errors.extend(
        frame.name + ":" + str(frame.lineno) for frame in traceback.extract_tb(error.__traceback__)
    )

report = {
    "schema": 1,
    "passed": not errors,
    "scope": "Actual Qt summary inspection and presentation-only adaptation of real native capture rows; no ordinary publication or full VM identity claim",
    "config": config,
    "checks": checks,
    "errors": errors,
    "screenshots": screenshots,
    "captures": captures,
}
(destination / "vm_push_handlers_gui.json").write_text(json.dumps(report, indent=2) + "\n")
print("[chernobog][vm-push-handlers-gui] " + ("FAIL" if errors else "PASS"), flush=True)
ida_pro.qexit(2 if errors else 0)
