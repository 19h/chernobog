"""Render the unchanged ordinary ownerless graph with the shared Qt form."""

import importlib.util
import json
import os
from pathlib import Path
import sys

import ida_auto
import ida_bytes
import ida_expr
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_pro

sys.dont_write_bytecode = True
ROOT = int(os.environ["CHERNOBOG_PROTECTED_REGION_ROOT"], 0)
DESTINATION = Path(os.environ["IDAUSR"]).parent
report = {"checks": [], "errors": []}
form = None


def check(name, condition):
    passed = bool(condition)
    report["checks"].append({"case": name, "passed": passed})
    if not passed:
        report["errors"].append(name)


try:
    assert ida_kernwin.is_idaq()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    analysis = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(analysis, ida_idaapi.BADADDR, "chernobog_native_analysis()")
    ida_auto.auto_wait()
    ida_auto.enable_auto(False)
    source = Path(os.environ["CHERNOBOG_VIEW_MODULE"])
    spec = importlib.util.spec_from_file_location("ordinary_region_gui_view", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from PySide6 import QtCore, QtWidgets

    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(
        value, ida_idaapi.BADADDR, f"chernobog_native_region_facts({ROOT})"
    )
    snapshot = json.loads(value.c_str())
    flags = int(ida_bytes.get_full_flags(ROOT))
    check(
        "existing-code protected region retains ordinary result",
        snapshot["available"]
        and snapshot["converged"]
        and not snapshot.get("candidate_decode", False)
        and len(snapshot["nodes"]) == 75
        and len(snapshot["edges"]) == 77
        and len(snapshot["records"]) == 3,
    )
    form = module.NativeRegionForm(ROOT, snapshot)
    form.Show("Ordinary protected region", options=ida_kernwin.PluginForm.WOPN_PERSIST)
    form.parent.window().resize(1700, 1100)
    QtWidgets.QApplication.processEvents()
    form.fit_graph()
    form.poll()
    QtWidgets.QApplication.processEvents()
    detail = json.loads(form.detail.toPlainText())
    check(
        "shared Qt view preserves ordinary graph interpretation",
        form.current
        and len(form.nodes) == 75
        and form.facts.rowCount() == 3
        and form.edges.rowCount() == 77
        and form.edges.horizontalHeaderItem(3).text() == "Basis"
        and form.edges.item(0, 3).text() == "encoding"
        and "Current exact graph" in form.status.text()
        and "selected ownerless root" in form.scope.text()
        and detail["current_exact_graph"] is True
        and detail["candidate_decode"] is False
        and "current_conditional_graph" not in detail,
    )
    edges = [item for item in form.scene.items() if isinstance(item, module.FlowEdge)]
    check(
        "ordinary edges retain encoding basis",
        bool(edges)
        and all(edge.row["truth"] == "encoding" for edge in edges)
        and all(edge.pen().style() == QtCore.Qt.PenStyle.DashLine for edge in edges),
    )
    check("ordinary GUI query retains root IDA flags", int(ida_bytes.get_full_flags(ROOT)) == flags)
    check(
        "ordinary GUI screenshot saved",
        form.parent.grab().save(str(DESTINATION / "ordinary_graph.png")),
    )
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
finally:
    if form is not None and not form.closed:
        form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
    (DESTINATION / "ordinary_gui.json").write_text(json.dumps(report, indent=2) + "\n")
    print("[chernobog][ordinary-gui] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
    ida_pro.qexit(2 if report["errors"] else 0)
