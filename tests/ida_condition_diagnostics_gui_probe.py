"""Exercise the owned condition-site tab in an actual IDA Qt form."""

import importlib.util
import json
import os
from pathlib import Path
import sys

import ida_auto
import ida_kernwin
import ida_loader
import ida_pro

sys.dont_write_bytecode = True
root = int(os.environ["CHERNOBOG_CONDITION_ROOT"], 0)
expected_sites = set(json.loads(os.environ["CHERNOBOG_CONDITION_SITES"]))
report = {"passed": False, "errors": [], "checks": []}
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
    spec = importlib.util.spec_from_file_location(
        "condition_diagnostics_gui", os.environ["CHERNOBOG_VIEW_MODULE"]
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from PySide6 import QtWidgets

    snapshot = module.load_inspection(root)
    form = module.EvidenceForm(root, snapshot)
    form.Show("Chernobog condition sites " + hex(root), options=ida_kernwin.PluginForm.WOPN_PERSIST)
    QtWidgets.QApplication.processEvents()
    form.poll()
    table = form.tables["conditions"]
    sites = {
        table.topLevelItem(index).data(0, module.QtCore.Qt.ItemDataRole.UserRole)["site"]
        for index in range(table.topLevelItemCount())
    }
    check(
        "protected sites appear in the condition tab",
        snapshot["conditions"]["available"] and expected_sites <= sites,
    )
    check(
        "condition tab retains source and model labels",
        [table.headerItem().text(index) for index in range(4)]
        == ["Use", "Model decision", "Source bytes", "Site"]
        and all(
            table.topLevelItem(index).text(2) == "match; reload decision"
            for index in range(table.topLevelItemCount())
        ),
    )
    selected = next(
        table.topLevelItem(index)
        for index in range(table.topLevelItemCount())
        if table.topLevelItem(index).text(3) in expected_sites
    )
    table.setCurrentItem(selected)
    QtWidgets.QApplication.processEvents()
    check(
        "selection navigates to bounded diagnostic detail",
        form.jump.isEnabled()
        and '"decision_current": "recompute with Reload"' in form.detail.toPlainText()
        and '"status": "unresolved"' in form.detail.toPlainText(),
    )
    report["condition_sites"] = len(sites)
    report["selected"] = selected.text(3)
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
finally:
    if form is not None:
        form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
    (Path(os.environ["IDAUSR"]).parent / "condition_diagnostics_gui.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print("[chernobog][condition-diagnostics-gui] " + ("PASS" if report["passed"] else "FAIL"))
    ida_pro.qexit(0 if report["passed"] else 1)
