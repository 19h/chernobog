"""Show syntax-only VM candidates after an incomplete temporal capture."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

import ida_auto
import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro

sys.dont_write_bytecode = True
ROOT = int(os.environ["CHERNOBOG_STRING_ENTRY"], 0)
VIEW = Path(os.environ["CHERNOBOG_VIEW_MODULE"])
DESTINATION = Path(os.environ["IDAUSR"]).parent
report = {"checks": [], "errors": [], "view_sha256": hashlib.sha256(VIEW.read_bytes()).hexdigest()}
form = None


def check(name, condition):
    passed = bool(condition)
    report["checks"].append({"case": name, "passed": passed})
    if not passed:
        report["errors"].append(name)


def source_inventory(snapshot):
    sites = {
        part.split(":")[0]
        for row in snapshot["native_vm_candidates"]["records"]
        for part in row["instruction_spans"].split(";")
        if part
    }
    return {
        site: (
            (ida_bytes.get_bytes(int(site, 0), 15) or b"").hex(),
            int(ida_bytes.get_full_flags(int(site, 0))),
        )
        for site in sites
    }


try:
    assert ida_kernwin.is_idaq()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    ida_auto.enable_auto(False)
    spec = importlib.util.spec_from_file_location("temporal_vm_abstain_view", VIEW)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from PySide6 import QtWidgets

    request = json.dumps({"args": [], "objects": []})
    bindings = []
    for name in ("_malloc", "_memset", "_free"):
        address = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        assert address != ida_idaapi.BADADDR
        bindings.append({"address": hex(address), "name": name})
    models = json.dumps(bindings)
    snapshot = module.temporal_vm_api(ROOT, 0, request, models)
    observation = snapshot["native_observations"]
    check(
        "budget-limited capture explicitly abstains from transition checks",
        snapshot["available"]
        and snapshot["ran"]
        and not snapshot["native_temporal_prefix_complete"]
        and not snapshot["native_state_capture_complete"]
        and not observation["available"]
        and observation["candidate_visits"] == 0
        and observation["transition_attempts"] == 0
        and observation["queries"] == 0
        and len(snapshot["native_vm_candidates"]["records"]) == 3,
    )
    ida_auto.enable_auto(True)
    ida_auto.auto_wait()
    ida_auto.enable_auto(False)
    before = source_inventory(snapshot)
    form = module.TemporalVmForm(ROOT, 0, request, models, snapshot)
    form.Show("Chernobog temporal VM abstention", options=ida_kernwin.PluginForm.WOPN_PERSIST)
    form.parent.window().resize(1700, 1100)
    QtWidgets.QApplication.processEvents()
    form.poll()
    check(
        "Qt separates three syntax candidates from zero visits",
        form.syntax.rowCount() == 3
        and form.visits.rowCount() == 0
        and len(form.nodes) >= 3
        and 0 < len(form.source_rows) < len(snapshot["heads"])
        and "local checks 0" in form.status.text()
        and "temporal prefix complete False" in form.status.text(),
    )
    form.syntax.selectRow(0)
    QtWidgets.QApplication.processEvents()
    detail = json.loads(form.detail.toPlainText())
    check(
        "selected scaffold is explicitly syntax-only",
        detail["candidate_scope"] == "syntax-only; no transition check"
        and detail["local_check"] == "not performed"
        and detail["solver_queries"] == 0
        and detail["observation_reason"]
        == "complete native instruction-entry or temporal event prefix required"
        and detail["selected"]["site"] == snapshot["native_vm_candidates"]["records"][0]["site"],
    )
    form.fit_graph()
    QtWidgets.QApplication.processEvents()
    check(
        "Qt abstention screenshot saved",
        form.parent.grab().save(str(DESTINATION / "temporal_vm_abstain.png")),
    )
    check("candidate source bytes and flags unchanged", before == source_inventory(snapshot))
    report["summary"] = {"syntax_candidates": 3, "candidate_visits": 0, "solver_queries": 0}
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
finally:
    if form is not None and not form.closed:
        form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
    (DESTINATION / "temporal_vm_abstain.json").write_text(json.dumps(report, indent=2) + "\n")
    print("[chernobog][temporal-vm-abstain] " + ("FAIL" if report["errors"] else "PASS"))
    ida_pro.qexit(2 if report["errors"] else 0)
