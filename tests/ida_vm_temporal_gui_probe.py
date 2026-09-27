"""Exercise checked ownerless VM visits in an actual IDA Qt evidence form."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro
import idautils

sys.dont_write_bytecode = True
ROOT = int(os.environ["CHERNOBOG_STRING_ENTRY"], 0)
VIEW = Path(os.environ["CHERNOBOG_VIEW_MODULE"])
DESTINATION = Path(os.environ["IDAUSR"]).parent
report = {"checks": [], "errors": [], "view_sha256": hashlib.sha256(VIEW.read_bytes()).hexdigest()}
forms = []
companion = None


def check(name, condition):
    passed = bool(condition)
    report["checks"].append({"case": name, "passed": passed})
    if not passed:
        report["errors"].append(name)


def head_inventory(snapshot):
    return [
        {
            "site": row["site"],
            "bytes": (ida_bytes.get_bytes(int(row["site"], 0), int(row["size"])) or b"").hex(),
            "flags": int(ida_bytes.get_full_flags(int(row["site"], 0))),
            "owner": (
                None
                if ida_funcs.get_func(int(row["site"], 0)) is None
                else int(ida_funcs.get_func(int(row["site"], 0)).start_ea)
            ),
            "xrefs": [
                (int(ref.frm), int(ref.to), int(ref.type), bool(ref.user))
                for ref in idautils.XrefsFrom(int(row["site"], 0))
            ],
        }
        for row in snapshot["heads"]
    ]


try:
    assert ida_kernwin.is_idaq()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    ida_auto.enable_auto(False)
    spec = importlib.util.spec_from_file_location("temporal_vm_gui_view", VIEW)
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
    ida_auto.enable_auto(True)
    ida_auto.auto_wait()
    ida_auto.enable_auto(False)
    suggested = json.loads(module.suggested_temporal_bindings())
    suggested_trace = module.temporal_vm_api(ROOT, 0, request, json.dumps(suggested))
    check(
        "default exact-name bindings produce a checked capture",
        all(binding in suggested for binding in bindings)
        and suggested_trace["available"]
        and suggested_trace["native_observations"]["candidate_visits"] == 4
        and suggested_trace["native_observations"]["queries"] == 8,
    )
    before = head_inventory(snapshot)
    check(
        "explicit temporal capture retains four checked ownerless visits",
        snapshot["available"]
        and snapshot["ran"]
        and not snapshot["function_evidence_published"]
        and not snapshot["vm_identity_proved"]
        and observation["available"]
        and observation["candidate_visits"] == 4
        and observation["transition_attempts"] == 4
        and observation["queries"] == 8,
    )
    form = module.TemporalVmForm(ROOT, 0, request, models, snapshot)
    forms.append(form)
    form.Show("Chernobog temporal VM probe", options=ida_kernwin.PluginForm.WOPN_PERSIST)
    form.parent.window().resize(1700, 1100)
    QtWidgets.QApplication.processEvents()
    form.poll()
    check(
        "Qt links visits and actual transfer graph",
        form.syntax.rowCount() == 4
        and form.visits.rowCount() == 4
        and bool(form.nodes)
        and form.transfers.rowCount() > 0
        and 0 < len(form.source_rows) < len(snapshot["heads"])
        and all(
            edge.row["truth"] == "witness"
            for edge in form.scene.items()
            if isinstance(edge, module.FlowEdge)
        )
        and "Captured seed" in form.status.text()
        and "candidate source bytes matching" in form.status.text()
        and "Historical fixed-seed" in form.scope.text(),
    )
    form.transfers.selectRow(0)
    QtWidgets.QApplication.processEvents()
    transfer_detail = json.loads(form.detail.toPlainText())
    check(
        "observed transfer selection does not inherit a candidate check",
        transfer_detail["selected"]["truth"] == "witness"
        and transfer_detail["candidate_scope"] == "no candidate selected"
        and transfer_detail["local_check"] == "not selected",
    )
    index = next(
        index for index, row in enumerate(observation["records"]) if row["site"] == "0x1000d64db"
    )
    syntax_index = next(
        index
        for index, row in enumerate(snapshot["native_vm_candidates"]["records"])
        if row["site"] == "0x1000d64db"
    )
    form.syntax.selectRow(syntax_index)
    QtWidgets.QApplication.processEvents()
    syntax_detail = json.loads(form.detail.toPlainText())
    check(
        "syntax candidate remains separate from a checked visit",
        syntax_detail["candidate_scope"] == "syntax-only; no transition check"
        and syntax_detail["local_check"] == "not performed",
    )
    form.visits.selectRow(index)
    QtWidgets.QApplication.processEvents()
    detail = json.loads(form.detail.toPlainText())
    check(
        "selected local proof links five ordered accesses and exact target",
        detail["selected"]["semantic_validation"] == "corroborated for captured transition"
        and detail["selected"]["target"] == "0x100007031"
        and detail["selected"]["transition_queries"] == "2"
        and detail["local_check"] == "corroborated for captured transition"
        and detail["candidate_scope"] == "captured local visit"
        and detail["observed_target"] == "0x100007031"
        and form.memory.rowCount() == 5
        and detail["visible_memory"] == 5
        and detail["source_bytes_match"]
        and form.jump.isEnabled(),
    )
    original_get_bytes = module.ida_bytes.get_bytes

    def stale_bytes(site, size):
        if site == 0x1000D64DB:
            return b"\x90" * size
        return original_get_bytes(site, size)

    module.ida_bytes.get_bytes = stale_bytes
    form.poll()
    check("changed source bytes disable navigation", not form.jump.isEnabled())
    module.ida_bytes.get_bytes = original_get_bytes
    form.poll()
    check("exact restored source bytes restore navigation", form.jump.isEnabled())
    form.fit_graph()
    QtWidgets.QApplication.processEvents()
    report["graph_geometry"] = {
        "scene": str(form.scene.itemsBoundingRect()),
        "viewport": str(form.graph.viewport().rect()),
        "scale": form.graph.transform().m11(),
    }
    check("Qt screenshot saved", form.parent.grab().save(str(DESTINATION / "temporal_vm_gui.png")))
    form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
    QtWidgets.QApplication.processEvents()
    after_form = head_inventory(snapshot)
    companion = module.EvidencePlugin()
    check(
        "temporal action registered",
        companion.init() == ida_idaapi.PLUGIN_KEEP and companion.temporal_registered,
    )
    check(
        "plugin opens explicit captured temporal form",
        companion.open_temporal_vm(ROOT, 0, request, models) and len(companion.temporal_forms) == 1,
    )
    existing = next(iter(companion.temporal_forms.values()))
    prior_capture = existing.snapshot["capture"]
    check(
        "reopening action replaces the prior captured result",
        companion.open_temporal_vm(ROOT, 0, request, models)
        and len(companion.temporal_forms) == 1
        and existing.snapshot["capture"] != prior_capture
        and existing.visits.rowCount() == 4,
    )
    QtWidgets.QApplication.processEvents()
    after = head_inventory(snapshot)
    report["inventory_unchanged"] = before == after
    report["inventory_after_form_unchanged"] = before == after_form
    report["inventory_second_capture_unchanged"] = after_form == after
    support = {
        span.split(":")[0]
        for row in observation["records"]
        for span in row["instruction_spans"].split(";")
        if span
    }
    report["candidate_support_unchanged"] = all(
        old == new for old, new in zip(before, after) if old["site"] in support
    )
    report["inventory_differences"] = [
        {"before": old, "after": new} for old, new in zip(before, after) if old != new
    ][:8]
    check("planned source bytes, flags, owners and xrefs unchanged", report["inventory_unchanged"])
    report["summary"] = {
        "heads": len(snapshot["heads"]),
        "visits": observation["candidate_visits"],
        "queries": observation["queries"],
        "memory_rows": 5,
    }
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
finally:
    if companion is not None:
        companion.term()
    for form in forms:
        if not form.closed:
            form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
    (DESTINATION / "temporal_vm_gui.json").write_text(json.dumps(report, indent=2) + "\n")
    print("[chernobog][temporal-vm-gui] " + ("FAIL" if report["errors"] else "PASS"))
    ida_pro.qexit(2 if report["errors"] else 0)
