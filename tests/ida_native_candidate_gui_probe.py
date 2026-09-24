"""Exercise the conditional packed-entry graph in an actual IDA Qt form."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_pro
import ida_segment
import idautils

sys.dont_write_bytecode = True
ROOT = int(os.environ["CHERNOBOG_CANDIDATE_ROOT"], 0)
VIEW = Path(os.environ["CHERNOBOG_VIEW_MODULE"])
DESTINATION = Path(os.environ["IDAUSR"]).parent


def inventory():
    digest = hashlib.sha256()
    total = heads = references = 0

    def add(value):
        digest.update(json.dumps(value, separators=(",", ":")).encode())
        digest.update(b"\n")

    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        size = int(segment.end_ea - segment.start_ea)
        total += size
        assert total <= 64 * 1024 * 1024
        add((int(segment.start_ea), int(segment.end_ea), int(segment.bitness), int(segment.perm)))
        for part in ida_bytes.get_bytes_and_mask(segment.start_ea, size) or (b"unloaded",):
            digest.update(part)
        for ea in idautils.Heads(segment.start_ea, segment.end_ea):
            heads += 1
            assert heads <= 1048576
            function = ida_funcs.get_func(ea)
            add(
                (
                    ea,
                    int(ida_bytes.get_full_flags(ea)),
                    int(ida_bytes.get_item_end(ea)),
                    None if function is None else int(function.start_ea),
                    ida_bytes.get_cmt(ea, True),
                    ida_bytes.get_cmt(ea, False),
                )
            )
            refs = sorted(
                (int(ref.frm), int(ref.to), int(ref.type), bool(ref.iscode), bool(ref.user))
                for ref in idautils.XrefsFrom(ea)
            )
            references += len(refs)
            assert references <= 2097152
            add(refs)
    functions = list(idautils.Functions())
    assert len(functions) <= 4096
    for ea in functions:
        function = ida_funcs.get_func(ea)
        add((ea, int(function.flags), list(idautils.Chunks(ea))))
    add(list(idautils.Names()))
    return {"sha256": digest.hexdigest(), "heads": heads, "references": references}


def api(name, ea):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"{name}({ea})")
    return json.loads(value.c_str())


report = {"checks": [], "errors": [], "view_sha256": hashlib.sha256(VIEW.read_bytes()).hexdigest()}
forms = []
companion = None


def check(name, condition):
    passed = bool(condition)
    report["checks"].append({"case": name, "passed": passed})
    if not passed:
        report["errors"].append(name)


try:
    assert ida_kernwin.is_idaq()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    ida_auto.enable_auto(False)
    spec = importlib.util.spec_from_file_location("candidate_gui_view", VIEW)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from PySide6 import QtCore, QtWidgets

    before = inventory()
    snapshot = api("chernobog_native_candidate_region", ROOT)
    ordinary = api("chernobog_native_region_facts", ROOT)
    check(
        "candidate and ordinary APIs retain separate classifications",
        snapshot["available"]
        and snapshot["candidate_decode"]
        and not ordinary["available"]
        and ordinary["reason"] == "not_existing_code_head",
    )
    form = module.NativeRegionForm(ROOT, snapshot, "chernobog_native_candidate_region")
    forms.append(form)
    form.Show(
        "Chernobog candidate bytes " + snapshot["root"], options=ida_kernwin.PluginForm.WOPN_PERSIST
    )
    form.parent.window().resize(1700, 1100)
    QtWidgets.QApplication.processEvents()
    form.fit_graph()
    form.poll()
    QtWidgets.QApplication.processEvents()
    check(
        "Qt displays every conditional node, record and frontier",
        form.current
        and len(form.nodes) == len(snapshot["nodes"]) == 9
        and form.facts.rowCount() == len(snapshot["records"]) == 1
        and form.edges.rowCount() == len(snapshot["edges"]) == 11
        and form.edges.horizontalHeaderItem(3).text() == "Basis"
        and form.edges.item(0, 3).text() == "conditional-byte-decode"
        and "conditional byte graph" in form.status.text()
        and "Conditional byte-decode candidate" in form.scope.text(),
    )
    edges = [item for item in form.scene.items() if isinstance(item, module.FlowEdge)]
    check(
        "candidate edges use conditional dashed styling",
        bool(edges)
        and all(edge.row["truth"] == "conditional-byte-decode" for edge in edges)
        and all(edge.pen().style() == QtCore.Qt.PenStyle.DashLine for edge in edges),
    )
    form.facts.selectRow(0)
    QtWidgets.QApplication.processEvents()
    detail = json.loads(form.detail.toPlainText())
    check(
        "selected branch remains unresolved and explicitly conditional",
        form.selected.get("status") == "unresolved"
        and form.selected.get("truth") == "conditional-byte-decode"
        and detail["candidate_decode"] is True
        and detail["current_conditional_graph"] is True
        and "current_exact_graph" not in detail
        and detail["published"] is False
        and detail["selected"]["outcome"] == "unknown",
    )
    check(
        "visible candidate text excludes personal paths",
        all(
            "/Users/" not in value
            for value in (form.status.text(), form.scope.text(), form.detail.toPlainText())
        ),
    )
    form.api_name = "chernobog_native_region_facts"
    form.poll()
    check(
        "cross-mode polling invalidates candidate navigation",
        not form.current and not form.jump.isEnabled(),
    )
    form.api_name = "chernobog_native_candidate_region"
    form.poll()
    check(
        "exact candidate recomputation restores navigation", form.current and form.jump.isEnabled()
    )
    check(
        "Qt screenshot saved",
        form.parent.grab().save(str(DESTINATION / "candidate_graph.png")),
    )
    form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
    QtWidgets.QApplication.processEvents()
    companion = module.EvidencePlugin()
    initialized = companion.init()
    check(
        "separate candidate action registered",
        initialized == ida_idaapi.PLUGIN_KEEP
        and companion.region_registered
        and companion.candidate_registered,
    )
    dispatched = companion.candidate_action.activate(SimpleNamespace(cur_ea=ROOT))
    QtWidgets.QApplication.processEvents()
    check(
        "registered candidate handler opens a conditional form",
        dispatched
        and len(companion.region_forms) == 1
        and next(iter(companion.region_forms.values())).snapshot == snapshot
        and next(iter(companion.region_forms.values())).current,
    )
    rejected = companion.candidate_action.activate(SimpleNamespace(cur_ea=0x40021B))
    check(
        "candidate handler rejects an existing code head",
        not rejected and len(companion.region_forms) == 1,
    )
    report["inventory_before"] = before
    report["inventory_after"] = inventory()
    check(
        "Qt inspection preserves IDB bytes, items, owners, references and names",
        report["inventory_before"] == report["inventory_after"],
    )
    report["candidate_summary"] = {
        "nodes": len(snapshot["nodes"]),
        "edges": len(snapshot["edges"]),
        "records": len(snapshot["records"]),
        "reason": snapshot["reason"],
    }
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
finally:
    if companion is not None:
        companion.term()
    for form in forms:
        if not form.closed:
            form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
    (DESTINATION / "candidate_gui.json").write_text(json.dumps(report, indent=2) + "\n")
    print("[chernobog][candidate-gui] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
    ida_pro.qexit(2 if report["errors"] else 0)
