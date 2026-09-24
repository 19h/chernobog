"""Exercise the protected VMP shadow call-use in the actual IDA Qt companion."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_pro
import ida_segment
import idautils

sys.dont_write_bytecode = True
ROOT = 0x100001440
VIEW = Path(os.environ["CHERNOBOG_VIEW_MODULE"])
WINDOW = Path(os.environ["CHERNOBOG_VMP_HELLO_WINDOW"])
DESTINATION = Path(os.environ["IDAUSR"]).parent
REQUEST = json.dumps(
    {
        "source": "0x10000144d",
        "target": "0x100001456",
        "register": "rdi",
        "max_bytes": 32,
    },
    sort_keys=True,
)


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


def selected_inventory():
    rows = []
    for ea in range(ROOT, ROOT + 40):
        flags = ida_bytes.get_full_flags(ea)
        owner = ida_funcs.get_func(ea)
        rows.append(
            (
                ea,
                int(flags),
                bool(ida_bytes.is_loaded(ea)),
                None if owner is None else int(owner.start_ea),
                tuple(
                    sorted(
                        (int(ref.frm), int(ref.type), bool(ref.iscode))
                        for ref in idautils.XrefsTo(ea)
                    )
                ),
            )
        )
    return hashlib.sha256(json.dumps(rows).encode()).hexdigest()


report = {"checks": [], "errors": [], "view_sha256": hashlib.sha256(VIEW.read_bytes()).hexdigest()}
forms = []
companion = None


def check(label, passed):
    report["checks"].append({"case": label, "passed": bool(passed)})
    if not passed:
        report["errors"].append(label)


try:
    assert ida_kernwin.is_idaq()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    ida_auto.enable_auto(False)
    spec = importlib.util.spec_from_file_location("vmp_shadow_use_gui_view", VIEW)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from PySide6 import QtCore, QtWidgets

    before = inventory()
    selected_before = selected_inventory()
    window = WINDOW.read_bytes()
    assert len(window) == 40 and window[28:] == b"Hello World\0"
    local_shadow = DESTINATION / "shadow-window.bin"
    local_shadow.write_bytes(window)
    snapshot = module.shadow_use_api(ROOT, 0, local_shadow, REQUEST)
    report["inventory_after_api"] = inventory()
    for _ in range(4):
        QtWidgets.QApplication.processEvents()
    report["inventory_after_idle_gui_pump"] = inventory()
    check(
        "explicit protected use available",
        snapshot["available"]
        and snapshot["shadow_use"]["available"]
        and snapshot["shadow_use"]["bytes"] == window[28:].hex()
        and snapshot["synthetic_entry"]
        and not snapshot["function_evidence_published"],
    )
    form = module.ShadowUseForm(ROOT, 0, local_shadow, REQUEST, snapshot)
    forms.append(form)
    form.Show(
        "Chernobog shadow call use " + snapshot["root"],
        options=ida_kernwin.PluginForm.WOPN_PERSIST,
    )
    report["inventory_after_form_show"] = inventory()
    form.parent.window().resize(1700, 1000)
    QtWidgets.QApplication.processEvents()
    form.fit_graph()
    form.poll()
    QtWidgets.QApplication.processEvents()
    bounds = form.scene.itemsBoundingRect()
    report["graph_geometry"] = {
        "viewport_width": form.graph.viewport().width(),
        "viewport_height": form.graph.viewport().height(),
        "scene_width": bounds.width(),
        "scene_height": bounds.height(),
        "scale": form.graph.transform().m11(),
    }
    check(
        "Qt renders use, graph, transfer and frontiers",
        form.current
        and len(form.nodes) == len(snapshot["heads"]) == 9
        and form.use_table.rowCount() == 1
        and form.edges.rowCount() == len(snapshot["edges"]) == 1
        and form.frontiers.rowCount() == len(snapshot["frontiers"]) == 2
        and form.use_table.item(0, 3).text() == "0x10000145c"
        and form.use_table.item(0, 4).text() == window[28:].hex()
        and "Current synthetic call-use capture" in form.status.text()
        and "no callee semantics" in form.scope.text(),
    )
    edges = [item for item in form.scene.items() if isinstance(item, module.FlowEdge)]
    check(
        "synthetic edge is visibly conditional",
        len(edges) == 1
        and edges[0].row["truth"] == "conditional-byte-decode"
        and edges[0].pen().style() == QtCore.Qt.PenStyle.DashLine,
    )
    form.use_table.selectRow(0)
    QtWidgets.QApplication.processEvents()
    detail = json.loads(form.detail.toPlainText())
    check(
        "selected use retains provenance and bytes",
        detail["current_exact_shadow_use"]
        and detail["synthetic_entry"]
        and not detail["function_evidence_published"]
        and not detail["vm_identity_proved"]
        and detail["selected"]["source"] == "0x10000144d"
        and detail["selected"]["pointer"] == "0x10000145c"
        and detail["selected"]["bytes"] == window[28:].hex()
        and not detail["selected"]["callee_semantics_proved"],
    )
    check(
        "visible fields exclude personal paths",
        all(
            "/Users/" not in value
            for value in (form.status.text(), form.scope.text(), form.detail.toPlainText())
        ),
    )
    changed = bytearray(window)
    changed[28] ^= 1
    local_shadow.write_bytes(changed)
    form.poll()
    check(
        "changed shadow bytes invalidate the visible capture",
        not form.current
        and "Stale shadow capture" in form.status.text()
        and form.use_table.item(0, 4).text() == window[28:].hex(),
    )
    local_shadow.write_bytes(window)
    form.poll()
    check("restored exact shadow recovers current status", form.current)
    original_api = module.shadow_use_api

    def mutate_during_query(root, seed, shadow_file, request):
        state = original_api(root, seed, shadow_file, request)
        local_shadow.write_bytes(changed)
        return state

    try:
        module.shadow_use_api = mutate_during_query
        form.poll()
        check("shadow mutation during recomputation invalidates capture", not form.current)
    finally:
        module.shadow_use_api = original_api
        local_shadow.write_bytes(window)
    form.poll()
    check("restored shadow after query mutation recovers status", form.current)
    check("Qt screenshot saved", form.parent.grab().save(str(DESTINATION / "shadow_use.png")))
    report["inventory_after_view"] = inventory()
    form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
    QtWidgets.QApplication.processEvents()
    companion = module.EvidencePlugin()
    check(
        "separate shadow-use action registered",
        companion.init() == ida_idaapi.PLUGIN_KEEP and companion.shadow_registered,
    )
    report["inventory_after_action_registration"] = inventory()
    companion.shadow_action.prompt = lambda: (str(local_shadow), REQUEST)
    dispatched = companion.shadow_action.activate(SimpleNamespace(cur_ea=ROOT))
    QtWidgets.QApplication.processEvents()
    check(
        "registered handler opens and reuses exact capture",
        dispatched
        and len(companion.shadow_forms) == 1
        and next(iter(companion.shadow_forms.values())).current
        and companion.shadow_action.activate(SimpleNamespace(cur_ea=ROOT))
        and len(companion.shadow_forms) == 1,
    )
    same_bytes_shadow = DESTINATION / "shadow-window-second.bin"
    same_bytes_shadow.write_bytes(window)
    check(
        "equal bytes in separate files retain distinct form identity",
        companion.open_shadow_use(ROOT, 0, same_bytes_shadow, REQUEST)
        and len(companion.shadow_forms) == 2
        and {Path(view.shadow_file) for view in companion.shadow_forms.values()}
        == {local_shadow, same_bytes_shadow},
    )
    report["inventory_before"] = before
    report["inventory_after"] = inventory()
    report["selected_inventory_before"] = selected_before
    report["selected_inventory_after"] = selected_inventory()
    report["global_inventory_equal"] = report["inventory_before"] == report["inventory_after"]
    check(
        "global inventory settles before the call-use form opens",
        report["inventory_after_idle_gui_pump"] == report["inventory_after"],
    )
    check(
        "Qt inspection preserves selected bytes, items, owners and references",
        report["selected_inventory_before"] == report["selected_inventory_after"],
    )
    report["shadow_summary"] = {
        "planned_heads": len(snapshot["heads"]),
        "entered_instructions": snapshot["instruction_count"],
        "edges": len(snapshot["edges"]),
        "frontiers": len(snapshot["frontiers"]),
        "use": snapshot["shadow_use"],
    }
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
finally:
    if companion is not None:
        companion.term()
    for form in forms:
        if not form.closed:
            form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
    (DESTINATION / "shadow_use_gui.json").write_text(json.dumps(report, indent=2) + "\n")
    print("[chernobog][shadow-use-gui] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
    ida_pro.qexit(2 if report["errors"] else 0)
