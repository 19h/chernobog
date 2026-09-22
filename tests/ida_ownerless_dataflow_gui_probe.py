"""Actual Qt ownerless-region inspection, freshness and navigation controls."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import traceback

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
checks, errors, captures, screenshots, forms = [], [], {}, [], []
destination = Path(os.environ["IDAUSR"]).parent
source_paths = {
    "preparation": Path(os.environ["CHERNOBOG_OWNERLESS_PROBE"]),
    "view": Path(os.environ["CHERNOBOG_VIEW_MODULE"]),
}
source_hashes = {
    name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in source_paths.items()
}
original_jump = ida_kernwin.jumpto
patched = None
companion = None
action_widget = None
FLAG_ENCODING = "Abstract bits: CF=1, PF=2, AF=4, ZF=8, SF=16, OF=32; not EFLAGS/RFLAGS positions"


def check(name, condition):
    checks.append({"case": name, "passed": bool(condition)})
    if not condition:
        errors.append(name)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def preserve(name, action):
    before = preparation.inventory()
    details = metadata_details() if name == "open_equal_form" else None
    value = action()
    after = preparation.inventory()
    check(name + " preserves whole IDB inventory", before == after)
    captures[name + "_inventory"] = {"before": before, "after": after}
    if details is not None and before != after:
        changed = metadata_details()
        captures[name + "_metadata_changes"] = {
            key: {"before": details.get(key), "after": changed.get(key)}
            for key in sorted(set(details) | set(changed))
            if details.get(key) != changed.get(key)
        }
    return value


def metadata_details():
    """Bounded diagnostics for a first-window metadata mutation, if observed."""
    result = {}
    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        result["segment:" + hex(segment.start_ea)] = (
            int(segment.end_ea),
            int(segment.bitness),
            int(segment.perm),
            [
                hashlib.sha256(part).hexdigest()
                for part in ida_bytes.get_bytes_and_mask(
                    segment.start_ea, segment.end_ea - segment.start_ea
                )
                or ()
            ],
        )
        for ea in idautils.Heads(segment.start_ea, segment.end_ea):
            function = ida_funcs.get_func(ea)
            result["head:" + hex(ea)] = (
                int(ida_bytes.get_full_flags(ea)),
                int(ida_bytes.get_item_end(ea)),
                None if function is None else int(function.start_ea),
                ida_bytes.get_cmt(ea, True),
                ida_bytes.get_cmt(ea, False),
                sorted(
                    (int(ref.frm), int(ref.to), int(ref.type), bool(ref.iscode), bool(ref.user))
                    for ref in idautils.XrefsFrom(ea)
                ),
            )
    for ea in idautils.Functions():
        function = ida_funcs.get_func(ea)
        result["function:" + hex(ea)] = (
            int(function.flags),
            list(idautils.Chunks(ea)),
            ida_funcs.get_func_cmt(function, True),
            ida_funcs.get_func_cmt(function, False),
        )
    result["names"] = list(idautils.Names())
    return result


def result(root):
    return preparation.api(f"chernobog_native_region_facts({root})")


def select_join(form, join):
    for index in range(form.facts.rowCount()):
        row = form.facts.item(index, 0).data(module.QtCore.Qt.ItemDataRole.UserRole)
        if preparation.number(row["site"]) == join and row["kind"] == "setcc-value":
            form.facts.selectRow(index)
            QtWidgets.QApplication.processEvents()
            return row
    raise AssertionError("missing fixture join in Qt facts table")


def visible_contract(form):
    check(
        "scope label retains exact complete contract", form.scope.text() == form.snapshot["scope"]
    )
    check(
        "complete scope label fits the visible form",
        form.scope.isVisible()
        and form.parent.rect().contains(form.scope.geometry())
        and form.scope.height() >= form.scope.heightForWidth(form.scope.width()),
    )
    check(
        "scope explicitly retains bounded unpublished normal-return contract",
        "selected ownerless root" in form.scope.text()
        and "no whole-program reachability" in form.scope.text()
        and "calls require normal return" in form.scope.text()
        and form.snapshot["published"] is False,
    )
    check(
        "Qt detail retains the exact abstract flag encoding",
        form.snapshot.get("flag_encoding") == FLAG_ENCODING
        and json.loads(form.detail.toPlainText()).get("flag_encoding") == FLAG_ENCODING,
    )


def save(form, filename, detail_text):
    cursor = form.detail.document().find(detail_text)
    assert not cursor.isNull()
    form.detail.setTextCursor(cursor)
    form.detail.centerCursor()
    # Keep the leading flag legend alongside the selected result. Centering a
    # late JSON field can otherwise scroll past the legend despite spare space.
    form.detail.verticalScrollBar().setValue(0)
    QtWidgets.QApplication.processEvents()
    check(
        filename + " selected detail is in the actual viewport",
        form.detail.viewport().rect().contains(form.detail.cursorRect(cursor)),
    )
    legend = form.detail.document().find(FLAG_ENCODING)
    assert not legend.isNull()
    start, end = module.QtGui.QTextCursor(legend), module.QtGui.QTextCursor(legend)
    start.setPosition(legend.selectionStart())
    end.setPosition(legend.selectionEnd())
    check(
        filename + " full flag encoding is in the actual viewport",
        form.detail.viewport().rect().contains(form.detail.cursorRect(start))
        and form.detail.viewport().rect().contains(form.detail.cursorRect(end)),
    )
    visible = [form.status.text(), form.scope.text(), form.detail.toPlainText()]
    for widget in form.parent.findChildren(QtWidgets.QWidget):
        if not widget.isVisible():
            continue
        for getter in ("text", "toPlainText", "toolTip", "windowTitle"):
            method = getattr(widget, getter, None)
            if callable(method):
                try:
                    value = method()
                except TypeError:
                    continue
                if isinstance(value, str):
                    visible.append(value)
    check(
        filename + " visible text excludes personal paths", all("/Users/" not in s for s in visible)
    )
    assert all("/Users/" not in s for s in visible)
    check(filename + " screenshot saved", form.parent.grab().save(str(destination / filename)))
    screenshots.append(filename)


def open_form(root, snapshot, title):
    form = module.NativeRegionForm(root, snapshot)
    forms.append(form)
    form.Show(title, options=ida_kernwin.PluginForm.WOPN_PERSIST)
    arrange_form(form)
    return form


def arrange_form(form):
    form.parent.window().show()
    form.parent.window().activateWindow()
    form.parent.window().resize(1700, 1100)
    form.detail.setMinimumHeight(600)
    form.detail.parentWidget().setSizes([200, 700])
    QtWidgets.QApplication.processEvents()
    form.fit_graph()
    QtWidgets.QApplication.processEvents()


def shape(form, snapshot, name):
    check(
        name + " actual Qt graph and tables retain every row",
        len(form.nodes) == len(snapshot["nodes"])
        and sum(isinstance(item, module.FlowNode) for item in form.scene.items())
        == len(snapshot["nodes"])
        and form.facts.rowCount() == len(snapshot["records"])
        and form.edges.rowCount() == len(snapshot["edges"]),
    )
    nodes = {node["site"] for node in snapshot["nodes"]}
    expected = sum(
        edge["source"] in nodes and edge["target"] in nodes for edge in snapshot["edges"]
    )
    check(
        name + " graph edges correspond to table endpoints",
        sum(isinstance(item, module.FlowEdge) for item in form.scene.items()) == expected,
    )
    visible_contract(form)


try:
    assert ida_kernwin.is_idaq()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, "chernobog_native_analysis()")
    ida_auto.auto_wait()
    ida_auto.enable_auto(False)
    preparation = load_module("ownerless_gui_preparation", source_paths["preparation"])
    module = load_module("ownerless_gui_view", source_paths["view"])
    from PySide6 import QtWidgets

    equal, equal_instructions = preparation.prepare_diamond("od_equal")
    conflict, conflict_instructions = preparation.prepare_diamond("od_conflict")
    check(
        "independent fixture spans have eleven heads each",
        len(equal_instructions) == len(conflict_instructions) == 11,
    )
    ordinary = preparation.symbol("df_equal")
    # Fixture ownership edits precede this experiment. Drain their deferred
    # topology work and refresh the independent owned control before measuring
    # any read-only API or GUI action.
    QtWidgets.QApplication.processEvents()
    owned_controls = []
    for name in (
        "df_equal",
        "df_different",
        "df_flags",
        "df_loop",
        "df_loop_changes",
        "df_stack",
        "df_stack_changes",
        "df_jump",
        "df_external",
        "df_target",
        "df_target_changes",
    ):
        function = ida_funcs.get_func(preparation.symbol(name))
        assert function is not None
        assert ida_auto.plan_and_wait(function.start_ea, function.end_ea)
        owned_controls.append(
            {"name": name, "start": hex(function.start_ea), "end": hex(function.end_ea)}
        )
    captures["setup_owned_control_refresh"] = owned_controls
    QtWidgets.QApplication.processEvents()
    publication = preparation.api(f"chernobog_native_evidence({ordinary})")
    check(
        "ordinary control starts with a fresh nonempty publication",
        any(
            row["fresh"] == "true" and row["kind"] == "setcc-value"
            for row in publication["records"]
        ),
    )
    captures["ordinary_publication_before"] = publication
    baseline_inventory = preparation.inventory()
    baseline = preserve("equal_api", lambda: result(equal[""]))
    unknown = preserve("conflict_api", lambda: result(conflict[""]))
    captures["equal_snapshot"], captures["conflict_snapshot"] = baseline, unknown
    check(
        "API explicitly labels its compact flag masks",
        baseline.get("flag_encoding") == unknown.get("flag_encoding") == FLAG_ENCODING
        and preparation.number(preparation.row_at(baseline, equal["_join"])["flags_known"])
        == 1 | 32
        and preparation.number(preparation.row_at(baseline, equal["_join"])["flags_value"]) == 1
        and preparation.number(preparation.row_at(unknown, conflict["_join"])["flags_known"]) == 32,
    )
    check(
        "equal and conflicting snapshots retain distinct semantic verdicts",
        preparation.row_at(baseline, equal["_join"])["status"] == "proved"
        and preparation.row_at(baseline, equal["_join"])["outcome"] == "true"
        and preparation.row_at(unknown, conflict["_join"])["status"] == "unresolved"
        and preparation.row_at(unknown, conflict["_join"])["outcome"] == "unknown",
    )
    for key, replacement in (("database", "different"), ("context", "0x0"), ("root", "0x0")):
        check(
            "exact-region identity rejects changed " + key,
            not module.current_native_region(baseline, dict(baseline, **{key: replacement})),
        )
    check(
        "zero context never authenticates an identical result",
        not module.current_native_region(
            dict(baseline, context="0x0"), dict(baseline, context="0x0")
        ),
    )
    form = preserve(
        "open_equal_form", lambda: open_form(equal[""], baseline, "Ownerless native facts: proved")
    )
    preserve("select_equal_join", lambda: select_join(form, equal["_join"]))
    check(
        "fresh proved row enables source navigation",
        form.current and form.jump.isEnabled() and form.selected["status"] == "proved",
    )
    shape(form, baseline, "equal")
    preserve("poll_equal_form", form.poll)
    save(form, "ownerless_equal_scope.png", '"scope":')
    save(form, "ownerless_equal_fact.png", '"status": "proved"')

    navigated = []

    def tracked_jump(ea, *args, **kwargs):
        navigated.append(int(ea))
        return original_jump(ea, *args, **kwargs)

    ida_kernwin.jumpto = tracked_jump
    preserve("fresh_actual_navigation", form.jump.click)
    QtWidgets.QApplication.processEvents()
    check(
        "fresh Qt button invokes actual IDA navigation",
        navigated == [equal["_join"]] and ida_kernwin.get_screen_ea() == equal["_join"],
    )
    left = equal["_left"]
    assert ida_bytes.get_byte(left) == 0xF9
    patched = left
    ida_bytes.patch_byte(left, 0xF8)
    changed = preserve("changed_api", lambda: result(equal[""]))
    captures["changed_snapshot"] = changed
    preserve("stale_form_poll", form.poll)
    check(
        "changed definition invalidates the old displayed result",
        not module.current_native_region(baseline, changed)
        and not form.current
        and not form.jump.isEnabled()
        and "stale" in form.status.text(),
    )
    preserve("stale_navigation_guard", form.jump_source)
    check("direct stale navigation action performs no jump", navigated == [equal["_join"]])
    save(form, "ownerless_stale_fact.png", '"current_exact_graph": false')
    ida_bytes.patch_byte(left, 0xF9)
    patched = None
    preserve("restored_form_poll", form.poll)
    check(
        "exact restoration admits the original graph again",
        form.current
        and form.jump.isEnabled()
        and module.current_native_region(baseline, result(equal[""])),
    )

    patched = left
    ida_bytes.patch_byte(left, 0xF8)
    preserve("recompute_changed_graph", form.reload)
    preserve("select_changed_join", lambda: select_join(form, equal["_join"]))
    check(
        "actual recompute shows a current unresolved graph",
        form.current
        and form.snapshot == changed
        and form.selected["status"] == "unresolved"
        and form.selected["outcome"] == "unknown"
        and form.jump.isEnabled(),
    )
    save(form, "ownerless_recomputed_unknown.png", '"status": "unresolved"')
    ida_bytes.patch_byte(left, 0xF9)
    patched = None
    preserve("recompute_restored_graph", form.reload)
    check("recompute restoration matches original full result", form.snapshot == baseline)

    other = preserve(
        "open_conflict_form",
        lambda: open_form(conflict[""], unknown, "Ownerless native facts: unresolved"),
    )
    preserve("select_conflict_join", lambda: select_join(other, conflict["_join"]))
    shape(other, unknown, "conflict")
    check(
        "unknown facts retain current source navigation without proof promotion",
        other.current and other.jump.isEnabled() and other.selected["status"] == "unresolved",
    )
    save(other, "ownerless_conflict_fact.png", '"status": "unresolved"')

    ida_kernwin.jumpto = original_jump
    companion = module.EvidencePlugin()
    initialized = preserve("register_inspector_actions", companion.init)
    check(
        "companion initialization registers the ownerless action",
        initialized == ida_idaapi.PLUGIN_KEEP and companion.region_registered,
    )
    assert initialized == ida_idaapi.PLUGIN_KEEP and companion.region_registered

    def activate_registered_action():
        global action_widget
        action_widget = ida_kernwin.open_disasm_window("Ownerless action context")
        assert action_widget is not None
        ida_kernwin.display_widget(action_widget, ida_kernwin.PluginForm.WOPN_DP_TAB)
        widget = ida_kernwin.PluginForm.FormToPyQtWidget(action_widget)
        widget.window().show()
        widget.window().activateWindow()
        ida_kernwin.activate_widget(action_widget, True)
        QtWidgets.QApplication.processEvents()
        assert original_jump(equal[""])
        QtWidgets.QApplication.processEvents()
        widget.setFocus()
        QtWidgets.QApplication.processEvents()
        check(
            "registered action uses the exact ownerless cursor root",
            ida_kernwin.get_screen_ea() == equal[""] and ida_funcs.get_func(equal[""]) is None,
        )
        dispatched = ida_kernwin.process_ui_action(module.REGION_ACTION)
        QtWidgets.QApplication.processEvents()
        return dispatched

    dispatched = preserve("activate_registered_inspector", activate_registered_action)
    check(
        "registered ownerless action opens exactly one region workspace",
        dispatched and len(companion.region_forms) == 1 and not companion.forms,
    )
    assert len(companion.region_forms) == 1
    registered_form = next(iter(companion.region_forms.values()))
    preserve("arrange_registered_form", lambda: arrange_form(registered_form))
    preserve("select_registered_join", lambda: select_join(registered_form, equal["_join"]))
    check(
        "registered action displays the original exact-root result",
        registered_form.root == equal[""]
        and registered_form.snapshot == baseline
        and registered_form.current,
    )
    shape(registered_form, baseline, "registered action")
    save(registered_form, "ownerless_registered_action.png", '"flag_encoding":')
    preserve("terminate_companion", companion.term)
    QtWidgets.QApplication.processEvents()
    check(
        "companion termination closes its region form and timer",
        registered_form.closed and not registered_form.timer.isActive(),
    )
    companion = None
    check(
        "companion termination unregisters the ownerless action",
        not preserve(
            "terminated_action_dispatch",
            lambda: ida_kernwin.process_ui_action(module.REGION_ACTION),
        ),
    )
    check(
        "all graph APIs and GUI controls preserve the restored IDB",
        preparation.inventory() == baseline_inventory,
    )
    check(
        "ordinary native publication remains unchanged",
        preparation.api(f"chernobog_native_evidence({ordinary})") == publication,
    )
    captures["ordinary_publication_after"] = preparation.api(
        f"chernobog_native_evidence({ordinary})"
    )
except BaseException as error:
    errors.append(type(error).__name__)
    captures["exception"] = {
        "type": type(error).__name__,
        "frames": [
            {"function": frame.name, "line": frame.lineno}
            for frame in traceback.extract_tb(error.__traceback__)
        ],
    }
finally:
    ida_kernwin.jumpto = original_jump
    if patched is not None:
        ida_bytes.patch_byte(patched, 0xF9)
    if companion is not None:
        companion.term()
    if action_widget is not None:
        ida_kernwin.close_widget(action_widget, ida_kernwin.PluginForm.WCLS_SAVE)
    for form in reversed(forms):
        try:
            form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
            QtWidgets.QApplication.processEvents()
            check("form closes its polling timer", form.closed and not form.timer.isActive())
        except BaseException as error:
            errors.append("form close: " + type(error).__name__)
    check(
        "preparation and view source identities remain unchanged",
        source_hashes
        == {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in source_paths.items()
        },
    )

report = {
    "passed": not errors,
    "scope": "Actual Qt/IDA ownerless-region inspection of native-executed synthetic diamonds; controlled IDB-only byte mutations are restored",
    "checks": checks,
    "errors": errors,
    "captures": captures,
    "screenshots": screenshots,
    "source_sha256": source_hashes,
}
(destination / "ownerless_dataflow_gui.json").write_text(json.dumps(report, indent=2) + "\n")
line = "[chernobog][ownerless-dataflow-gui] " + ("FAIL" if errors else "PASS")
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
