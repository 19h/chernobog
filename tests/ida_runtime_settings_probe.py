"""Exercise the real runtime settings dialog, including Cancel and cache refresh."""

import json
import os
from pathlib import Path
import sys
import traceback

import ida_auto
import ida_bytes
import ida_diskio
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_name
import ida_pro
import idc

# Prefer this IDA installation's Qt bindings over user-added Python paths.
sys.path.insert(0, ida_diskio.idadir("python"))
from PySide6 import QtCore, QtWidgets

out = Path(os.environ["IDAUSR"]).parent
report = {"passed": False, "checks": [], "errors": []}
options = ("auto", "writable_const", "stack_alias_objects")


def check(name, condition):
    report["checks"].append({"name": name, "passed": bool(condition)})
    if not condition:
        report["errors"].append(name)


def values():
    return {name: idc.eval_idc('chernobog_get_option("%s");' % name) for name in options}


def text(view):
    return "\n".join(ida_lines.tag_remove(line.line) for line in view.cfunc.get_pseudocode())


def drive_dialog(apply, automatic=True, writable=2, objects=True):
    state = {"seen": False, "attempts": 0, "error": None}
    initial = values()

    def interact():
        state["attempts"] += 1
        dialog = next(
            (
                widget
                for widget in QtWidgets.QApplication.topLevelWidgets()
                if widget.isVisible() and widget.windowTitle() == "Chernobog runtime settings"
            ),
            None,
        )
        if dialog is None:
            if state["attempts"] < 100:
                QtCore.QTimer.singleShot(25, interact)
            return
        state["seen"] = True
        try:
            boxes = {
                widget.text().replace("&", ""): widget
                for widget in dialog.findChildren(QtWidgets.QCheckBox)
            }
            assert boxes["Automatic deobfuscation"].isChecked() == (initial["auto"] == "1")
            assert boxes["Bounded stack objects"].isChecked() == (
                initial["stack_alias_objects"] == "1"
            )
            boxes["Automatic deobfuscation"].setChecked(automatic)
            boxes["Bounded stack objects"].setChecked(objects)
            combo = dialog.findChild(QtWidgets.QComboBox)
            assert combo is not None
            assert [combo.itemText(i) for i in range(combo.count())] == [
                "Disabled",
                "Scalars",
                "Scalars and arrays",
            ]
            assert combo.currentIndex() == int(initial["writable_const"] or "0")
            combo.setCurrentIndex(writable)
            labels = "\n".join(label.text() for label in dialog.findChildren(QtWidgets.QLabel))
            assert "Settings reset when IDA closes" in labels
            dialog.grab().save(str(out / "runtime-settings.png"))
            wanted = "Apply" if apply else "Cancel"
            button = next(
                button
                for button in dialog.findChildren(QtWidgets.QPushButton)
                if button.text().replace("&", "") == wanted
            )
            button.click()
        except Exception:
            state["error"] = traceback.format_exc()
            dialog.close()

    QtCore.QTimer.singleShot(0, interact)
    state["action_result"] = ida_kernwin.process_ui_action("chernobog:settings")
    report.setdefault("dialogs", []).append(state)
    assert state["seen"], "settings action did not open its dialog"
    assert state["error"] is None, state["error"]


def run_test():
    try:
        assert ida_kernwin.is_idaq()
        idc.batch(0)
        ida_auto.auto_wait()
        assert ida_hexrays.init_hexrays_plugin()
        check(
            "settings action registered",
            "chernobog:settings" in ida_kernwin.get_registered_actions(),
        )
        check(
            "IDC settings entry registered",
            "chernobog_settings()" in idc.eval_idc("chernobog_help();"),
        )
        for name in options:
            assert idc.eval_idc('chernobog_set_option("%s", 0);' % name) == 1
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "_object_escape")
        if ea == ida_idaapi.BADADDR:
            ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "object_escape")
        assert ea != ida_idaapi.BADADDR
        function = ida_funcs.get_func(ea)
        original = ida_bytes.get_bytes(ea, function.end_ea - ea)
        view = ida_hexrays.open_pseudocode(ea, 0)
        assert view
        ida_kernwin.activate_widget(view.ct, True)
        widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(view.ct)
        widget.window().show()
        widget.window().activateWindow()
        QtWidgets.QApplication.setActiveWindow(widget.window())
        widget.setFocus()
        QtWidgets.QApplication.processEvents()
        before = text(view)
        check("fixture begins with dispatcher", "while (" in before or "switch (" in before)
        original_options = values()
        drive_dialog(False)
        check("Cancel preserves options", values() == original_options)
        check("Cancel preserves pseudocode", text(view) == before)
        drive_dialog(True)
        check(
            "Apply updates runtime options",
            values() == {"auto": "1", "writable_const": "2", "stack_alias_objects": "1"},
        )
        after = text(view)
        check(
            "Apply refreshes existing pseudocode",
            "while (" not in after and "switch (" not in after,
        )
        drive_dialog(True, automatic=False, writable=0, objects=False)
        check("settings can be disabled", values() == original_options)
        check(
            "disabling refreshes existing pseudocode",
            "while (" in text(view) or "switch (" in text(view),
        )
        check("native bytes unchanged", original == ida_bytes.get_bytes(ea, len(original)))
        report["passed"] = not report["errors"]
    except Exception:
        report["errors"].append(traceback.format_exc())
    finally:
        (out / "runtime-settings.json").write_text(json.dumps(report, indent=2) + "\n")
        print(
            "[chernobog][runtime-settings] " + ("PASS" if report["passed"] else "FAIL"), flush=True
        )
        ida_pro.qexit(0 if report["passed"] else 1)
    return -1


timer = ida_kernwin.register_timer(500, run_test)
