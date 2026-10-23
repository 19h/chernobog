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
defaults = {
    "auto": "0",
    "writable_const": "0",
    "stack_alias_objects": "0",
    "rax": "0",
    "rax_runs": "1",
    "rax_timeout_ms": "50",
    "rax_max_insns": "1000",
    "mba_smt": "1",
    "mba_affine": "0",
    "mba_backend": "auto",
    "inline_forwarders": "1",
    "verbose": "0",
}
options = tuple(defaults)


def check(name, condition):
    report["checks"].append({"name": name, "passed": bool(condition)})
    if not condition:
        report["errors"].append(name)


def values():
    return {name: idc.eval_idc('chernobog_get_option("%s");' % name) for name in options}


def text(view):
    return "\n".join(ida_lines.tag_remove(line.line) for line in view.cfunc.get_pseudocode())


def drive_dialog(
    apply,
    automatic=True,
    writable=2,
    objects=True,
    rax=False,
    smt=True,
    affine=True,
    backend="legacy",
    inline=True,
    verbose=False,
    runs=2,
    timeout=100,
    instructions=2000,
):
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
            for label, option in (
                ("RAX emulation", "rax"),
                ("SMT MBA synthesis", "mba_smt"),
                ("Affine MBA reconstruction", "mba_affine"),
                ("Inline forwarding wrappers", "inline_forwarders"),
                ("Verbose logging", "verbose"),
            ):
                assert boxes[label].isChecked() == (initial[option] == "1")
            boxes["RAX emulation"].setChecked(rax)
            boxes["SMT MBA synthesis"].setChecked(smt)
            boxes["Affine MBA reconstruction"].setChecked(affine)
            boxes["Inline forwarding wrappers"].setChecked(inline)
            boxes["Verbose logging"].setChecked(verbose)
            combos = dialog.findChildren(QtWidgets.QComboBox)
            combo = next(c for c in combos if c.itemText(0) == "Disabled")
            backend_combo = next(c for c in combos if c.itemText(0) == "Default")
            numeric = [c for c in combos if c.isEditable()]
            assert [c.currentText() for c in numeric] == [
                initial["rax_runs"],
                initial["rax_timeout_ms"],
                initial["rax_max_insns"],
            ]
            for field, value in zip(numeric, (runs, timeout, instructions)):
                field.setEditText(str(value))
            assert backend_combo.currentIndex() == ("auto", "cobra", "legacy").index(
                initial["mba_backend"]
            )
            backend_combo.setCurrentIndex(("auto", "cobra", "legacy").index(backend))
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
        for name, value in defaults.items():
            assert idc.eval_idc('chernobog_set_option("%s", "%s");' % (name, value)) == 1
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
        expected = dict(
            defaults,
            auto="1",
            writable_const="2",
            stack_alias_objects="1",
            mba_affine="1",
            mba_backend="legacy",
            rax_runs="2",
            rax_timeout_ms="100",
            rax_max_insns="2000",
        )
        check("Apply updates runtime options", values() == expected)
        after = text(view)
        check(
            "Apply refreshes existing pseudocode",
            "while (" not in after and "switch (" not in after,
        )
        disabled = idc.eval_idc("chernobog_rax_explore(%d);" % ea)
        check(
            "RAX disabled while static recovery runs",
            idc.eval_idc("chernobog_rax_result_name(%d);" % disabled) == "disabled",
        )
        check(
            "no emulation evidence in static mode",
            not idc.eval_idc("chernobog_rax_summary(%d).available;" % ea),
        )
        math_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "_mba_expression")
        if math_ea == ida_idaapi.BADADDR:
            math_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "mba_expression")
        assert idc.SetType(math_ea, "unsigned int mba_expression(unsigned int x, unsigned int y);")
        idc.eval_idc("chernobog_rule_reset_stats();")
        math = ida_hexrays.decompile(math_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        math_text = "\n".join(ida_lines.tag_remove(line.line) for line in math.get_pseudocode())
        check(
            "MBA rules operate without RAX",
            "^" not in math_text and "&" not in math_text and "+" in math_text,
        )
        report["mba_without_rax"] = math_text
        drive_dialog(
            True, rax=True, smt=False, affine=False, backend="cobra", inline=False, verbose=True
        )
        check(
            "RAX can be enabled independently",
            values()["rax"] == "1" and values()["mba_smt"] == "0",
        )
        result = idc.eval_idc("chernobog_rax_explore(%d);" % ea)
        check(
            "enabled RAX actually explores",
            idc.eval_idc("chernobog_rax_result_name(%d);" % result)
            in ("explored", "already_fresh"),
        )
        check(
            "enabled RAX publishes evidence",
            bool(idc.eval_idc("chernobog_rax_summary(%d).available;" % ea)),
        )
        drive_dialog(True)
        check(
            "disabling RAX discards previous evidence",
            not idc.eval_idc("chernobog_rax_summary(%d).available;" % ea),
        )
        result = idc.eval_idc("chernobog_rax_explore(%d);" % ea)
        check(
            "RAX stays disabled after prior execution",
            idc.eval_idc("chernobog_rax_result_name(%d);" % result) == "disabled",
        )
        drive_dialog(
            True,
            automatic=False,
            writable=0,
            objects=False,
            affine=False,
            backend="auto",
            runs=1,
            timeout=50,
            instructions=1000,
        )
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
        # Dialog testing temporarily enables interactive mode. Restore batch
        # exit behavior so save prompts cannot strand this disposable IDA.
        idc.batch(1)
        # Let this IDA timer return before shutdown unregisters its callbacks.
        code = 0 if report["passed"] else 1
        QtCore.QTimer.singleShot(0, lambda: ida_pro.qexit(code))
    return -1


timer = ida_kernwin.register_timer(500, run_test)
