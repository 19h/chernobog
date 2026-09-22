"""Validate live/historical inspection and optionally its actual Qt workspace."""

import importlib.util
import json
import os
import sys
from pathlib import Path

import ida_auto
import ida_bytes
import ida_expr
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro

sys.dont_write_bytecode = True
checks, errors = [], []


def evaluate(expression):
    result = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(
        result, ida_idaapi.BADADDR, expression
    ), "IDC evaluation failed"
    return result.c_str() if result.vtype == ida_expr.VT_STR else result.num


def check(label, condition):
    checks.append({"case": label, "passed": bool(condition)})
    if not condition:
        errors.append(label)


try:
    ida_auto.auto_wait()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]), "plugin unavailable"
    target = ida_name.get_name_ea(ida_idaapi.BADADDR, "_temporal_strings")
    key = ida_name.get_name_ea(ida_idaapi.BADADDR, "_temporal_key")
    assert target != ida_idaapi.BADADDR and key != ida_idaapi.BADADDR
    evaluate(f"chernobog_rax_explore({target})")
    snapshot = json.loads(evaluate(f"chernobog_evidence_view({target})"))
    (Path(os.environ["IDAUSR"]).parent / "evidence_snapshot.json").write_text(
        json.dumps(snapshot, indent=2) + "\n"
    )
    state = json.loads(evaluate(f"chernobog_evidence_state({target})"))
    check("fresh exact snapshot", snapshot["available"] and snapshot["fresh"] and state["fresh"])
    check(
        "graph separates encodings and witnesses",
        {r["truth"] for r in snapshot["edges"]} == {"encoding", "witness"},
    )
    check(
        "allocation generations retained",
        {r["generation"] for r in snapshot["lifetimes"]} >= {"0x1", "0x2"},
    )
    check(
        "modeled uses retain bytes",
        any(
            r.get("producer") == "modeled-argument" and r.get("bytes_hex")
            for r in snapshot["events"]
        ),
    )
    check(
        "run stops and model provenance",
        len(snapshot["runs"]) == 4
        and all(r["modeled"] == "true" and r["returned"] == "true" for r in snapshot["runs"]),
    )
    tuples = [
        (int(r["run"], 0), int(r["seed"], 0), int(r["sequence"], 0)) for r in snapshot["events"]
    ]
    check("per-run event order", tuples == sorted(tuples))
    original_key = ida_bytes.get_byte(key)
    ida_bytes.patch_byte(key, original_key ^ 1)
    stale = json.loads(evaluate(f"chernobog_evidence_view({target})"))
    check(
        "stale capture remains inspectable",
        stale["available"]
        and not stale["fresh"]
        and stale["generation"] == snapshot["generation"]
        and stale["events"] == snapshot["events"],
    )
    check(
        "live state rejects consumed-key patch",
        not json.loads(evaluate(f"chernobog_evidence_state({target})"))["fresh"],
    )
    ida_bytes.patch_byte(key, original_key)
    check("exact restoration", json.loads(evaluate(f"chernobog_evidence_state({target})"))["fresh"])
    other = ida_name.get_name_ea(ida_idaapi.BADADDR, "_main")
    check(
        "foreign function rejected",
        not json.loads(evaluate(f"chernobog_evidence_view({other})"))["available"],
    )
    module_path = os.environ.get("CHERNOBOG_VIEW_MODULE")
    if module_path:
        spec = importlib.util.spec_from_file_location("evidence_view_under_test", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        check("UI identity accepts current capture", module.current_snapshot(snapshot, state))
        foreign = dict(state, database="different")
        check("UI rejects database change", not module.current_snapshot(snapshot, foreign))
        check(
            "UI rejects superseded generation",
            not module.current_snapshot(snapshot, dict(state, generation="0x0")),
        )
        check(
            "UI rejects reused generation with new publication",
            not module.current_snapshot(snapshot, dict(state, revision="0x0")),
        )
        allocation = snapshot["lifetimes"][0]
        identity = tuple(allocation[k] for k in ("run", "seed", "allocation", "generation"))
        selected = module.matching_events(snapshot, allocation=identity)
        check(
            "linked lifetime filter",
            selected and {r["kind"] for r in selected} >= {"allocate", "use", "release"},
        )
        if ida_kernwin.is_idaq():
            from PySide6 import QtWidgets

            form = module.EvidenceForm(target, snapshot)
            form.Show("Chernobog evidence test", options=ida_kernwin.PluginForm.WOPN_PERSIST)
            form.parent.window().show()
            form.parent.window().activateWindow()
            QtWidgets.QApplication.processEvents()
            check("Qt workspace created", hasattr(form, "tables") and len(form.nodes) > 0)
            form.select_site(selected[0]["site"])
            check(
                "graph selection links events",
                form.tables["events"].topLevelItemCount()
                == len(module.matching_events(snapshot, site=selected[0]["site"])),
            )
            form.select_record(selected[0])
            check(
                "selection includes scope detail",
                snapshot["generation"] in form.detail.toPlainText(),
            )
            ida_bytes.patch_byte(key, original_key ^ 1)
            form.poll()
            check(
                "Qt stale state disables navigation",
                not form.current and not form.jump.isEnabled() and "STALE" in form.status.text(),
            )
            ida_bytes.patch_byte(key, original_key)
            form.poll()
            check("Qt exact restoration", form.current)
            form.tables["lifetimes"].setCurrentItem(form.tables["lifetimes"].topLevelItem(0))
            check(
                "allocation selection links lifetime events",
                form.tables["events"].topLevelItemCount() == len(selected),
            )
            form.tables["runs"].setCurrentItem(form.tables["runs"].topLevelItem(0))
            first_run = snapshot["runs"][0]
            check(
                "run selection links ordered events",
                form.tables["events"].topLevelItemCount()
                == len(module.matching_events(snapshot, run=(first_run["run"], first_run["seed"]))),
            )
            form.clear_filters()
            form.select_site(selected[0]["site"])
            form.parent.resize(1200, 780)
            form.parent.window().resize(1400, 900)
            QtWidgets.QApplication.processEvents()
            form.select_record(selected[0])
            QtWidgets.QApplication.processEvents()
            node_bounds = form.graph.mapFromScene(
                form.nodes[selected[0]["site"]].sceneBoundingRect()
            ).boundingRect()
            check(
                "selected node visible after layout",
                form.graph.viewport().rect().intersects(node_bounds),
            )
            form.parent.grab().save(str(Path(os.environ["IDAUSR"]).parent / "evidence_view.png"))
            form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
            QtWidgets.QApplication.processEvents()
            check("Qt close stops polling", form.closed and not form.timer.isActive())
            companion = module.EvidencePlugin()
            check("companion registers GUI action", companion.init() == ida_idaapi.PLUGIN_KEEP)
            disassembly = ida_kernwin.open_disasm_window("Evidence probe disassembly")
            assert disassembly is not None, "disassembly unavailable"
            ida_kernwin.display_widget(disassembly, ida_kernwin.PluginForm.WOPN_DP_TAB)
            disassembly_qt = ida_kernwin.PluginForm.FormToPyQtWidget(disassembly)
            disassembly_qt.window().show()
            disassembly_qt.window().activateWindow()
            ida_kernwin.activate_widget(disassembly, True)
            QtWidgets.QApplication.processEvents()
            ida_kernwin.jumpto(target)
            QtWidgets.QApplication.processEvents()
            disassembly_qt.setFocus()
            QtWidgets.QApplication.processEvents()
            check("action context is current function", ida_kernwin.get_screen_ea() == target)
            dispatched = ida_kernwin.process_ui_action(module.ACTION)
            QtWidgets.QApplication.processEvents()
            check(
                "registered action opens current function",
                dispatched
                and len(companion.forms) == 1
                and all(not item.closed for item in companion.forms.values()),
            )
            ida_kernwin.process_ui_action(module.ACTION)
            check("registered action reuses workspace", len(companion.forms) == 1)
            companion.term()
            QtWidgets.QApplication.processEvents()
            check(
                "companion termination closes workspace",
                all(item.closed for item in companion.forms.values()),
            )
    evaluate("chernobog_rax_clear()")
    check(
        "cleared capture unavailable",
        not json.loads(evaluate(f"chernobog_evidence_view({target})"))["available"],
    )
    evaluate(f"chernobog_rax_explore({target})")
    renewed = json.loads(evaluate(f"chernobog_evidence_state({target})"))
    check(
        "republication receives a distinct revision",
        renewed["fresh"] and renewed["revision"] != snapshot["revision"],
    )
    evaluate("chernobog_rax_clear()")
except BaseException as error:
    errors.append(type(error).__name__)

(Path(os.environ["IDAUSR"]).parent / "evidence_view.json").write_text(
    json.dumps({"checks": checks, "errors": errors}, indent=2) + "\n"
)
line = "[chernobog][evidence-view] " + (
    "FAIL " + "; ".join(errors) if errors else "PASS checks=%d" % len(checks)
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
