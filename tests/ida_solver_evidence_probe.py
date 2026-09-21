"""Capture actual production SMT queries and exercise their historical GUI."""
import importlib.util
import json
import os
import sys
from pathlib import Path

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_hexrays as hx
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro

sys.dont_write_bytecode = True
checks, errors, captures = [], [], {}


def check(name, value):
    checks.append({"case": name, "passed": bool(value)})
    if not value:
        errors.append(name)


def evaluate(expression):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    return value.c_str() if value.vtype == ida_expr.VT_STR else value.num


def snapshot(ea):
    return json.loads(evaluate(f"chernobog_solver_evidence({ea})"))


try:
    ida_auto.auto_wait()
    assert hx.init_hexrays_plugin()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    names = os.environ.get("CHERNOBOG_QUERY_NAMES", "query_nonlinear,query_linear").split(",")
    targets = {}
    for name in names:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "_" + name)
        assert ea != ida_idaapi.BADADDR
        targets[name] = ea
        function = ida_funcs.get_func(ea)
        raw = ida_bytes.get_bytes(function.start_ea, function.end_ea - function.start_ea)
        assert hx.decompile(ea, None, hx.DECOMP_NO_CACHE) is not None
        data = snapshot(ea)
        captures[name] = data
        check(name + " native bytes retained", raw == ida_bytes.get_bytes(function.start_ea, len(raw)))
        check(name + " query scope is exact", all(r["function"] == hex(ea) and r["phase"]
              and r["applicability"].startswith("recorded formula only") for r in data["records"]))
        check(name + " repeated inspection is read-only", data == snapshot(ea))
        state = json.loads(evaluate(f"chernobog_solver_state({ea})"))
        check(name + " compact polling omits formula copies", len(state["records"]) == len(data["records"])
              and all(set(r) == {"query_id", "source_bytes_current"} for r in state["records"]))
    all_rows = [r for data in captures.values() for r in data["records"]]
    check("production queries retained", bool(all_rows))
    check("production SAT assignment retained", any(r["result"] == "sat" and r.get("model_constants") != "0"
          and "model_0_symbol" in r for r in all_rows))
    check("production universal exclusion retained", any(r["result"] == "unsat" for r in all_rows))
    check("nonlinear affine fit has an actual counterexample", any(r["result"] == "sat"
          and r["role"] == "bitvector-equivalence mismatch" and "model_0_symbol" in r for r in all_rows))
    check("formula text survives JSON encoding", any(r.get("formula_complete") == "true"
          and "\n" in r["formula"] and "assert" in r["formula"] for r in all_rows))
    check("source navigation does not claim IR applicability", all("navigation only" in r["source_contract"]
          for r in all_rows))
    eligible = [(name, r) for name, data in captures.items() for r in data["records"]
                if r["source_bytes_current"] == "true"]
    assert eligible, "no query instruction identity"
    selected_name, selected = next(pair for pair in eligible
                                   if pair[1]["role"] == "bitvector-equivalence mismatch"
                                   and pair[1]["result"] == "sat")
    target = targets[selected_name]
    site = int(selected["site"], 0)
    byte = ida_bytes.get_byte(site)
    ida_bytes.patch_byte(site, byte ^ 1)
    changed = snapshot(target)
    check("source byte patch invalidates navigation", not any(r["query_id"] == selected["query_id"]
          and r["source_bytes_current"] == "true" for r in changed["records"]))
    ida_bytes.patch_byte(site, byte)
    check("source byte restoration retains historical query", snapshot(target) == captures[selected_name])
    module_path = os.environ.get("CHERNOBOG_VIEW_MODULE")
    if module_path:
        spec = importlib.util.spec_from_file_location("solver_evidence_ui_test", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        saved = captures[selected_name]
        check("UI accepts exact source snapshot", selected["query_id"] in module.current_solver_sources(saved, saved))
        check("UI rejects foreign database", not module.current_solver_sources(saved, dict(saved, database="different")))
        check("UI rejects newer query generation", not module.current_solver_sources(saved, dict(saved, generation="0x0")))
        if ida_kernwin.is_idaq():
            from PySide6 import QtWidgets
            form = module.EvidenceForm(target, module.load_inspection(target))
            form.Show("Chernobog SMT evidence test", options=ida_kernwin.PluginForm.WOPN_PERSIST)
            form.parent.window().show()
            form.parent.window().activateWindow()
            QtWidgets.QApplication.processEvents()
            form.select_record(selected)
            check("SMT pane exposes actual query", selected["role"] in form.detail.toPlainText()
                  and "query_applicability" in form.detail.toPlainText())
            check("SMT formula is displayed with original newlines", selected["formula"] in form.detail.toPlainText())
            bar = form.detail.verticalScrollBar()
            bar.setValue(bar.maximum())
            scroll = bar.value()
            form.poll()
            check("polling preserves detail scroll", scroll > 0 and bar.value() == scroll)
            bar.setValue(0)
            check("SMT navigation guard independent of execution", not form.current and form.jump.isEnabled())
            ida_bytes.patch_byte(site, byte ^ 1)
            form.poll()
            check("SMT stale source navigation disabled", not form.jump.isEnabled())
            ida_bytes.patch_byte(site, byte)
            form.poll()
            check("SMT source restoration permits navigation only", form.jump.isEnabled()
                  and "current IR applicability unverified" in form.detail.toPlainText())
            form.tabs.setCurrentWidget(form.tables["solver"])
            form.parent.window().resize(1600, 1000)
            QtWidgets.QApplication.processEvents()
            form.fit_graph()
            QtWidgets.QApplication.processEvents()
            form.parent.grab().save(str(Path(os.environ["IDAUSR"]).parent / "solver_evidence.png"))
            form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
            QtWidgets.QApplication.processEvents()
            check("SMT form closes polling", form.closed and not form.timer.isActive())
    before = snapshot(target)
    assert hx.decompile(target, None, hx.DECOMP_NO_CACHE) is not None
    after = snapshot(target)
    check("new decompilation replaces query generation", before["generation"] != after["generation"])
    if module_path:
        check("UI rejects superseded queries", not module.current_solver_sources(before, after))
except BaseException as error:
    errors.append(type(error).__name__)

(Path(os.environ["IDAUSR"]).parent / "solver_evidence.json").write_text(
    json.dumps({"checks": checks, "errors": errors, "captures": captures}, indent=2) + "\n")
line = "[chernobog][solver-evidence] " + ("FAIL " + "; ".join(errors) if errors else "PASS checks=%d" % len(checks))
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
