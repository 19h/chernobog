"""Production capture and GUI validation for partial VM-role observations."""
import importlib.util
import json
import os
import sys
from pathlib import Path
import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro
import ida_ua

sys.dont_write_bytecode = True
checks, errors, captures = [], [], {}


def check(name, value):
    checks.append({"case": name, "passed": bool(value)})
    if not value:
        errors.append(name)


def evaluate(expression):
    v = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(v, ida_idaapi.BADADDR, expression)
    return v.c_str() if v.vtype == ida_expr.VT_STR else v.num


def api(name, ea):
    return json.loads(evaluate(f"{name}({ea})"))


def address(name):
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "_vm_observe" + name)
    assert ea != ida_idaapi.BADADDR
    return ea


try:
    ida_auto.auto_wait()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    for name in ("", "_boundary", "_outside"):
        start, end = address(name), address(name + "_end")
        for ea in range(start, end):
            f = ida_funcs.get_func(ea)
            if f and f.start_ea >= start:
                ida_funcs.del_func(f.start_ea)
        ea = start
        while ea < end:
            size = ida_ua.create_insn(ea)
            assert size > 0
            ea += size
        assert ida_funcs.add_func(start, end)
    target = address("")
    check("no fabricated capture", not api("chernobog_vm_states", target)["states_available"])
    evaluate(f"chernobog_rax_explore({target})")
    captured = api("chernobog_vm_states", target)
    captures["repeated"] = captured
    evidence = api("chernobog_evidence_view", target)
    captures["raw"] = evidence
    rows = captured["states"]
    check("fresh joined capture", captured["states_available"] and evidence["fresh"]
          and captured["revision"] == evidence["revision"] and len(rows) == 12)
    check("one native candidate", len(captured["records"]) == 1
          and len({r["vm_candidate"] for r in rows}) == 1)
    check("all visits remain distinct", len({r["vm_state"] for r in rows}) == 12)
    base = address("_bytes")
    for run in sorted({r["run"] for r in rows}):
        group = [r for r in rows if r["run"] == run]
        check("VIP progression " + run, [int(r["entry_vip"], 0) for r in group] == [base, base+1, base+2])
        check("key progression " + run, [r["entry_key"] for r in group] == ["0x5a", "0x58", "0x58"])
        check("output decode " + run, [r["output_decoded_register"] for r in group] == ["0x2", "0x0", "0x1"])
    check("observed local path", bool(rows) and all(r["path"] == "sampled local address/size path" for r in rows))
    check("memory access order", bool(rows) and all(r["accesses_captured"] == "2"
          and r["access_0_kind"] == r["access_1_kind"] == "read"
          and r["access_0_size_bytes"] == "1" and r["access_1_size_bytes"] == "8" for r in rows))
    check("unknown VM identity remains explicit", bool(rows) and all(r["virtual_stack"] == r["vm_context"] == r["memory_epoch"] == "unknown"
          and r["logical_state_complete"] == "false" and r["merge"] == "not admitted"
          and r["semantic_validation"] == "not performed" for r in rows))
    before = api("chernobog_solver_evidence", target)
    check("repeatable pure projection", api("chernobog_vm_states", target) == captured
          and api("chernobog_solver_evidence", target) == before)
    original = ida_bytes.get_byte(base)
    ida_bytes.patch_byte(base, original ^ 1)
    stale = api("chernobog_vm_states", target)
    check("consumed data patch prevents fresh role join", not stale["states_available"] and not stale["states"])
    ida_bytes.patch_byte(base, original)
    check("exact restoration", api("chernobog_vm_states", target) == captured)
    module_path = os.environ["CHERNOBOG_VIEW_MODULE"]
    spec = importlib.util.spec_from_file_location("vm_state_view_test", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    state = api("chernobog_evidence_state", target)
    check("UI publication identity", module.current_snapshot(captured, state)
          and not module.current_snapshot(captured, dict(state, revision="0x0"))
          and not module.current_snapshot(captured, dict(state, database="foreign")))
    if ida_kernwin.is_idaq():
        from PySide6 import QtWidgets
        form = module.EvidenceForm(target, module.load_inspection(target))
        form.Show("Chernobog VM state test", options=ida_kernwin.PluginForm.WOPN_PERSIST)
        form.parent.window().show()
        form.parent.window().activateWindow()
        QtWidgets.QApplication.processEvents()
        form.tabs.setCurrentWidget(form.tables["vm_states"])
        form.tables["vm_states"].setCurrentItem(form.tables["vm_states"].topLevelItem(0))
        check("GUI displays captured states", form.tables["vm_states"].topLevelItemCount() == 12
              and form.jump.isEnabled() and "Virtual stack, VM context and memory epoch: unknown" in form.detail.toPlainText())
        check("state selection links its run", form.run == (rows[0]["run"], rows[0]["seed"])
              and form.tables["events"].topLevelItemCount() == len(module.matching_events(evidence, run=form.run)))
        proof_before = api("chernobog_solver_evidence", target)
        form.poll()
        check("polling does not run solver", proof_before == api("chernobog_solver_evidence", target))
        ida_bytes.patch_byte(base, original ^ 1)
        form.poll()
        check("stale join disables navigation", not form.jump.isEnabled()
              and form.tables["vm_states"].topLevelItemCount() == 12)
        ida_bytes.patch_byte(base, original)
        form.poll()
        check("restored join revalidates navigation", form.jump.isEnabled())
        instruction = address("_dispatch")
        byte = ida_bytes.get_byte(instruction)
        ida_bytes.patch_byte(instruction, 0x90)
        form.poll()
        check("changed candidate disables state navigation", not form.jump.isEnabled())
        ida_bytes.patch_byte(instruction, byte)
        form.poll()
        check("restored candidate navigation", form.jump.isEnabled())
        form.parent.window().resize(1600, 1000)
        QtWidgets.QApplication.processEvents()
        form.fit_graph()
        QtWidgets.QApplication.processEvents()
        form.parent.grab().save(str(Path(os.environ["IDAUSR"]).parent / "vm_states.png"))
        evaluate("chernobog_rax_clear()")
        evaluate(f"chernobog_rax_explore({target})")
        form.poll()
        check("superseded publication disables old join", not form.jump.isEnabled())
        form.reload()
        form.select_record(form.vm_states["states"][0])
        check("explicit reload admits new publication", form.jump.isEnabled())
        form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
        QtWidgets.QApplication.processEvents()
        check("close stops polling", form.closed and not form.timer.isActive())
    boundary = address("_boundary")
    check("foreign function cannot borrow capture", not api("chernobog_vm_states", boundary)["states_available"])
    evaluate(f"chernobog_rax_explore({boundary})")
    b = api("chernobog_vm_states", boundary)
    raw = api("chernobog_evidence_view", boundary)
    captures["boundary"], captures["boundary_raw"] = b, raw
    check("boundary output sampled", b["states_available"] and len(b["states"]) == 4
          and all(r["exit"].startswith("function-boundary") and r["target"] == hex(address("_outside")) for r in b["states"]))
    executed = [r for r in raw["events"] if r["kind"] == "execute"]
    accesses = [r for r in raw["events"] if r["kind"] == "memory"]
    check("boundary target not executed", bool(executed) and bool(accesses)
          and all(r["site"] != hex(address("_outside")) for r in executed)
          and all(r["address"] != hex(address("_marker")) for r in accesses)
          and not raw["omitted"].get("events", 0))
    check("boundary remains run stop", len(raw["runs"]) == 4 and all(r["kind"] == "function-boundary" for r in raw["runs"]))
    evaluate("chernobog_rax_clear()")
    check("cleared states unavailable", not api("chernobog_vm_states", boundary)["states_available"])
except BaseException as error:
    errors.append(type(error).__name__)

(Path(os.environ["IDAUSR"]).parent / "vm_observations.json").write_text(
    json.dumps({"checks": checks, "errors": errors, "captures": captures}, indent=2) + "\n")
line = "[chernobog][vm-observations] " + ("FAIL " + "; ".join(errors) if errors else "PASS checks=%d" % len(checks))
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
