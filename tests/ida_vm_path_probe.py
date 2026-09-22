"""Actual protected paths: recognition, summaries, boundaries and freshness."""
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
import ida_ua
import ida_xref

sys.dont_write_bytecode = True
checks, errors, captures = [], [], {}


def check(name, value):
    checks.append({"case": name, "passed": bool(value)})
    if not value:
        errors.append(name)


def api(name, ea):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"{name}({ea})")
    return json.loads(value.c_str())


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, "chernobog_native_analysis()")
    ida_auto.auto_wait()
    entries = {name: int(ea, 0) for name, ea in json.loads(os.environ["CHERNOBOG_CORPUS_ENTRIES"]).items()}
    expected = {"corpus_transform": (11, 0, 8, 10, "backward"), "corpus_branch": (6, 8, 7, 10, "forward")}
    module_path = os.environ.get("CHERNOBOG_VIEW_MODULE")
    module = None
    if module_path:
        spec = importlib.util.spec_from_file_location("vm_path_view_test", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    for name, ea in entries.items():
        plain = api("chernobog_vm_regions", ea)
        full = api("chernobog_vm_summaries", ea)
        captures[name] = full
        check(name + " one real protected candidate", len(full["records"]) == 1)
        candidate = full["records"][0]
        spans = [(int(address, 0), int(size)) for address, size in
                 (part.split(":") for part in candidate["instruction_spans"].split(";") if part)]
        check(name + " all source bytes retained", candidate["bytes"] == "".join(ida_bytes.get_bytes(address, size).hex() for address, size in spans))
        check(name + " physical jumps represented", any(a + size != b for (a, size), (b, _) in zip(spans, spans[1:])))
        check(name + " ownerless code stays ownerless", all(ida_funcs.get_func(address) is None for address, _ in spans))
        roles = tuple(int(candidate[k]) for k in ("vip_register", "value_register", "key_register", "dispatch_base_register"))
        check(name + " source-specific roles and direction", roles == expected[name][:4] and candidate["direction"] == expected[name][4])
        check(name + " complete local effect summary", len(full["summaries"]) == 1 and full["summary_bindings"][0]["status"] == "reference")
        summary = full["summaries"][0]
        check(name + " stack and memory effects preserved", summary["accesses"] == "5" and "ordered" in summary["memory"])
        check(name + " no execution admission", "no VM execution" in candidate["ownership"] and "not admitted" in summary["transition"])
        check(name + " no budget exhaustion", not full["path_scan_truncated"] and not full["reachability_truncated"])
        check(name + " read-only repeatable recognition", plain["records"] == full["records"] == api("chernobog_vm_regions", ea)["records"])
        # Inspect the untouched input before mutation controls enqueue IDA
        # ownership analysis that can run during Qt event processing.
        if module and ida_kernwin.is_idaq() and name == "corpus_transform":
            from PySide6 import QtWidgets
            gui_snapshot = module.load_inspection(ea)
            captures["gui_inspection"] = gui_snapshot["vm"]
            form = module.EvidenceForm(ea, gui_snapshot)
            form.Show("Protected VM path test", options=ida_kernwin.PluginForm.WOPN_PERSIST)
            form.parent.window().show()
            QtWidgets.QApplication.processEvents()
            form.poll()
            form.tabs.setCurrentWidget(form.tables["vm"])
            form.select_record(candidate)
            captures["gui_detail"] = form.detail.toPlainText()
            check("GUI recognition remains current after event processing", candidate["vm_candidate"] in form.vm_current)
            check("GUI shows complete local model and path provenance", "Modeled local effects: reference" in form.detail.toPlainText() and "instruction_spans" in form.detail.toPlainText())
            check("GUI keeps candidate separate from execution", not form.current and not form.edges)
            form.parent.window().resize(1600, 1000)
            QtWidgets.QApplication.processEvents()
            form.parent.grab().save(str(Path(os.environ["IDAUSR"]).parent / "vm_paths.png"))
            form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
            QtWidgets.QApplication.processEvents()
            check("GUI closes its poller", form.closed and not form.timer.isActive())
        remote = next(b for (a, size), (b, _) in zip(spans, spans[1:]) if a + size != b)
        before = ida_bytes.get_byte(remote)
        ida_bytes.patch_byte(remote, 0xCC)
        changed = api("chernobog_vm_regions", ea)
        check(name + " remote code patch revokes candidate", not changed["records"])
        if module:
            check(name + " UI rejects remote stale path", not module.current_vm_candidates(full, changed))
        ida_bytes.patch_byte(remote, before)
        check(name + " exact restoration restores recognition", api("chernobog_vm_regions", ea)["records"] == plain["records"])
        other = next(address for address in entries.values() if address != ea)
        assert ida_xref.add_cref(other, remote, ida_xref.fl_JN | ida_xref.XREF_USER)
        check(name + " alternate entry rejects path", not api("chernobog_vm_regions", ea)["records"])
        ida_xref.del_cref(other, remote, False)
        check(name + " alternate-entry removal restores path", api("chernobog_vm_regions", ea)["records"] == plain["records"])
        size = next(size for address, size in spans if address == remote)
        assert ida_funcs.add_func(remote, remote + size)
        foreign = api("chernobog_vm_regions", ea)
        check(name + " foreign function is a traversal stop", not foreign["records"] and foreign["foreign_function_stops"] >= 1)
        ida_funcs.del_func(remote)
        check(name + " removing foreign owner restores path", api("chernobog_vm_regions", ea)["records"] == plain["records"])
    base = (max(ida_segment.getnseg(i).end_ea for i in range(ida_segment.get_segm_qty())) + 0xFFFF) & ~0xFFFF
    assert ida_segment.add_segm(0, base, base + 0x1000, "vm_path_budget", "CODE")
    segment = ida_segment.getseg(base)
    segment.perm, segment.bitness = 5, 2
    assert ida_segment.update_segm(segment)
    payload = bytes.fromhex("0fb6064883c601") + bytes([0xF8]) * 130 + bytes.fromhex("ff24c7")
    ida_bytes.put_bytes(base, payload)
    cursor = base
    while cursor < base + len(payload):
        size = ida_ua.create_insn(cursor)
        assert size > 0
        cursor += size
    assert ida_funcs.add_func(base, base + len(payload))
    budget = api("chernobog_vm_regions", base)
    check("per-path exhaustion is explicit", not budget["records"] and budget["path_scan_truncated"])
    check("path and reachable-head budgets hold", budget["path_steps"] <= 8192 and budget["reachable_heads"] <= 1024)
    if module and ida_kernwin.is_idaq():
        from PySide6 import QtWidgets
        budget_form = module.EvidenceForm(base, module.load_inspection(base))
        budget_form.Show("VM path budget test", options=ida_kernwin.PluginForm.WOPN_PERSIST)
        QtWidgets.QApplication.processEvents()
        check("GUI reports path scan exhaustion", "scan truncated True" in budget_form.status.text())
        budget_form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
        QtWidgets.QApplication.processEvents()
        check("GUI budget form closes its poller", budget_form.closed and not budget_form.timer.isActive())
except Exception as error:
    errors.append(type(error).__name__)
    captures["exception_frames"] = [{"function": f.name, "line": f.lineno} for f in traceback.extract_tb(error.__traceback__)]

(Path(os.environ["IDAUSR"]).parent / "vm_paths.json").write_text(json.dumps({"checks": checks, "errors": errors, "captures": captures}, indent=2) + "\n")
line = "[chernobog][vm-path] " + ("FAIL" if errors else "PASS")
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
