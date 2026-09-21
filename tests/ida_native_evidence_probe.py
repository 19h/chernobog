"""Inspect live native conclusions without promoting annotations or receipts."""
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
import ida_xref
import idautils

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


def address(name):
    for label in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, label)
        if ea != ida_idaapi.BADADDR:
            return ea
    raise AssertionError("fixture symbol absent")


def inspect(ea):
    return json.loads(evaluate(f"chernobog_native_evidence({ea})"))


def database_observables(ea):
    return [(int(site), ida_bytes.get_bytes(site, ida_bytes.get_item_size(site)),
             ida_bytes.get_cmt(site, True), ida_bytes.get_cmt(site, False),
             sorted((int(x.to), int(x.type)) for x in idautils.XrefsFrom(site)))
            for site in idautils.FuncItems(ea)]


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    mode = os.environ["CHERNOBOG_NATIVE_FIXTURE"]
    cases = {
        "stack": {"vt_reg": "stack-transfer", "vt_mem": "stack-transfer", "vt_indexed": "stack-transfer",
                  "vt_unknown_reg": "candidate", "vt_alias": "candidate", "vt_writable": "candidate",
                  "vt_adjust": None, "vt_far": None, "vt_width": None, "vt_alternate": None},
        "flags": {"vf_e": "local-flag-branch", "vf_ne": "local-flag-branch", "vf_cmc": "local-flag-branch",
                  "vf_set_false": "setcc-value", "vf_set_true": "setcc-value",
                  "vf_cmov_false32": "cmov-condition", "vf_unknown_input": None,
                  "vf_unknown_carry": None, "vf_call_barrier": None, "vf_alternate_entry": None},
        "getpc": {"gp_materialize": "stack-address-materialization", "gp_renamed": "stack-address-materialization",
                  "gp_call": "get-pc-call", "gp_adjust": "get-pc-call"},
        "caps": {"ve_many": "local-flag-branch", "ve_deep": "local-flag-branch"},
    }[mode]
    for name, expected in cases.items():
        ea = address(name)
        before = database_observables(ea)
        capture = inspect(ea)
        again = inspect(ea)
        captures[name] = capture
        rows = capture["records"]
        if expected is None:
            check(name + " no invented proof", not rows)
        else:
            admitted = [r for r in rows if (r["truth"] == "candidate" if expected == "candidate" else r["kind"] == expected)]
            check(name + " current typed conclusion", admitted and all(r["fresh"] == "true" for r in admitted))
            check(name + " dependency detail", admitted and all(int(r["dependency_count"]) > 0
                  and r["dependency_0"] and r["assumption"] and r["publication"] != "0x0" for r in admitted))
            if expected == "candidate":
                check(name + " unresolved has no edge", all(r["edge"] == "false" and "target" not in r for r in admitted))
            if expected == "stack-transfer":
                check(name + " target and retained stack write", all(r["target"] == hex(address("vt_target"))
                      and r["width_bits"] == "64" and r["stack_delta_bytes"] == "0"
                      and r["stack_write_bytes"] == "8" for r in admitted))
        check(name + " inspection is stable and read-only", before == database_observables(ea) and capture == again)
    if mode == "caps":
        many, deep = captures["ve_many"], captures["ve_deep"]["records"][0]
        check("native proof quota counts every omitted conclusion", len(many["records"]) == 128 and many["omitted"] == 12)
        check("native dependency quota is explicit", int(deep["dependency_count"]) > 64
              and int(deep["dependencies_omitted"]) == int(deep["dependency_count"]) - 64
              and len([k for k in deep if k.startswith("dependency_") and k != "dependency_count"]) == 64)
    if mode == "getpc":
        for name in ("gp_call", "gp_adjust"):
            check(name + " context-specific return is linked to caller", any(r["kind"] == "call-context-return"
                  and r["fresh"] == "true" and r["context_call"] == hex(address(name))
                  and "CALL" in r["effect_scope"] for r in captures[name]["records"]))
    first = next(iter(cases))
    target = address(first)
    saved = captures[first]
    assert saved["records"]
    observed = saved["records"][0]
    pub = observed["publication"]
    dependent = int(observed["dependency_0"].split(":", 1)[0], 0)
    original = ida_bytes.get_byte(dependent)
    ida_bytes.patch_byte(dependent, original ^ 1)
    stale = inspect(target)
    check("consumed-byte patch revokes inspected publication", not any(r["publication"] == pub
          and r["fresh"] == "true" for r in stale["records"]))
    ida_bytes.patch_byte(dependent, original)
    function = ida_funcs.get_func(target)
    ida_auto.plan_range(function.start_ea, function.end_ea)
    ida_auto.auto_wait()
    renewed = inspect(target)
    check("restoration requires a new live publication", any(r["source"] == observed["source"]
          and r["site"] == observed["site"] and r["kind"] == observed["kind"]
          and r["fresh"] == "true" and r["publication"] != pub for r in renewed["records"]))
    check("non-function request unavailable", not inspect(ida_idaapi.BADADDR)["available"])
    if mode == "flags":
        for name, value in (("vf_set_false", "0x0"), ("vf_set_true", "0x1")):
            check(name + " exact byte result", any(r["kind"] == "setcc-value" and r["value"] == value
                  and r["width_bits"] == "8" for r in captures[name]["records"]))
        unknown = address("vf_unknown_input")
        old_comment = ida_bytes.get_cmt(unknown, True)
        ida_bytes.set_cmt(unknown, "[chernobog][ida-analysis] locally proven x86 flags", True)
        check("annotation text cannot create a proof", not inspect(unknown)["records"])
        ida_bytes.set_cmt(unknown, old_comment or "", True)
    module_path = os.environ.get("CHERNOBOG_VIEW_MODULE")
    if module_path:
        spec = importlib.util.spec_from_file_location("native_evidence_ui_test", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        check("old native capture rejects replacement publication", pub not in module.current_native_publications(saved, renewed))
        check("native capture rejects foreign database", not module.current_native_publications(
              renewed, dict(renewed, database="different")))
        check("native capture rejects modified conclusion", not module.current_native_publications(
              renewed, dict(renewed, records=[dict(r, conclusion="changed") for r in renewed["records"]])))
        if ida_kernwin.is_idaq():
            from PySide6 import QtWidgets
            snapshot = module.load_inspection(target)
            check("native inspection works without rax capture", not snapshot["available"] and snapshot["native"]["records"])
            form = module.EvidenceForm(target, snapshot)
            form.Show("Chernobog native evidence test", options=ida_kernwin.PluginForm.WOPN_PERSIST)
            form.parent.window().show()
            form.parent.window().activateWindow()
            QtWidgets.QApplication.processEvents()
            record = snapshot["native"]["records"][0]
            form.select_record(record)
            check("native proof has independent current navigation", not form.current
                  and form.record_current(record) and form.jump.isEnabled())
            check("native proof pane has supporting bytes", record["dependency_0"] in form.detail.toPlainText())
            edges = [item for item in form.scene.items() if isinstance(item, module.FlowEdge)]
            check("native edge retains its proof category", all(e.row["truth"] == "native-proof" for e in edges)
                  and (bool(edges) if record["edge"] == "true" else True))
            ida_bytes.patch_byte(dependent, original ^ 1)
            form.poll()
            check("native stale navigation disabled", not form.record_current(record) and not form.jump.isEnabled())
            check("native table labels invalidated record", "historical" in form.tables["native"].topLevelItem(0).text(2))
            ida_bytes.patch_byte(dependent, original)
            ida_auto.plan_range(function.start_ea, function.end_ea)
            ida_auto.auto_wait()
            form.poll()
            check("old native view stays historical after reanalysis", not form.record_current(record))
            form.reload()
            check("explicit reload admits renewed native proof", bool(form.native_current))
            form.parent.window().resize(1500, 950)
            QtWidgets.QApplication.processEvents()
            form.select_record(form.native["records"][0])
            form.tabs.setCurrentWidget(form.tables["native"])
            QtWidgets.QApplication.processEvents()
            form.parent.grab().save(str(Path(os.environ["IDAUSR"]).parent / "native_evidence.png"))
            form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
            QtWidgets.QApplication.processEvents()
            check("native view closes polling", form.closed and not form.timer.isActive())
except BaseException as error:
    errors.append(type(error).__name__)

(Path(os.environ["IDAUSR"]).parent / "native_evidence.json").write_text(
    json.dumps({"checks": checks, "errors": errors, "captures": captures}, indent=2) + "\n")
line = "[chernobog][native-evidence] " + ("FAIL " + "; ".join(errors) if errors else "PASS checks=%d" % len(checks))
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
