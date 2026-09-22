"""Check modeled local transitions against real RAX captures in IDA."""

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
stack_dispatch = os.environ.get("CHERNOBOG_VM_STACK_DISPATCH") == "1"


def check(name, condition):
    checks.append({"case": name, "passed": bool(condition)})
    if not condition:
        errors.append(name)


def evaluate(expression):
    v = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(v, ida_idaapi.BADADDR, expression)
    return v.c_str() if v.vtype == ida_expr.VT_STR else v.num


def api(name, ea):
    return json.loads(evaluate(f"{name}({ea})"))


def address(suffix):
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "_vm_observe" + suffix)
    assert ea != ida_idaapi.BADADDR
    return ea


try:
    ida_auto.auto_wait()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    for suffix in ("", "_boundary", "_outside", "_relative"):
        start, end = address(suffix), address(suffix + "_end")
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
    for suffix, count in (("", 12), ("_boundary", 4), ("_relative", 4)):
        target = address(suffix)
        evaluate(f"chernobog_rax_explore({target})")
        before = api("chernobog_solver_evidence", target)
        observed = api("chernobog_vm_states", target)
        check(
            suffix + " pure state projection has no SMT",
            api("chernobog_solver_evidence", target) == before,
        )
        check(
            suffix + " complete direct trace",
            len(observed["states"]) == count
            and all(r["data_capture_complete"] == "true" for r in observed["states"]),
        )
        checked = api("chernobog_vm_transitions", target)
        proof = api("chernobog_solver_evidence", target)
        captures[suffix or "repeated"] = {
            "observed": observed,
            "checked": checked,
            "queries": proof,
        }
        check(
            suffix + " every local transition corroborated",
            len(checked["states"]) == count
            and all(
                r["semantic_validation"] == "corroborated for captured transition"
                for r in checked["states"]
            ),
        )
        check(
            suffix + " bounded real query counts",
            checked["transition_attempts"] == count and checked["transition_queries"] == 2 * count,
        )
        rows = [r for r in proof["records"] if r["phase"] == "vm-observed-transition"]
        check(
            suffix + " SAT inputs before UNSAT mismatch",
            len(rows) == 2 * count
            and [r["result"] for r in rows] == ["sat", "unsat"] * count
            and all(
                r["role"] in ("VM observed input consistency", "VM observed output mismatch")
                for r in rows
            ),
        )
        check(
            suffix + " queries identify exact check and visit",
            all(
                len(
                    [
                        q
                        for q in rows
                        if q.get("transition_check") == r["transition_check"]
                        and q.get("capture_revision") == r["revision"]
                        and all(q.get(k) == r[k] for k in ("run", "seed", "sequence", "site"))
                    ]
                )
                == 2
                for r in checked["states"]
            ),
        )
        check(
            suffix + " scope remains local and partial",
            all(
                r["logical_state_complete"] == "false"
                and r["merge"] == "not admitted"
                and "target execution not admitted" in r["transition_contract"]
                for r in checked["states"]
            ),
        )
        raw = api("chernobog_evidence_view", target)
        check(
            suffix + " run completeness visible",
            all(
                r["data_trace_complete"] == "true"
                and r["data_trace_truncated"] == r["data_trace_filtered"] == "false"
                for r in raw["runs"]
            ),
        )
        if stack_dispatch:
            check(
                suffix + " return contract visible",
                all(
                    "CET shadow stack disabled" in r["transition_contract"]
                    for r in checked["states"]
                ),
            )
            check(
                suffix + " target push and return read captured",
                all(
                    r["accesses_captured"] == ("7" if suffix == "_relative" else "4")
                    and r[f"access_{int(r['accesses_captured'])-2}_kind"] == "write"
                    and r[f"access_{int(r['accesses_captured'])-1}_kind"] == "read"
                    and r[f"access_{int(r['accesses_captured'])-2}_value_low64"] == r["target"]
                    and r[f"access_{int(r['accesses_captured'])-1}_value_low64"] == r["target"]
                    for r in checked["states"]
                ),
            )
        if suffix == "_boundary":
            check(
                "boundary preserved after corroboration",
                all(r["exit"].startswith("function-boundary") for r in checked["states"])
                and all(
                    r["boundary"] == "true" and r["context_complete"] == "false"
                    for r in raw["runs"]
                ),
            )
        if suffix == "_relative":
            kinds = ["read", "write", "read", "write", "read"] + (
                ["write", "read"] if stack_dispatch else []
            )
            check(
                "stack effects retain all ordered accesses",
                all(
                    r["accesses_captured"] == str(len(kinds))
                    and [r[f"access_{i}_kind"] for i in range(len(kinds))] == kinds
                    for r in checked["states"]
                ),
            )
            check(
                "relative signed value and key feedback",
                all(
                    r["output_decoded_register"] == "0xffffffffffffffe0"
                    and r["output_key"] == "0x11223344aa9988ba"
                    and r["output_native_sp"] == r["entry_native_sp"]
                    for r in checked["states"]
                ),
            )
            source = address("_relative_dispatch")
            byte = ida_bytes.get_byte(source)
            ida_bytes.patch_byte(source, 0x90)
            stale = api("chernobog_vm_transitions", target)
            check(
                "stale capture yields no checks",
                not stale["states_available"]
                and not stale["states"]
                and stale["transition_queries"] == 0
                and stale["transition_attempts"] == 0,
            )
            ida_bytes.patch_byte(source, byte)
            check(
                "restored capture permits explicit checks",
                api("chernobog_vm_transitions", target)["transition_queries"] == 8,
            )
    if ida_kernwin.is_idaq():
        from PySide6 import QtWidgets

        target = address("_relative")
        spec = importlib.util.spec_from_file_location(
            "vm_transition_view", os.environ["CHERNOBOG_VIEW_MODULE"]
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        form = module.EvidenceForm(target, module.load_inspection(target))
        form.Show("Chernobog VM transition test", options=ida_kernwin.PluginForm.WOPN_PERSIST)
        form.parent.window().show()
        form.parent.window().activateWindow()
        QtWidgets.QApplication.processEvents()
        form.tabs.setCurrentWidget(form.tables["vm_states"])
        form.tables["vm_states"].setCurrentItem(form.tables["vm_states"].topLevelItem(0))
        check(
            "Qt transition result and contract visible",
            "corroborated for captured transition" in form.detail.toPlainText()
            and "one captured normal-completion transition" in form.detail.toPlainText()
            and form.jump.isEnabled(),
        )
        check(
            "Qt result links its two SMT queries",
            '"transition_query_references"' in form.detail.toPlainText()
            and '"role": "VM observed input consistency"' in form.detail.toPlainText()
            and '"role": "VM observed output mismatch"' in form.detail.toPlainText(),
        )
        before = api("chernobog_solver_evidence", target)
        form.poll()
        check("Qt polling never repeats checks", api("chernobog_solver_evidence", target) == before)
        check(
            "Qt SMT tab includes real transition queries",
            any(r["phase"] == "vm-observed-transition" for r in form.queries["records"]),
        )
        source = address("_relative_dispatch")
        byte = ida_bytes.get_byte(source)
        ida_bytes.patch_byte(source, 0x90)
        form.poll()
        check(
            "historical result loses navigation",
            not form.jump.isEnabled()
            and "corroborated for captured transition" in form.detail.toPlainText(),
        )
        ida_bytes.patch_byte(source, byte)
        form.poll()
        check("restored result navigation", form.jump.isEnabled())
        form.parent.window().resize(1600, 1000)
        QtWidgets.QApplication.processEvents()
        form.fit_graph()
        QtWidgets.QApplication.processEvents()
        form.parent.grab().save(str(Path(os.environ["IDAUSR"]).parent / "vm_transitions.png"))
        form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
        QtWidgets.QApplication.processEvents()
        check("close stops polling", form.closed and not form.timer.isActive())
except BaseException as error:
    errors.append(type(error).__name__)

(Path(os.environ["IDAUSR"]).parent / "vm_transitions.json").write_text(
    json.dumps({"checks": checks, "errors": errors, "captures": captures}, indent=2) + "\n"
)
line = "[chernobog][vm-transitions] " + (
    "FAIL " + "; ".join(errors) if errors else "PASS checks=%d" % len(checks)
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
