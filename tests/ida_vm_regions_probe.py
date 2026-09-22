"""Exercise real IDA decoding, candidate bounds and view invalidation."""

import importlib.util
import json
import os
import sys
from pathlib import Path
import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro
import ida_ua
import ida_xref

sys.dont_write_bytecode = True
checks, errors, captures = [], [], {}
summary_captures = {}


def check(name, value):
    checks.append({"case": name, "passed": bool(value)})
    if not value:
        errors.append(name)


def api(name, ea):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"{name}({ea})")
    return json.loads(value.c_str())


def snapshot(ea):
    return api("chernobog_vm_regions", ea)


try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    names = [
        "table_forward",
        "table_clone",
        "table_backward",
        "relative_backward",
        "relative_forward",
        "bad_stride",
        "bad_alias",
        "bad_extension",
        "quota",
        "scan_limit",
        "semantic_groups",
    ]
    targets = {}
    for name in names:
        start = ida_name.get_name_ea(ida_idaapi.BADADDR, "_vm_" + name)
        end = ida_name.get_name_ea(ida_idaapi.BADADDR, "_vm_" + name + "_end")
        assert start != ida_idaapi.BADADDR and start < end
        # Fixture layout is explicit: disconnected indirect dispatch suffixes
        # belong to one declared test range. This does not infer VM ownership.
        for ea in range(start, end):
            owner = ida_funcs.get_func(ea)
            if owner and owner.start_ea >= start:
                ida_funcs.del_func(owner.start_ea)
        ea = start
        while ea < end:
            size = ida_ua.create_insn(ea)
            assert size > 0
            ea += size
        assert ida_funcs.add_func(start, end)
        targets[name] = start
        before = ida_bytes.get_bytes(start, end - start)
        data = snapshot(start)
        captures[name] = data
        check(
            name + " inspection read-only and repeatable",
            before == ida_bytes.get_bytes(start, end - start) and data == snapshot(start),
        )
        expected = (
            0
            if name.startswith("bad_") or name == "scan_limit"
            else 64 if name == "quota" else 4 if name == "semantic_groups" else 1
        )
        check(name + " candidate count", len(data["records"]) == expected)
        check(
            name + " no semantic or execution admission",
            all(
                r["truth"] == "candidate"
                and r["summary_reuse"].startswith("unproved")
                and "no VM execution" in r["ownership"]
                and "target" not in r
                for r in data["records"]
            ),
        )
        full = api("chernobog_vm_summaries", start)
        summary_captures[name] = full
        check(
            name + " summary inspection retains candidate bytes",
            data["records"] == full["records"]
            and before == ida_bytes.get_bytes(start, end - start),
        )
        check(
            name + " summaries retain normal-completion contract",
            all(
                "normal completion" in r["contract"]
                and "ordered data" in r["memory"]
                and "not admitted" in r["transition"]
                for r in full["summaries"]
            ),
        )
    a, b = captures["table_forward"]["records"][0], captures["table_clone"]["records"][0]
    check(
        "renamed clone preserves normalized syntax",
        a["normalized_shape"] == b["normalized_shape"]
        and a["vip_register"] != b["vip_register"]
        and a["bytes"] != b["bytes"],
    )
    check(
        "backward predecrement recognized",
        captures["table_backward"]["records"][0]["direction"] == "backward",
    )
    r = captures["relative_backward"]["records"][0]
    check(
        "relative decode retains width-specific key update",
        r["read_bits"] == "32"
        and r["stack_key_update"] == ("true" if r["address_bits"] == "64" else "false")
        and r["dispatch_kind"] == "relative register",
    )
    check(
        "candidate quota reports exact omissions",
        captures["quota"]["omitted"] == 6 and not captures["quota"]["truncated"],
    )
    check(
        "scan exhaustion explicit",
        captures["scan_limit"]["truncated"] and captures["scan_limit"]["instructions"] == 1024,
    )
    groups = summary_captures["semantic_groups"]
    bindings = groups["summary_bindings"]
    check(
        "production modeled-effect references deduplicate",
        len(groups["summaries"]) == 2 and len(bindings) == 4,
    )
    check(
        "register-renamed clone reuses after UNSAT",
        bindings[1]["status"] == "reused after UNSAT"
        and bindings[1]["summary_id"] == bindings[0]["summary_id"],
    )
    check(
        "distinct syntax reuses after UNSAT",
        bindings[2]["status"] == "reused after UNSAT"
        and groups["records"][2]["normalized_shape"] != groups["records"][0]["normalized_shape"],
    )
    check(
        "changed decode has separate reference",
        bindings[3]["status"] == "reference"
        and bindings[3]["summary_id"] != bindings[0]["summary_id"]
        and "SAT:" in bindings[3]["reason"],
    )
    query_rows = api("chernobog_solver_evidence", targets["semantic_groups"])["records"]
    check(
        "summary proofs are real scoped SMT queries",
        len(query_rows) == 3
        and all(
            r["phase"] == "vm-local-summary" and r["role"] == "VM local summary effect mismatch"
            for r in query_rows
        )
        and [r["result"] for r in query_rows] == ["unsat", "unsat", "sat"],
    )
    quota = summary_captures["quota"]
    check(
        "summary bounds report scanned omissions",
        len(quota["summary_bindings"]) == 16
        and quota["summary_omitted"] == 54
        and quota["comparison_attempts"] == 15,
    )
    target = targets["table_forward"]
    # A code entry into the middle invalidates the local single-entry contract.
    inside = ida_bytes.next_head(target, ida_idaapi.BADADDR)
    assert ida_xref.add_cref(targets["bad_stride"], inside, ida_xref.fl_JN | ida_xref.XREF_USER)
    check("alternate entry rejects candidate", not snapshot(target)["records"])
    ida_xref.del_cref(targets["bad_stride"], inside, False)
    check(
        "removing alternate entry restores candidate", snapshot(target) == captures["table_forward"]
    )
    module_path = os.environ.get("CHERNOBOG_VIEW_MODULE")
    assert module_path
    spec = importlib.util.spec_from_file_location("vm_view_test", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    saved = captures["table_forward"]
    check(
        "UI accepts recomputed candidate",
        a["vm_candidate"] in module.current_vm_candidates(saved, snapshot(target)),
    )
    check(
        "UI rejects foreign database",
        not module.current_vm_candidates(saved, dict(saved, database="foreign")),
    )
    byte = ida_bytes.get_byte(target)
    ida_bytes.patch_byte(target, 0x90)
    check(
        "changed decode invalidates candidate",
        not module.current_vm_candidates(saved, snapshot(target)),
    )
    ida_bytes.patch_byte(target, byte)
    check(
        "restoration permits candidate navigation",
        a["vm_candidate"] in module.current_vm_candidates(saved, snapshot(target)),
    )
    if ida_kernwin.is_idaq():
        from PySide6 import QtWidgets

        form = module.EvidenceForm(target, module.load_inspection(target))
        form.Show("Chernobog VM candidates test", options=ida_kernwin.PluginForm.WOPN_PERSIST)
        form.parent.window().show()
        form.parent.window().activateWindow()
        QtWidgets.QApplication.processEvents()
        form.tabs.setCurrentWidget(form.tables["vm"])
        form.select_record(a)
        check(
            "candidate-only view opens",
            not form.current
            and form.jump.isEnabled()
            and form.tables["vm"].topLevelItemCount() == 1,
        )
        check(
            "VM detail states unresolved contracts",
            "Unresolved:" in form.detail.toPlainText()
            and "Syntax grouping: unproved" in form.detail.toPlainText(),
        )
        check("VM recognition creates no proof edge", not form.edges)
        ida_bytes.patch_byte(target, 0x90)
        form.poll()
        check("stale VM navigation disabled", not form.jump.isEnabled())
        ida_bytes.patch_byte(target, byte)
        form.poll()
        check("restored candidate navigation", form.jump.isEnabled())
        form.parent.window().resize(1600, 1000)
        QtWidgets.QApplication.processEvents()
        form.fit_graph()
        QtWidgets.QApplication.processEvents()
        form.parent.grab().save(str(Path(os.environ["IDAUSR"]).parent / "vm_regions.png"))
        form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
        QtWidgets.QApplication.processEvents()
        check("VM form closes polling", form.closed and not form.timer.isActive())
        group_ea = targets["semantic_groups"]
        form = module.EvidenceForm(group_ea, module.load_inspection(group_ea))
        form.Show("Chernobog VM effects test", options=ida_kernwin.PluginForm.WOPN_PERSIST)
        form.parent.window().show()
        form.parent.window().activateWindow()
        QtWidgets.QApplication.processEvents()
        form.tabs.setCurrentWidget(form.tables["vm"])
        selected = groups["records"][2]
        form.select_record(selected)
        check(
            "GUI exposes proof-gated local reuse",
            "Modeled local effects: reused after UNSAT" in form.detail.toPlainText()
            and '"sources_current": true' in form.detail.toPlainText(),
        )
        proof_before = api("chernobog_solver_evidence", group_ea)
        form.poll()
        check(
            "GUI polling never reruns solver",
            proof_before == api("chernobog_solver_evidence", group_ea),
        )
        reference = int(groups["records"][0]["site"], 0)
        original = ida_bytes.get_byte(reference)
        ida_bytes.patch_byte(reference, 0x90)
        form.poll()
        check(
            "reference invalidation does not borrow candidate freshness",
            form.jump.isEnabled() and '"sources_current": false' in form.detail.toPlainText(),
        )
        ida_bytes.patch_byte(reference, original)
        form.poll()
        check(
            "restored reference revalidates local summary sources",
            '"sources_current": true' in form.detail.toPlainText(),
        )
        form.parent.window().resize(1600, 1000)
        QtWidgets.QApplication.processEvents()
        form.fit_graph()
        QtWidgets.QApplication.processEvents()
        form.parent.grab().save(str(Path(os.environ["IDAUSR"]).parent / "vm_summaries.png"))
        form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
        QtWidgets.QApplication.processEvents()
        check("summary form closes polling", form.closed and not form.timer.isActive())
except BaseException as error:
    errors.append(type(error).__name__)

(Path(os.environ["IDAUSR"]).parent / "vm_regions.json").write_text(
    json.dumps(
        {
            "checks": checks,
            "errors": errors,
            "captures": captures,
            "summary_captures": summary_captures,
        },
        indent=2,
    )
    + "\n"
)
line = "[chernobog][vm-regions] " + (
    "FAIL " + "; ".join(errors) if errors else "PASS checks=%d" % len(checks)
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
