"""Real protected push/RET path plus explicit x86/x64 decoder boundaries."""

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
    entries = {
        name: int(ea, 0) for name, ea in json.loads(os.environ["CHERNOBOG_CORPUS_ENTRIES"]).items()
    }
    ea = entries["corpus_branch"]
    full = api("chernobog_vm_summaries", ea)
    captures["protected"] = full
    check("one seed-one protected path", len(full["records"]) == 1)
    row = full["records"][0]
    spans = [
        (int(address, 0), int(size))
        for address, size in (
            part.split(":") for part in row["instruction_spans"].split(";") if part
        )
    ]
    check(
        "exact source roles and transfer",
        [
            row[k]
            for k in ("vip_register", "value_register", "key_register", "dispatch_base_register")
        ]
        == ["5", "9", "8", "11"]
        and row["transfer_kind"] == "push/near-return",
    )
    check(
        "actual 25 instruction path retained",
        len(spans) == 25
        and spans[-1][0] == int(row["dispatch"], 0)
        and ida_bytes.get_bytes(*spans[-1]) == bytes.fromhex("c3"),
    )
    check(
        "exact ordered source bytes",
        row["bytes"] == "".join(ida_bytes.get_bytes(*span).hex() for span in spans),
    )
    check(
        "ownerless path stays ownerless",
        all(ida_funcs.get_func(address) is None for address, _ in spans),
    )
    check(
        "protected path is complete within budgets",
        not full["path_scan_truncated"] and not full["reachability_truncated"],
    )
    summary = full["summaries"][0]
    check(
        "seven accesses include target push and return read",
        summary["accesses"] == "7"
        and summary["access_5_kind"] == "write"
        and summary["access_6_kind"] == "read"
        and summary["access_5_bits"] == summary["access_6_bits"] == "64",
    )
    check("shadow-stack assumption explicit", "CET shadow stack disabled" in summary["contract"])
    check(
        "local model does not admit execution",
        "not admitted" in summary["transition"] and "no VM execution" in row["ownership"],
    )
    check(
        "unmodeled other seed-one prefix remains unresolved",
        not api("chernobog_vm_regions", entries["corpus_transform"])["records"],
    )
    module_path = os.environ["CHERNOBOG_VIEW_MODULE"]
    spec = importlib.util.spec_from_file_location("vm_stack_view_test", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if ida_kernwin.is_idaq():
        from PySide6 import QtWidgets

        form = module.EvidenceForm(ea, module.load_inspection(ea))
        form.Show("Protected stack dispatch test", options=ida_kernwin.PluginForm.WOPN_PERSIST)
        form.parent.window().show()
        QtWidgets.QApplication.processEvents()
        form.poll()
        form.tabs.setCurrentWidget(form.tables["vm"])
        form.select_record(row)
        check("GUI retains current local recognition", row["vm_candidate"] in form.vm_current)
        check(
            "GUI exposes transfer and stack contract",
            "push/near-return" in form.detail.toPlainText()
            and "CET shadow stack disabled" in form.detail.toPlainText(),
        )
        check("GUI has no invented execution edges", not form.current and not form.edges)
        form.parent.window().resize(1600, 1000)
        QtWidgets.QApplication.processEvents()
        form.parent.grab().save(str(Path(os.environ["IDAUSR"]).parent / "vm_stack_dispatch.png"))
        form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
        QtWidgets.QApplication.processEvents()
        check("GUI closes polling", form.closed and not form.timer.isActive())
    dispatch = spans[-1][0]
    ida_bytes.patch_byte(dispatch, 0xCB)
    check(
        "far-return patch revokes protected candidate",
        not api("chernobog_vm_regions", ea)["records"],
    )
    check(
        "UI rejects changed return bytes",
        not module.current_vm_candidates(full, api("chernobog_vm_regions", ea)),
    )
    ida_bytes.patch_byte(dispatch, 0xC3)
    check(
        "restoring return restores candidate",
        api("chernobog_vm_regions", ea)["records"] == full["records"],
    )
    assert ida_xref.add_cref(
        entries["corpus_transform"], dispatch, ida_xref.fl_JN | ida_xref.XREF_USER
    )
    check(
        "alternate return entry rejects protected path",
        not api("chernobog_vm_regions", ea)["records"],
    )
    ida_xref.del_cref(entries["corpus_transform"], dispatch, False)
    check(
        "removing alternate entry restores protected path",
        api("chernobog_vm_regions", ea)["records"] == full["records"],
    )
    for mode, base in ((32, 0x50000000), (64, 0x51000000)):
        assert ida_segment.getseg(base) is None
        assert ida_segment.add_segm(0, base, base + 0x10000, "stack_dispatch_" + str(mode), "CODE")
        segment = ida_segment.getseg(base)
        segment.perm, segment.bitness = 5, 1 if mode == 32 else 2
        assert ida_segment.update_segm(segment)
        table = "0fb606" + ("83c601" if mode == 32 else "4883c601")
        relative = "8b06" + ("83c60401c7" if mode == 32 else "4883c6044863c04801c7")
        table_push = "ff348500300000" if mode == 32 else "ff34c7"
        cases = {
            "table": table + table_push + "c3",
            "relative": relative + "57c3",
            "ret16": relative + "5766c3",
            "ret_adjust_zero": relative + "57c20000",
            "ret_adjust_eight": relative + "57c20800",
            "far": relative + "57cb",
            "far_adjust": relative + "57ca0800",
            "address_override": relative + "5767c3",
            "repeat_prefix": relative + "57f3c3",
            "push16": relative + "6657c3",
            "no_target_push": relative + "c3",
        }
        for index, (name, hexcode) in enumerate(cases.items()):
            start = base + index * 0x100
            code = bytes.fromhex(hexcode)
            ida_bytes.put_bytes(start, code)
            cursor = start
            while cursor < start + len(code):
                size = ida_ua.create_insn(cursor)
                assert size > 0
                cursor += size
            assert ida_funcs.add_func(start, start + len(code))
            result = api("chernobog_vm_summaries", start)
            captures[str(mode) + "_" + name] = result
            positive = name in ("table", "relative")
            check(str(mode) + " " + name + " admission", len(result["records"]) == int(positive))
            check(
                str(mode) + " " + name + " inspection preserves bytes",
                ida_bytes.get_bytes(start, len(code)) == code,
            )
            if positive:
                candidate = result["records"][0]
                effects = result["summaries"][0]
                check(
                    str(mode) + " " + name + " widths/stack effects",
                    candidate["transfer_kind"] == "push/near-return"
                    and candidate["address_bits"] == str(mode)
                    and effects["accesses"] == ("4" if name == "table" else "3"),
                )
                check(
                    str(mode) + " " + name + " selected-function candidate",
                    candidate["site"] == hex(start)
                    and candidate["dispatch"] == hex(start + len(code) - 1),
                )
except Exception as error:
    errors.append(type(error).__name__)
    captures["exception_frames"] = [
        {"function": f.name, "line": f.lineno} for f in traceback.extract_tb(error.__traceback__)
    ]

(Path(os.environ["IDAUSR"]).parent / "vm_stack_dispatch.json").write_text(
    json.dumps({"checks": checks, "errors": errors, "captures": captures}, indent=2) + "\n"
)
line = "[chernobog][vm-stack-dispatch] " + ("FAIL" if errors else "PASS")
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
