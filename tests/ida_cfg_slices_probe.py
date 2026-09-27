"""Bounded predecessor facts in large owned functions and freshness controls."""

import json
import os
from pathlib import Path
import sys

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_loader
import ida_name
import ida_pro
import ida_ua
import ida_xref
import idautils

sys.dont_write_bytecode = True
records, errors, captures = [], [], {}
baseline = os.environ.get("CHERNOBOG_CFG_SLICE_BASELINE") == "1"
first_budget = os.environ.get("CHERNOBOG_CFG_SLICE_NO_QUERY_RESERVE") == "1"
depth = int(os.environ.get("CHERNOBOG_IDA_FLAG_SCAN_DEPTH", "8"))
register_depth = int(os.environ.get("CHERNOBOG_IDA_REGISTER_SCAN_DEPTH", "0")) or 64


def check(label, condition):
    records.append({"case": label, "passed": bool(condition)})
    if not condition:
        errors.append(label)


def address(name):
    for candidate in ("_" + name, name):
        value = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if value != ida_idaapi.BADADDR:
            return value
    raise AssertionError("fixture symbol missing: " + name)


def instructions(name):
    start, end = address(name), address(name + "_end")
    result = []
    cursor = start
    while cursor < end:
        instruction = ida_ua.insn_t()
        assert ida_ua.decode_insn(instruction, cursor) > 0
        assert ida_bytes.is_code(ida_bytes.get_flags(cursor))
        assert ida_funcs.get_func(cursor).start_ea == start
        result.append(instruction)
        cursor += instruction.size
    assert cursor == end
    return result


def inspect(name, label=None):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(
        value, ida_idaapi.BADADDR, f"chernobog_native_evidence({address(name)})"
    )
    result = json.loads(value.c_str())
    captures[label or name] = result
    return result


def conditions(snapshot):
    return [
        row
        for row in snapshot["records"]
        if row["kind"] == "setcc-value" and row["fresh"] == "true"
    ]


def transfers(snapshot):
    return [
        row
        for row in snapshot["records"]
        if row["kind"] == "stack-transfer" and row["fresh"] == "true"
    ]


def reanalyze(name):
    ida_auto.plan_and_wait(address(name), address(name + "_end"))
    ida_auto.auto_wait()


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    names = (
        "slice_equal192",
        "slice_different192",
        "slice_flags192",
        "slice_loop192",
        "slice_cut192",
        "slice_target192",
        "slice_memory192",
        "slice_inventory4096",
        "slice_inventory4097",
        "slice_prefix8",
    )
    ida_auto.auto_wait()
    native_bytes = {}
    for name in names:
        start, end = address(name), address(name + "_end")
        owner = ida_funcs.get_func(start)
        if owner is not None and owner.start_ea == start:
            if owner.end_ea != end:
                assert ida_funcs.set_func_end(start, end)
        else:
            assert owner is None and ida_funcs.add_func(start, end)
        cursor = start
        while cursor < end:
            length = ida_ua.create_insn(cursor)
            assert length > 0
            cursor += length
        assert cursor == end
        reanalyze(name)
        native_bytes[name] = ida_bytes.get_bytes(start, end - start)
        code = instructions(name)
        check(name + " has a large complete owned inventory", len(code) > 192)
        if name in ("slice_inventory4096", "slice_inventory4097"):
            check(name + " exact head count", len(code) == int(name[-4:]))
        snapshot = inspect(name)
        enabled = not baseline and depth >= 8
        expected = enabled and name in (
            "slice_equal192",
            "slice_flags192",
            "slice_loop192",
            "slice_inventory4096",
        )
        if name == "slice_prefix8":
            expected = depth >= 8 and not (first_budget and depth == 8)
        rows = conditions(snapshot)
        check(name + " exact condition admission", bool(rows) == expected)
        if rows:
            check(name + " exact condition value", len(rows) == 1 and rows[0]["value"] == "0x1")
            if not baseline:
                check(
                    name + " support retains every inventoried head",
                    int(rows[0]["dependency_count"]) == len(code),
                )
                check(
                    name + " display accounts for omitted dependencies",
                    int(rows[0]["dependencies_omitted"]) == len(code) - 64,
                )
        if name in ("slice_target192", "slice_memory192"):
            rows = transfers(snapshot)
            expected = not baseline and register_depth >= 8
            check(
                name + " exact transfer admission",
                len(rows) == 1 and (rows[0]["truth"] == "native-proof") == expected,
            )
            if expected:
                check(
                    name + " exact destination",
                    int(rows[0]["target"], 0) == address("slice_destination"),
                )
                check(
                    name + " actual destination edge",
                    any(
                        x.to == address("slice_destination") and x.iscode and x.user
                        for x in idautils.XrefsFrom(int(rows[0]["site"], 0))
                    ),
                )
    if not baseline and depth >= 8:
        name = "slice_equal192"
        code = instructions(name)
        join = next(i.ea for i in code if i.get_canon_mnem() == "cmp")
        source = address("slice_external")
        before = conditions(captures[name])[0]
        assert ida_xref.add_cref(source, join, ida_xref.fl_JN | ida_xref.XREF_USER)
        reanalyze(name)
        check("external slice entry revokes exact value", not conditions(inspect(name, "external")))
        ida_xref.del_cref(source, join, False)
        reanalyze(name)
        renewed = conditions(inspect(name, "external_restored"))
        check(
            "external entry removal recomputes a new publication",
            len(renewed) == 1 and renewed[0]["publication"] != before["publication"],
        )
        defining = next(
            i for i in code if i.get_canon_mnem() == "mov" and i.Op2.type == ida_ua.o_imm
        )
        raw = ida_bytes.get_bytes(defining.ea, defining.size)
        try:
            assert raw[-4:] == bytes((42, 0, 0, 0))
            assert ida_bytes.patch_byte(defining.ea + defining.size - 4, 41)
            reanalyze(name)
            check(
                "different sliced predecessor revokes consensus",
                not conditions(inspect(name, "definition_changed")),
            )
        finally:
            ida_bytes.patch_bytes(defining.ea, raw)
            reanalyze(name)
        check(
            "restored predecessor recomputes consensus", bool(conditions(inspect(name, "restored")))
        )
        # This NOP is outside the transfer slice but inside the complete guard
        # inventory. Replacing it changes the fingerprint, even though the
        # later definitions still establish the same value.
        outside = code[0]
        raw = ida_bytes.get_bytes(outside.ea, outside.size)
        old = conditions(inspect(name, "outside_before"))[0]
        try:
            assert raw == b"\x90" and ida_bytes.patch_byte(outside.ea, 0xF8)
            reanalyze(name)
            changed = conditions(inspect(name, "outside_changed"))
            check(
                "outside-slice byte mutation recomputes guard publication",
                len(changed) == 1 and changed[0]["publication"] != old["publication"],
            )
        finally:
            ida_bytes.patch_bytes(outside.ea, raw)
            reanalyze(name)
        check(
            "outside-slice byte restoration preserves exact value",
            bool(conditions(inspect(name, "outside_restored"))),
        )
    for name, raw in native_bytes.items():
        check(
            name + " preserves final native bytes",
            ida_bytes.get_bytes(address(name), len(raw)) == raw,
        )
except BaseException as error:
    errors.append(type(error).__name__)
    frames = []
    traceback = error.__traceback__
    while traceback:
        frames.append({"function": traceback.tb_frame.f_code.co_name, "line": traceback.tb_lineno})
        traceback = traceback.tb_next
    captures["exception"] = {"type": type(error).__name__, "frames": frames}

(Path(os.environ["IDAUSR"]).parent / "cfg_slices.json").write_text(
    json.dumps({"records": records, "errors": errors, "captures": captures}, indent=2) + "\n"
)
print("[chernobog][cfg-slices] " + ("FAIL" if errors else "PASS"), flush=True)
ida_pro.qexit(2 if errors else 0)
