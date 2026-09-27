"""Live decoder-admission controls for exact jumps into executable data segments."""

import json
import os
from pathlib import Path
import struct
import traceback

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro
import ida_segment
import ida_ua
import ida_xref

checks, errors, rows = [], [], []


def check(name, value):
    checks.append({"case": name, "passed": bool(value)})
    if not value:
        errors.append(name)


def stats(run=True):
    result = {}
    snapshot = ida_expr.idc_value_t()
    query = "chernobog_native_analysis()" if run else "chernobog_native_stats()"
    assert not ida_expr.eval_idc_expr(snapshot, ida_idaapi.BADADDR, query)
    fields = [
        "direct_jump_decode_attempts",
        "direct_jump_targets_decoded",
        "direct_jump_decode_truncated",
    ]
    if os.environ.get("CHERNOBOG_FLOW_LEGACY_STATS") != "1":
        fields.append("direct_jump_heads_reanalyzed")
    for field in fields:
        value = ida_expr.idc_value_t()
        assert not ida_expr.get_idcv_attr(value, snapshot, field)
        result[field] = int(value.num)
    return result


def segment(start, name, kind, permissions=5, bitness=2):
    assert ida_segment.add_segm(0, start, start + 0x1000, name, kind)
    result = ida_segment.getseg(start)
    result.perm, result.bitness = permissions, bitness
    assert ida_segment.update_segm(result)
    return result


def item_state(ea):
    flags = ida_bytes.get_full_flags(ea)
    return (
        ida_bytes.is_code(flags),
        ida_bytes.is_data(flags),
        ida_bytes.is_tail(flags),
        int(ida_bytes.get_item_head(ea)),
        int(ida_bytes.get_item_size(ea)),
    )


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    before_stats = stats()
    base = (
        max(ida_segment.getnseg(i).end_ea for i in range(ida_segment.get_segm_qty())) + 0xFFFF
    ) & ~0xFFFF
    source_segment = segment(base, "decode_controls", "CODE")
    cases = [
        "named_positive",
        "defined_head",
        "defined_tail",
        "interior_data",
        "interior_label",
        "unloaded",
        "nonexec",
        "unknown_permissions",
        "different_bitness",
        "conditional",
        "indirect",
        "positive",
    ]
    for index, name in enumerate(cases):
        start = base + 0x10000 + index * 0x1000
        target, source = start + 0x100, base + index * 0x20
        permissions = (
            ida_segment.SEGPERM_READ
            if name == "nonexec"
            else 0 if name == "unknown_permissions" else 5
        )
        target_segment = segment(
            start, "decode_" + name, "DATA", permissions, 1 if name == "different_bitness" else 2
        )
        payload = b"\xb8\x2a\x00\x00\x00\xc3"
        if name != "unloaded":
            ida_bytes.put_bytes(target, payload)
        if name == "named_positive":
            assert ida_name.set_name(target, "decode_named_positive", ida_name.SN_NOWARN)
        if name == "interior_label":
            assert ida_name.set_name(target + 2, "decode_interior_label", ida_name.SN_NOWARN)
        if name == "defined_head":
            assert ida_bytes.create_data(target, ida_bytes.FF_BYTE, 5, ida_idaapi.BADADDR)
        if name == "defined_tail":
            ida_bytes.put_bytes(target - 1, b"\0")
            assert ida_bytes.create_data(target - 1, ida_bytes.FF_BYTE, 8, ida_idaapi.BADADDR)
        if name == "interior_data":
            assert ida_bytes.create_data(target + 2, ida_bytes.FF_BYTE, 1, ida_idaapi.BADADDR)
        if name == "conditional":
            instruction = b"\x0f\x84" + struct.pack("<i", target - source - 6)
        elif name == "indirect":
            instruction = b"\xff\xe0"
        else:
            instruction = b"\xe9" + struct.pack("<i", target - source - 5)
        ida_bytes.put_bytes(source, instruction)
        assert ida_ua.create_insn(source) == len(instruction)
        if name == "indirect":
            assert ida_xref.add_cref(source, target, ida_xref.fl_JN | ida_xref.XREF_USER)
        rows.append(
            {
                "name": name,
                "source": source,
                "target": target,
                "payload": payload.hex(),
                "items_before": [item_state(target + i) for i in range(6)],
                "name_before": (
                    ida_name.get_name(target)
                    if ida_bytes.has_user_name(ida_bytes.get_full_flags(target))
                    else ""
                ),
                "permissions": permissions,
                "segment_type": int(target_segment.type),
            }
        )
    ida_auto.auto_wait()
    measured = stats()
    ida_auto.auto_wait()
    disabled = os.environ.get("CHERNOBOG_IDA_DIRECT_JUMP_DECODE") == "0"
    cap = int(os.environ.get("CHERNOBOG_IDA_DIRECT_JUMP_TARGETS", "256"))
    expected_decoded = 0 if disabled or cap == 0 else 1 if cap == 1 else 2
    check(
        "exact decoder creation count",
        measured["direct_jump_targets_decoded"] - before_stats["direct_jump_targets_decoded"]
        == expected_decoded,
    )
    if cap in (0, 1) and not disabled:
        check("exhausted budget is explicit", measured["direct_jump_decode_truncated"] == 1)
        check(
            "attempt cap applies across callbacks", measured["direct_jump_decode_attempts"] <= cap
        )
    for row in rows:
        name, target = row["name"], row["target"]
        expected = (
            not disabled
            and cap > 0
            and (name == "named_positive" or name == "positive" and cap > 1)
        )
        row["decoded"] = ida_bytes.is_code(ida_bytes.get_full_flags(target))
        check(name + " admission", row["decoded"] == expected)
        if expected:
            row["successor_decoded"] = ida_bytes.is_code(ida_bytes.get_full_flags(target + 5))
            check(name + " ordinary successor decoding", row["successor_decoded"])
        if not expected:
            check(
                name + " item definitions preserved",
                row["items_before"] == [item_state(target + i) for i in range(6)],
            )
        if name != "unloaded":
            check(name + " bytes preserved", ida_bytes.get_bytes(target, 6).hex() == row["payload"])
        if row["name_before"]:
            check(name + " label preserved", ida_name.get_name(target) == row["name_before"])
        if name == "interior_label":
            check(
                name + " interior label preserved",
                ida_name.get_name(target + 2) == "decode_interior_label",
            )
        current = ida_segment.getseg(target)
        check(
            name + " segment metadata preserved",
            current.perm == row["permissions"] and current.type == row["segment_type"],
        )
    previous = measured["direct_jump_targets_decoded"]
    if not disabled and cap > 2:
        before_repair = stats()
        for row in rows:
            if row["name"] not in ("named_positive", "positive"):
                continue
            target = row["target"]
            function = ida_funcs.get_func(target)
            if function is not None:
                assert function.start_ea == target
                assert ida_funcs.del_func(target)
            assert ida_bytes.del_items(target + 5, ida_bytes.DELIT_SIMPLE, 1)
            for queue in (ida_auto.AU_CODE, ida_auto.AU_PROC, ida_auto.AU_USED):
                ida_auto.auto_unmark(target, target + 6, queue)
            check(
                row["name"] + " first head retained",
                ida_bytes.is_code(ida_bytes.get_full_flags(target)),
            )
            check(
                row["name"] + " successor is unknown before source reanalysis",
                ida_bytes.is_unknown(ida_bytes.get_full_flags(target + 5)),
            )
            ida_auto.plan_ea(row["source"])
            ida_auto.auto_wait()
            stats()
            ida_auto.auto_wait()
            ida_auto.auto_wait()
            row["repair_diagnostics"] = {
                "statistics": stats(False),
                "code_queue": int(ida_auto.peek_auto_queue(target + 5, ida_auto.AU_CODE)),
                "used_queue": int(ida_auto.peek_auto_queue(target, ida_auto.AU_USED)),
                "auto_complete": bool(ida_auto.auto_is_ok()),
                "head_end": int(ida_bytes.get_item_end(target)),
                "successor_flags": int(ida_bytes.get_full_flags(target + 5)),
                "successor_loaded": bool(ida_bytes.is_loaded(target + 5)),
            }
            row["repaired_successor"] = ida_bytes.is_code(ida_bytes.get_full_flags(target + 5))
            check(
                row["name"] + " existing-head successor repair",
                row["repaired_successor"] == (os.environ.get("CHERNOBOG_FLOW_LEGACY_STATS") != "1"),
            )
            check(
                row["name"] + " repair does not force an owner", ida_funcs.get_func(target) is None
            )
        after_repair = stats()
        check(
            "existing-head repair creates no target head",
            after_repair["direct_jump_targets_decoded"]
            == before_repair["direct_jump_targets_decoded"],
        )
        if "direct_jump_heads_reanalyzed" in after_repair:
            check(
                "existing-head repair schedules processor reanalysis",
                after_repair["direct_jump_heads_reanalyzed"]
                > before_repair["direct_jump_heads_reanalyzed"],
            )
        row = next(row for row in rows if row["name"] == "positive")
        target = row["target"]
        for guard in ("defined successor", "interior successor data", "interior successor label"):
            ida_bytes.del_items(target + 5, ida_bytes.DELIT_SIMPLE, 6)
            ida_bytes.put_bytes(target + 5, b"\xbb\x2b\x00\x00\x00\xc3")
            for queue in (ida_auto.AU_CODE, ida_auto.AU_PROC, ida_auto.AU_USED):
                ida_auto.auto_unmark(target, target + 11, queue)
            if guard == "defined successor":
                assert ida_bytes.create_data(target + 5, ida_bytes.FF_BYTE, 5, ida_idaapi.BADADDR)
            elif guard == "interior successor data":
                assert ida_bytes.create_data(target + 7, ida_bytes.FF_BYTE, 1, ida_idaapi.BADADDR)
            else:
                assert ida_name.set_name(target + 7, "guarded_successor_label", ida_name.SN_NOWARN)
            items_before = [item_state(target + i) for i in range(5, 11)]
            before_guard = stats()
            ida_auto.plan_ea(row["source"])
            ida_auto.auto_wait()
            ida_auto.auto_wait()
            after_guard = stats()
            check(
                guard + " items preserved",
                items_before == [item_state(target + i) for i in range(5, 11)],
            )
            check(
                guard + " bytes preserved",
                ida_bytes.get_bytes(target + 5, 6) == b"\xbb\x2b\x00\x00\x00\xc3",
            )
            if "direct_jump_heads_reanalyzed" in after_guard:
                check(
                    guard + " not scheduled",
                    after_guard["direct_jump_heads_reanalyzed"]
                    == before_guard["direct_jump_heads_reanalyzed"],
                )
    check(
        "repeated analysis does not re-admit code",
        stats()["direct_jump_targets_decoded"] == previous,
    )
except Exception as error:
    errors.append(type(error).__name__)
    rows.append(
        {
            "exception_frames": [
                {"function": frame.name, "line": frame.lineno}
                for frame in traceback.extract_tb(error.__traceback__)
            ]
        }
    )

(Path(os.environ["IDAUSR"]).parent / "direct_jump_decode.json").write_text(
    json.dumps({"checks": checks, "errors": errors, "rows": rows}, indent=2) + "\n"
)
line = "[chernobog][direct-jump-decode] " + ("FAIL" if errors else "PASS")
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
