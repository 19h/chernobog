"""Check defined flags and unknown results across REX-prefixed BSWAP16."""

import hashlib
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
import ida_loader
import ida_name
import ida_pro
import ida_ua
import idautils

sys.dont_write_bytecode = True
CASES = ("rex_bswap_cf", "rex_bswap_zf", "rex_bswap_unknown")
ENCODING = bytes.fromhex("66410fc9")
report = {"schema": 1, "passed": False, "checks": [], "errors": [], "cases": {}}


def check(name, condition):
    report["checks"].append({"case": name, "passed": bool(condition)})
    if not condition:
        report["errors"].append(name)


def api(expression):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    return json.loads(value.c_str())


def symbol(name):
    for candidate in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return int(ea)
    raise AssertionError("fixture symbol missing: " + name)


def inventory(start, end):
    digest = hashlib.sha256()
    count = 0
    for ea in idautils.Heads(start, end):
        size = ida_bytes.get_item_end(ea) - ea
        owner = ida_funcs.get_func(ea)
        row = [
            int(ea),
            int(size),
            (ida_bytes.get_bytes(ea, size) or b"").hex(),
            int(ida_bytes.get_full_flags(ea)),
            None if owner is None else int(owner.start_ea),
        ]
        count += 1
        digest.update(json.dumps(row, separators=(",", ":")).encode() + b"\n")
    return {"items": count, "sha256": digest.hexdigest()}


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    enabled = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(enabled, ida_idaapi.BADADDR, "chernobog_native_analysis()")
    ida_auto.auto_wait()
    ida_auto.enable_auto(False)
    for name in CASES:
        start = symbol(name)
        use = symbol(name + "_use")
        function = ida_funcs.get_func(start)
        assert function is not None and function.start_ea == start
        continuation = ida_funcs.get_func(use)
        assert continuation is not None and continuation.start_ea == use
        end = int(continuation.end_ea)
        instructions = []
        for ea in idautils.Heads(start, end):
            if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
                continue
            decoded = ida_ua.insn_t()
            size = ida_ua.decode_insn(decoded, ea)
            assert 0 < size <= 15
            instructions.append(
                {"site": hex(ea), "size": size, "bytes": ida_bytes.get_bytes(ea, size).hex()}
            )
        swaps = [row for row in instructions if row["bytes"] == ENCODING.hex()]
        check(name + " exact single REX BSWAP16", len(swaps) == 1)
        check(
            name + " exact continuation", len(swaps) == 1 and use == int(swaps[0]["site"], 16) + 4
        )
        check(name + " disposable root owner removal", ida_funcs.del_func(start))
        check(name + " disposable continuation owner removal", ida_funcs.del_func(use))
        before = inventory(start, end)
        region = api(f"chernobog_native_region_facts({start})")
        after = inventory(start, end)
        check(name + " region inspection preserves prepared IDB", before == after)
        check(
            name + " bounded unpublished region",
            region["schema"] == 1
            and region["available"]
            and region["root"] == hex(start)
            and region["published"] is False
            and not region["truncated"],
        )
        report["cases"][name] = {
            "start": hex(start),
            "use": hex(use),
            "end": hex(end),
            "instructions": instructions,
            "swap": swaps[0] if swaps else None,
            "prepared_inventory": before,
            "region": region,
        }
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
    report["exception_frames"] = [
        {"function": frame.name, "line": frame.lineno}
        for frame in traceback.extract_tb(error.__traceback__)
    ]

(Path(os.environ["IDAUSR"]).parent / "bswap16_rex_fixture.json").write_text(
    json.dumps(report, sort_keys=True, indent=2) + "\n"
)
print("[chernobog][bswap16-rex-fixture] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 2)
