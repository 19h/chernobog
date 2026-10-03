"""Inspect the exact protected REX BSWAP16 site without changing its IDB."""

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
import ida_pro
import ida_ua
import idautils

sys.dont_write_bytecode = True
SITE = 0x10007012E
BYTES = bytes.fromhex("66410fc9")
report = {"schema": 1, "passed": False, "checks": [], "errors": []}


def check(name, condition):
    report["checks"].append({"case": name, "passed": bool(condition)})
    if not condition:
        report["errors"].append(name)


def api(expression):
    result = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression)
    return json.loads(result.c_str())


def inventory(owner):
    function = ida_funcs.get_func(owner)
    assert function is not None and function.start_ea == owner
    digest = hashlib.sha256()
    count = 0
    for ea in idautils.Heads(function.start_ea, function.end_ea):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            continue
        count += 1
        assert count <= 4096
        size = ida_bytes.get_item_end(ea) - ea
        row = [
            int(ea),
            int(size),
            (ida_bytes.get_bytes(ea, size) or b"").hex(),
            int(ida_bytes.get_full_flags(ea)),
        ]
        digest.update(json.dumps(row, separators=(",", ":")).encode() + b"\n")
    return {"heads": count, "sha256": digest.hexdigest(), "flags": int(function.flags)}


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    enabled = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(enabled, ida_idaapi.BADADDR, "chernobog_native_analysis()")
    ida_auto.auto_wait()
    function = ida_funcs.get_func(SITE)
    check("exact protected function owner", function is not None and function.start_ea == SITE - 2)
    owner = int(function.start_ea)
    instruction = ida_ua.insn_t()
    size = ida_ua.decode_insn(instruction, SITE)
    check(
        "exact REX BSWAP16 head",
        size == len(BYTES)
        and ida_bytes.is_code(ida_bytes.get_full_flags(SITE))
        and ida_bytes.get_item_head(SITE) == SITE
        and ida_bytes.get_bytes(SITE, size) == BYTES
        and ida_ua.print_insn_mnem(SITE).lower() == "bswap",
    )
    report["site"] = hex(SITE)
    report["bytes"] = BYTES.hex()
    report["owner"] = hex(owner)
    report["inventory_before"] = inventory(owner)
    report["diagnostics"] = api(f"chernobog_native_condition_diagnostics({owner})")
    report["inventory_after"] = inventory(owner)
    check(
        "diagnostics preserve owned code", report["inventory_before"] == report["inventory_after"]
    )
    check(
        "bounded owned diagnostic",
        report["diagnostics"]["schema"] == 1
        and report["diagnostics"]["available"]
        and report["diagnostics"]["function"] == hex(owner)
        and report["diagnostics"]["heads_examined"] <= 4096
        and not report["diagnostics"]["truncated"],
    )
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
    report["exception_frames"] = [
        {"function": frame.name, "line": frame.lineno}
        for frame in traceback.extract_tb(error.__traceback__)
    ]

(Path(os.environ["IDAUSR"]).parent / "bswap16_rex.json").write_text(
    json.dumps(report, sort_keys=True, indent=2) + "\n"
)
print("[chernobog][bswap16-rex] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 2)
