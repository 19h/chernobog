"""Capture exact direct-memory jump facts under a read-only region query."""

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
import ida_ida
import ida_idaapi
import ida_loader
import ida_name
import ida_pro
import ida_ua
import idautils

sys.dont_write_bytecode = True
CASES = ("known_memory_jump", "dynamic_memory_jump")
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
    report["address_bits"] = 64 if ida_ida.inf_is_64bit() else 32
    report["target_seven"] = hex(symbol("target_seven"))
    report["target_eight"] = hex(symbol("target_eight"))
    report["mutable_pointer"] = hex(symbol("mutable_pointer"))
    for name in CASES:
        start, site = symbol(name), symbol(name + "_site")
        owner = ida_funcs.get_func(start)
        jump_owner = ida_funcs.get_func(site)
        assert owner is not None and owner.start_ea == start
        assert jump_owner is not None
        jump_owner_start = int(jump_owner.start_ea)
        assert jump_owner_start in (start, site)
        end = int(jump_owner.end_ea)
        instruction = ida_ua.insn_t()
        size = ida_ua.decode_insn(instruction, site)
        site_bytes = (ida_bytes.get_bytes(site, size) or b"").hex()
        check(name + " exact opcode", size == 6 and site_bytes.startswith("ff25"))
        check(name + " disposable owner removal", ida_funcs.del_func(start))
        if jump_owner_start != start:
            check(name + " disposable jump owner removal", ida_funcs.del_func(site))
        before = inventory(start, end)
        region = api(f"chernobog_native_region_facts({start})")
        direct_entry = api(f"chernobog_native_region_facts({site})")
        after = inventory(start, end)
        check(name + " read-only", before == after)
        check(
            name + " bounded unpublished region",
            region["available"]
            and region["root"] == hex(start)
            and region["published"] is False
            and region["converged"]
            and not region["truncated"],
        )
        report["cases"][name] = {
            "start": hex(start),
            "site": hex(site),
            "site_bytes": site_bytes,
            "decoded_operand_type": int(instruction.Op1.type),
            "decoded_operand_address": hex(int(instruction.Op1.addr)),
            "inventory": before,
            "region": region,
            "direct_entry": direct_entry,
        }
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
    report["exception_frames"] = [
        {"function": frame.name, "line": frame.lineno}
        for frame in traceback.extract_tb(error.__traceback__)
    ]

(Path(os.environ["IDAUSR"]).parent / "indirect_jump_memory.json").write_text(
    json.dumps(report, sort_keys=True, indent=2) + "\n"
)
print("[chernobog][indirect-jump-memory] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 2)
