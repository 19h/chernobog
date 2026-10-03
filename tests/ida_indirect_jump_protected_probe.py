"""Compare the same supplied ownerless initializer across indirect-jump revisions."""

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
import ida_segment
import idautils

sys.dont_write_bytecode = True
ROOT = 0x1002946B5
JUMP = 0x10024801A
report = {"schema": 1, "passed": False, "checks": [], "errors": []}


def check(name, condition):
    report["checks"].append({"case": name, "passed": bool(condition)})
    if not condition:
        report["errors"].append(name)


def inventory():
    digest = hashlib.sha256()
    total = heads = references = 0
    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        size = int(segment.end_ea - segment.start_ea)
        total += size
        assert total <= 64 * 1024 * 1024
        identity = [
            int(segment.start_ea),
            int(segment.end_ea),
            int(segment.bitness),
            int(segment.perm),
        ]
        digest.update(json.dumps(identity, separators=(",", ":")).encode() + b"\n")
        for part in ida_bytes.get_bytes_and_mask(segment.start_ea, size) or (b"unloaded",):
            digest.update(part)
        for ea in idautils.Heads(segment.start_ea, segment.end_ea):
            heads += 1
            assert heads <= 1048576
            owner = ida_funcs.get_func(ea)
            refs = sorted(
                (int(ref.frm), int(ref.to), int(ref.type), bool(ref.iscode), bool(ref.user))
                for ref in idautils.XrefsFrom(ea)
            )
            references += len(refs)
            assert references <= 2097152
            row = [
                int(ea),
                int(ida_bytes.get_full_flags(ea)),
                int(ida_bytes.get_item_end(ea)),
                None if owner is None else int(owner.start_ea),
                refs,
            ]
            digest.update(json.dumps(row, separators=(",", ":")).encode() + b"\n")
    return {"sha256": digest.hexdigest(), "heads": heads, "references": references}


def api(expression):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    return json.loads(value.c_str())


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    enabled = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(enabled, ida_idaapi.BADADDR, "chernobog_native_analysis()")
    ida_auto.auto_wait()
    check("ownerless selected root", ida_funcs.get_func(ROOT) is None)
    check(
        "exact register jump head",
        ida_bytes.get_item_head(JUMP) == JUMP
        and ida_bytes.get_bytes(JUMP, 3) == bytes.fromhex("41ffe2"),
    )
    report["inventory_before"] = inventory()
    report["region"] = api(f"chernobog_native_region_facts({ROOT})")
    report["inventory_after"] = inventory()
    check("read-only inventory", report["inventory_before"] == report["inventory_after"])
    region = report["region"]
    check(
        "bounded unpublished initializer",
        region["schema"] == 1
        and region["available"]
        and region["root"] == hex(ROOT)
        and region["published"] is False
        and region["converged"]
        and not region["truncated"]
        and len(region["nodes"]) == 75
        and len(region["edges"]) == 77,
    )
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
    report["exception_frames"] = [
        {"function": frame.name, "line": frame.lineno}
        for frame in traceback.extract_tb(error.__traceback__)
    ]

(Path(os.environ["IDAUSR"]).parent / "indirect_jump_protected.json").write_text(
    json.dumps(report, sort_keys=True, indent=2) + "\n"
)
print(
    "[chernobog][indirect-jump-protected] " + ("PASS" if report["passed"] else "FAIL"), flush=True
)
ida_pro.qexit(0 if report["passed"] else 2)
