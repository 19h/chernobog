"""Count decoded indirect jump forms in supplied x86-64 corpus members."""

import json
import os
from pathlib import Path
import traceback

import ida_allins
import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_loader
import ida_pro
import ida_segment
import ida_ua
import idautils

KINDS = (
    "register",
    "rex-register",
    "stack-top",
    "rex-stack-top",
    "direct-memory",
    "other",
)
report = {
    "schema": 1,
    "passed": False,
    "checks": [],
    "errors": [],
    "segments": [],
    "totals": {kind: 0 for kind in KINDS},
}


def check(name, condition):
    report["checks"].append({"case": name, "passed": bool(condition)})
    if not condition:
        report["errors"].append(name)


def classify(data):
    size = len(data)
    if size == 2 and data[0] == 0xFF and 0xE0 <= data[1] <= 0xE7:
        return "register"
    if size == 3 and 0x40 <= data[0] <= 0x4F and data[1] == 0xFF and 0xE0 <= data[2] <= 0xE7:
        return "rex-register"
    if data == bytes.fromhex("ff2424"):
        return "stack-top"
    if (
        size == 4
        and 0x40 <= data[0] <= 0x4F
        and (data[0] & 3) == 0
        and data[1:] == bytes.fromhex("ff2424")
    ):
        return "rex-stack-top"
    if size == 6 and data[:2] == bytes.fromhex("ff25"):
        return "direct-memory"
    return "other"


try:
    ida_auto.auto_wait()
    report["processor"] = ida_ida.inf_get_procname()
    report["address_bits"] = 64 if ida_ida.inf_is_64bit() else 32
    check("x86-64 processor", report["processor"] == "metapc" and report["address_bits"] == 64)
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    report["plugin_loaded"] = True
    for start in idautils.Segments():
        segment = ida_segment.getseg(start)
        if segment is None or not (segment.perm & ida_segment.SEGPERM_EXEC):
            continue
        row = {
            "name": ida_segment.get_segm_name(segment),
            "start": hex(int(segment.start_ea)),
            "end": hex(int(segment.end_ea)),
            "code_heads": 0,
            "indirect_jumps": 0,
            "counts": {kind: 0 for kind in KINDS},
            "examples": {kind: [] for kind in KINDS},
        }
        for ea in idautils.Heads(segment.start_ea, segment.end_ea):
            flags = ida_bytes.get_full_flags(ea)
            if not ida_bytes.is_code(flags) or not ida_bytes.is_head(flags):
                continue
            row["code_heads"] += 1
            instruction = ida_ua.insn_t()
            size = ida_ua.decode_insn(instruction, ea)
            if size <= 0 or instruction.itype != ida_allins.NN_jmpni:
                continue
            data = ida_bytes.get_bytes(ea, size) or b""
            if len(data) != size:
                continue
            kind = classify(data)
            row["indirect_jumps"] += 1
            row["counts"][kind] += 1
            report["totals"][kind] += 1
            if len(row["examples"][kind]) < 16:
                owner = ida_funcs.get_func(ea)
                row["examples"][kind].append(
                    {
                        "site": hex(int(ea)),
                        "bytes": data.hex(),
                        "owner": None if owner is None else hex(int(owner.start_ea)),
                        "operand_type": int(instruction.Op1.type),
                    }
                )
        report["segments"].append(row)
    report["code_heads"] = sum(segment["code_heads"] for segment in report["segments"])
    report["indirect_jumps"] = sum(segment["indirect_jumps"] for segment in report["segments"])
    check("count conservation", sum(report["totals"].values()) == report["indirect_jumps"])
    check("nonempty executable code", report["code_heads"] > 0)
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
    report["exception_frames"] = [
        {"function": frame.name, "line": frame.lineno}
        for frame in traceback.extract_tb(error.__traceback__)
    ]

(Path(os.environ["IDAUSR"]).parent / "protected_indirect_census.json").write_text(
    json.dumps(report, sort_keys=True, indent=2) + "\n"
)
print(
    "[chernobog][protected-indirect-census] " + ("PASS" if report["passed"] else "FAIL"), flush=True
)
ida_pro.qexit(0 if report["passed"] else 2)
