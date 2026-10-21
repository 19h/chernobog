"""Supplemental D810 SDK faults, separate from the frozen promotion manifest."""

import ctypes
import hashlib
import platform
import json
import os
from pathlib import Path
import ida_auto
import ida_hexrays
import ida_name
import ida_kernwin
import ida_lines
import ida_pro


def main():
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays unavailable")
    library = ctypes.CDLL(os.environ["CHERNOBOG_D810_SDK_BRIDGE"])
    probe = library.chernobog_mba_d810_memory_probe
    probe.argtypes = [ctypes.c_uint64, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
    probe.restype = ctypes.c_int
    rows = []
    for name in ("test_chained_add", "test_cst_simplification"):
        ea = ida_name.get_name_ea(0xFFFFFFFFFFFFFFFF, name)
        if ea == 0xFFFFFFFFFFFFFFFF:
            ea = ida_name.get_name_ea(0xFFFFFFFFFFFFFFFF, "_" + name)
        if ea == 0xFFFFFFFFFFFFFFFF:
            raise RuntimeError("Missing supplemental fixture: " + name)
        for fault in range(24 if name == "test_cst_simplification" else 23):
            output = ctypes.create_string_buffer(4096)
            code = probe(ea, fault, output, len(output))
            row = json.loads(output.value)
            row.update(function=name, route="memory", code=code)
            rows.append(row)
            print("[chernobog][d810-sdk]", name, fault, code, flush=True)
    control = library.chernobog_mba_d810_control_probe
    control.argtypes = probe.argtypes
    control.restype = ctypes.c_int
    selection = os.environ.get(
        "CHERNOBOG_D810_CONTROL_NAMES",
        "single_iteration_simple,abc_f6_add_dispatch,nested_simple,while_switch_flattened",
    )
    for name in selection.split(","):
        ea = ida_name.get_name_ea(0xFFFFFFFFFFFFFFFF, name)
        if ea == 0xFFFFFFFFFFFFFFFF:
            ea = ida_name.get_name_ea(0xFFFFFFFFFFFFFFFF, "_" + name)
        if ea == 0xFFFFFFFFFFFFFFFF:
            raise RuntimeError("Missing supplemental control fixture: " + name)
        for fault in range(18):
            output = ctypes.create_string_buffer(4096)
            code = control(ea, fault, output, len(output))
            row = json.loads(output.value)
            row.update(function=name, route="control", code=code)
            rows.append(row)
            print("[chernobog][d810-control-sdk]", name, fault, code, flush=True)
    negatives = os.environ.get("CHERNOBOG_D810_CONTROL_NEGATIVES", "")
    for name in filter(None, negatives.split(",")):
        ea = ida_name.get_name_ea(0xFFFFFFFFFFFFFFFF, name)
        if ea == 0xFFFFFFFFFFFFFFFF:
            ea = ida_name.get_name_ea(0xFFFFFFFFFFFFFFFF, "_" + name)
        if ea == 0xFFFFFFFFFFFFFFFF:
            raise RuntimeError("Missing negative control fixture: " + name)
        output = ctypes.create_string_buffer(4096)
        fault = 16 if name == "d810_control_volatile" else -1
        code = control(ea, fault, output, len(output))
        row = json.loads(output.value)
        row.update(function=name, route="negative-control", code=code)
        rows.append(row)
    literal_probe = library.chernobog_mba_d810_literal_probe
    literal_probe.argtypes = [ctypes.c_uint64, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t]
    literal_probe.restype = ctypes.c_int
    literals = []
    for literal in (0xFFFFFFFF, 0x80000000, 0xADC07CB7):
        output = ctypes.create_string_buffer(4096)
        code = literal_probe(ea, literal, output, len(output))
        literals.append(
            {
                "input32": literal,
                "expected64": (literal - (1 << 32)) & ((1 << 64) - 1),
                "code": code,
                "text": ida_lines.tag_remove(output.value.decode()),
            }
        )
    library.chernobog_mba_d810_revision.restype = ctypes.c_char_p
    library.chernobog_mba_d810_source_fingerprint.restype = ctypes.c_char_p
    report = {
        "revision": library.chernobog_mba_d810_revision().decode(),
        "source_fingerprint": library.chernobog_mba_d810_source_fingerprint().decode(),
        "bridge_sha256": hashlib.sha256(
            Path(os.environ["CHERNOBOG_D810_SDK_BRIDGE"]).read_bytes()
        ).hexdigest(),
        "kernel_version": ida_kernwin.get_kernel_version(),
        "hexrays_version": ida_hexrays.get_hexrays_version(),
        "system": platform.system(),
        "machine": platform.machine(),
        "rows": rows,
        "literals": literals,
        "failures": sum(r["code"] != 0 for r in rows + literals),
    }
    (Path(os.environ["IDAUSR"]).parent / "d810_sdk.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "[chernobog][d810-sdk] "
        + ("FAIL" if report["failures"] else "PASS")
        + " probes="
        + str(len(rows)),
        flush=True,
    )
    ida_pro.qexit(int(bool(report["failures"])))


try:
    main()
except BaseException as error:
    print("[chernobog][d810-sdk] FAIL", type(error).__name__, str(error), flush=True)
    ida_pro.qexit(9)
