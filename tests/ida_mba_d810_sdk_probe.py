"""Supplemental D810 SDK faults, separate from the frozen promotion manifest."""

import ctypes
import json
import os
from pathlib import Path
import ida_auto
import ida_hexrays
import ida_name
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
        for fault in range(22):
            output = ctypes.create_string_buffer(4096)
            code = probe(ea, fault, output, len(output))
            row = json.loads(output.value)
            row.update(function=name, code=code)
            rows.append(row)
            print("[chernobog][d810-sdk]", name, fault, code, flush=True)
    report = {"rows": rows, "failures": sum(r["code"] != 0 for r in rows)}
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
