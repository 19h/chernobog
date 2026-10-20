"""Exercise production SDK emission and mutation gates in a licensed IDA process."""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform

import ida_auto
import ida_hexrays
import ida_kernwin
import ida_loader
import ida_pro


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays unavailable")
    plugin = Path(os.environ["CHERNOBOG_PLUGIN_PATH"])
    if not ida_loader.find_plugin("chernobog", False) and not ida_loader.load_plugin(str(plugin)):
        raise RuntimeError("Chernobog plugin unavailable")
    bridge = Path(os.environ["CHERNOBOG_COBRA_SDK_BRIDGE"])
    bridge_hash = digest(bridge)
    library = ctypes.CDLL(str(bridge))
    run = library.chernobog_mba_cobra_sdk_bridge
    run.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
    run.restype = ctypes.c_int
    reports = []
    errors = []
    selection = os.environ.get(
        "CHERNOBOG_COBRA_SDK_MODES",
        "cobra:Normal,cobra:Deep,cobra:Faults,legacy:Normal,legacy:Deep",
    )
    for mode in selection.split(","):
        backend, profile = mode.split(":")
        print(f"[chernobog][cobra-sdk] Running {backend}/{profile}", flush=True)
        buffer = ctypes.create_string_buffer(1048576)
        code = run(
            {"legacy": 0, "cobra": 1}[backend],
            {"Normal": 0, "Deep": 1, "Faults": 2}[profile],
            buffer,
            len(buffer),
        )
        if not buffer.value:
            errors.append(f"SDK bridge did not produce a report: {mode} ({code})")
            continue
        report = json.loads(buffer.value.decode())
        reports.append(report)
        if code or report.get("failures"):
            errors.append(f"SDK bridge failed: {mode} ({code})")
    if digest(bridge) != bridge_hash:
        errors.append("SDK bridge artifact changed during execution")
    report = {
        "schema_version": 1,
        "kernel_version": ida_kernwin.get_kernel_version(),
        "hexrays_version": ida_hexrays.get_hexrays_version(),
        "system": platform.system(),
        "machine": platform.machine(),
        "plugin_sha256": digest(plugin),
        "bridge_sha256": bridge_hash,
        "reports": reports,
        "errors": errors,
    }
    output = Path(os.environ["IDAUSR"]).parent / "mba_cobra_sdk.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        f"[chernobog][cobra-sdk] {'FAIL' if errors else 'PASS'} reports={len(reports)}", flush=True
    )
    ida_pro.qexit(int(bool(errors)))


try:
    main()
except BaseException as error:
    print(f"[chernobog][cobra-sdk] FAIL exception={type(error).__name__}: {error}", flush=True)
    ida_pro.qexit(9)
