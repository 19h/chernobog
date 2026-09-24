"""Confirm the prior installed plugin has no explicit shadow-use query."""

import hashlib
import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_expr
import ida_idaapi
import ida_loader
import ida_pro

ROOT = 0x100001440
WINDOW = Path(os.environ["CHERNOBOG_VMP_HELLO_WINDOW"])


def fingerprint():
    rows = [
        [int(ida_bytes.get_full_flags(ea)), bool(ida_bytes.is_loaded(ea))]
        for ea in range(ROOT, ROOT + 40)
    ]
    return hashlib.sha256(json.dumps(rows).encode()).hexdigest()


report = {"checks": [], "errors": []}


def check(label, passed):
    report["checks"].append({"case": label, "passed": bool(passed)})
    if not passed:
        report["errors"].append(label)


try:
    if not ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]):
        raise RuntimeError("prior plugin load failed")
    ida_auto.auto_wait()
    before = fingerprint()
    selected = ida_expr.idc_value_t()
    old_call = f"chernobog_vm_trace_candidate_shadow({ROOT},0,{json.dumps(str(WINDOW))})"
    if ida_expr.eval_idc_expr(selected, ida_idaapi.BADADDR, old_call):
        raise RuntimeError("prior shadow trace unavailable")
    shadow = json.loads(selected.c_str())
    request = json.dumps(
        {
            "source": "0x10000144d",
            "target": "0x100001456",
            "register": "rdi",
            "max_bytes": 32,
        }
    )
    new_call = (
        f"chernobog_vm_trace_candidate_shadow_use({ROOT},0,"
        f"{json.dumps(str(WINDOW))},{json.dumps(request)})"
    )
    result = ida_expr.idc_value_t()
    absent = bool(ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, new_call))
    after = fingerprint()
    check("prior shadow trace remains available", shadow["available"])
    check("prior explicit shadow-use API absent", absent)
    check("IDA byte and flag inventory unchanged", before == after)
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "vmp_hello_use_prior.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n"
)
print("[chernobog][vmp-hello-use-prior] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
ida_pro.qexit(2 if report["errors"] else 0)
