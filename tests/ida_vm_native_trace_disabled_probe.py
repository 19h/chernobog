"""A disabled backend must not start a native-region capture or publication."""
import json
import os
from pathlib import Path
import ida_auto
import ida_expr
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_pro

checks, errors = [], []
try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    ea = int(next(iter(json.loads(os.environ["CHERNOBOG_CORPUS_ENTRIES"]).values())), 0)
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"chernobog_evidence_state({ea})")
    before = value.c_str()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"chernobog_vm_trace({ea}, 0)")
    result = json.loads(value.c_str())
    checks.append(result["available"] is False and result["scope"] == "native-region"
                  and result["reason"] == "native decoder/emulator unavailable")
    request = json.dumps({"args": ["0x0"], "objects": [{"argument": 0, "offset": 0, "bytes": "00"}]})
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR,
        f"chernobog_vm_trace_input({ea}, 0, {json.dumps(request)})")
    result = json.loads(value.c_str())
    checks.append(result["available"] is False and result["scope"] == "native-region"
                  and result["reason"] == "native decoder/emulator unavailable")
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR,
        f"chernobog_vm_trace_walk({ea}, 0, {json.dumps(request)})")
    result = json.loads(value.c_str())
    checks.append(result["available"] is False and result["scope"] == "native-region"
                  and result["reason"] == "native decoder/emulator unavailable")
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR,
        f"chernobog_vm_trace_check({ea}, 0, {json.dumps(request)})")
    result = json.loads(value.c_str())
    checks.append(result["available"] is False and result["scope"] == "native-region"
                  and result["reason"] == "native decoder/emulator unavailable")
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"chernobog_evidence_state({ea})")
    checks.append(before == value.c_str())
except Exception as error:
    errors.append(type(error).__name__)
passed = not errors and len(checks) == 5 and all(checks)
(Path(os.environ["IDAUSR"]).parent / "vm_native_disabled.json").write_text(
    json.dumps({"passed": passed, "checks": checks, "errors": errors}, indent=2) + "\n")
line = "[chernobog][vm-native-disabled] " + ("PASS" if passed else "FAIL")
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(0 if passed else 2)
