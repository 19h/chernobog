"""Measure the protected REX BSWAP16 static frontier in a disposable IDB."""

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

sys.dont_write_bytecode = True
SITE = 0x10007012E
OWNER = SITE - 2
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


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    enabled = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(enabled, ida_idaapi.BADADDR, "chernobog_native_analysis()")
    ida_auto.auto_wait()
    check(
        "original protected site and owner",
        ida_bytes.get_bytes(SITE, len(BYTES)) == BYTES
        and (function := ida_funcs.get_func(SITE)) is not None
        and function.start_ea == OWNER,
    )
    ida_auto.enable_auto(False)
    check("disposable owner removal", ida_funcs.del_func(OWNER))
    check(
        "ownerless exact code head retained",
        ida_funcs.get_func(SITE) is None
        and ida_bytes.is_code(ida_bytes.get_full_flags(SITE))
        and ida_bytes.get_item_head(SITE) == SITE
        and ida_bytes.get_bytes(SITE, len(BYTES)) == BYTES,
    )
    report["region"] = api(f"chernobog_native_region_facts({SITE})")
    check(
        "root-scoped unpublished region",
        report["region"]["schema"] == 1
        and report["region"]["root"] == hex(SITE)
        and report["region"]["published"] is False,
    )
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
    report["exception_frames"] = [
        {"function": frame.name, "line": frame.lineno}
        for frame in traceback.extract_tb(error.__traceback__)
    ]

(Path(os.environ["IDAUSR"]).parent / "bswap16_rex_region.json").write_text(
    json.dumps(report, sort_keys=True, indent=2) + "\n"
)
print("[chernobog][bswap16-rex-region] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 2)
