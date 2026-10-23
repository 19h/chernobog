"""Decompile threaded selects twice and retain C for native differential execution."""

import json
import os
from pathlib import Path
import traceback

import ida_auto
import ida_hexrays
import ida_idaapi
import ida_lines
import ida_name
import ida_pro
import idc

out = Path(os.environ["IDAUSR"]).parent
report = {"passed": False}
try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "_threaded_select")
    if ea == ida_idaapi.BADADDR:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "threaded_select")
    assert ea != ida_idaapi.BADADDR
    assert idc.SetType(ea, "unsigned int threaded_select(const int *values);")
    texts = []
    for _ in range(2):
        cfunc = ida_hexrays.decompile(ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        assert cfunc
        cfunc.mba.verify(True)
        texts.append("\n".join(ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()))
    assert texts[0] == texts[1], "Repeated decompilation changed pseudocode"
    (out / "recovered.c").write_text("#define __fastcall\n" + texts[0] + "\n")
    report.update(passed=True, decompilations=len(texts), pseudocode=texts[0])
except Exception:
    report["error"] = traceback.format_exc()
(out / "optblock-lifetime.json").write_text(json.dumps(report, indent=2) + "\n")
print("[chernobog][optblock-lifetime] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 1)
