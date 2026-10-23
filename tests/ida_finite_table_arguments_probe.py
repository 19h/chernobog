"""Verify call-argument table proofs and preservation of mutable/effectful inputs."""

import json
import os
from pathlib import Path
import re
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
    texts = {}
    for name in ("table_argument", "mutable_argument", "effectful_argument", "table_data_read"):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "_" + name)
        if ea == ida_idaapi.BADADDR:
            ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        assert ea != ida_idaapi.BADADDR
        assert idc.SetType(ea, "unsigned int %s(unsigned int input);" % name)
        cf = ida_hexrays.decompile(ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        assert cf
        texts[name] = "\n".join(ida_lines.tag_remove(line.line) for line in cf.get_pseudocode())
    assert "first[" not in texts["table_argument"] and "second[" not in texts["table_argument"]
    assert re.search(r"consume_value\([^)]*(?:\b97\b|0x61\b)", texts["table_argument"])
    assert "mutable_first" in texts["mutable_argument"]
    assert texts["effectful_argument"].count("next_input(") == 2
    assert "observed_value" in texts["table_data_read"]
    assert "data_offsets" not in texts["table_data_read"]
    assert "first[" not in texts["table_data_read"] and "second[" not in texts["table_data_read"]
    report.update(passed=True, pseudocode=texts)
    bodies = [re.sub(r"\b(?:a[0-9]+|input|value):\s*", "", text) for text in texts.values()]
    (out / "recovered.c").write_text(
        "#define __fastcall\n#define __int8 char\n" + "\n\n".join(bodies)
    )
except Exception:
    report["error"] = traceback.format_exc()
(out / "finite-table-arguments.json").write_text(json.dumps(report, indent=2) + "\n")
print("[chernobog][finite-table-arguments] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 1)
