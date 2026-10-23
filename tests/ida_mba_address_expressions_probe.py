"""Verify address-keyed MBA recovery without assuming a concrete stack address."""

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


def preserve_frame_aliases(text):
    # Recompiled C must retain the frame aliases described by IDA. In
    # particular, &savedregs-8 and a local at rbp-8 denote the same address.
    pattern = re.compile(
        r"^\s*(_BYTE|_DWORD|__int64) (\w+)(?:\[(\d+)\])?; // .*" r"\[rbp([+-][0-9A-Fa-f]+h)\].*$",
        re.MULTILINE,
    )
    slots = []
    widths = {"_BYTE": 1, "_DWORD": 4, "__int64": 8}
    for match in pattern.finditer(text):
        kind, name, count, offset = match.groups()
        displacement = int(offset[1:-1], 16) * (-1 if offset[0] == "-" else 1)
        slots.append((kind, name, count, displacement, widths[kind] * int(count or 1)))
    if not slots:
        return text
    base = min(slot[3] for slot in slots)
    length = max(slot[3] + slot[4] for slot in slots) - base
    assert 0 < length <= 4096
    text = pattern.sub("", text)
    for kind, name, count, offset, _ in slots:
        pointer = "((%s *)(recovered_frame + %d))" % (kind, offset - base)
        replacement = pointer if count else "(*%s)" % pointer
        text = re.sub(r"\b" + re.escape(name) + r"\b", replacement, text)
    return text.replace("{", "{\n  _Alignas(16) unsigned char recovered_frame[%d];" % length, 1)


out = Path(os.environ["IDAUSR"]).parent
report = {"passed": False}
try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    texts = {}
    report["statistics"] = {}
    for name in ("address_key", "partial_address_key", "address_sum", "distinct_addresses"):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "_" + name)
        if ea == ida_idaapi.BADADDR:
            ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        assert ea != ida_idaapi.BADADDR
        assert idc.SetType(ea, "unsigned int %s(unsigned int input);" % name)
        cf = ida_hexrays.decompile(ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        assert cf
        texts[name] = "\n".join(ida_lines.tag_remove(line.line) for line in cf.get_pseudocode())
        report["statistics"][name] = json.loads(idc.eval_idc("chernobog_mba_smt_stats(%d);" % ea))
    report["pseudocode"] = texts
    assert "|" not in texts["address_key"], texts["address_key"]
    assert "|" not in texts["address_sum"], texts["address_sum"]
    assert "|" not in texts["partial_address_key"], texts["partial_address_key"]
    assert "verify_pair(" in texts["distinct_addresses"]
    report.update(passed=True, pseudocode=texts)
    bodies = [
        preserve_frame_aliases(re.sub(r"\b(?:a[0-9]+|input|value):\s*", "", text))
        for text in texts.values()
    ]
    (out / "recovered.c").write_text(
        "#define __fastcall\n#define __int8 char\n#define __int64 long long\n#define _BYTE unsigned char\n#define _DWORD unsigned int\n"
        + "\n\n".join(bodies)
    )
except Exception:
    report["error"] = traceback.format_exc()
(out / "mba-address-expressions.json").write_text(json.dumps(report, indent=2) + "\n")
print(
    "[chernobog][mba-address-expressions] " + ("PASS" if report["passed"] else "FAIL"), flush=True
)
ida_pro.qexit(0 if report["passed"] else 1)
