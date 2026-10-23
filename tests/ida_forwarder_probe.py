"""Verify native forwarder inlining without changing bytes or function flags."""

import json
import os
from pathlib import Path
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_lines
import ida_name
import idautils
import ida_pro
import idc

out = Path(os.environ["IDAUSR"]).parent
report = {"passed": False, "checks": [], "errors": [], "pseudocode": {}}


def address(name):
    for candidate in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return ea
    raise AssertionError("missing fixture symbol: " + name)


def check(name, condition):
    report["checks"].append({"name": name, "passed": bool(condition)})
    if not condition:
        report["errors"].append(name)


try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    wrappers = (
        "direct_wrapper",
        "indirect_wrapper",
        "aligned_wrapper",
        "framed_wrapper",
        "chain_wrapper",
        "custom_wrapper",
        "postprocess_wrapper",
        "restore_wrapper",
        "restore_caller",
    )
    for name in (*wrappers, "forward_target", "alternate_target"):
        assert idc.SetType(
            address(name), "unsigned __int64 %s(unsigned __int64 a, unsigned __int64 b);" % name
        )
    for name in ("forward_caller", "negative_caller"):
        assert idc.SetType(address(name), "unsigned __int64 %s(unsigned __int64 input);" % name)
    assert idc.SetType(
        address("custom_wrapper"),
        "unsigned __int64 __usercall custom_wrapper@<rax>(unsigned __int64 a@<rdi>, unsigned __int64 b@<rsi>);",
    )
    assert idc.SetType(
        address("target_slot"),
        "unsigned __int64 (*target_slot)(unsigned __int64, unsigned __int64);",
    )
    names = ("forward_caller", "negative_caller", "restore_caller", *wrappers[:-1])
    original = {
        name: [
            (start, ida_bytes.get_bytes(start, end - start))
            for start, end in idautils.Chunks(address(name))
        ]
        for name in names
    }
    flags = {name: ida_funcs.get_func(address(name)).flags for name in names}
    for iteration in range(2):
        for name in ("forward_caller", "negative_caller", "restore_caller"):
            cf = ida_hexrays.decompile(address(name), flags=ida_hexrays.DECOMP_NO_CACHE)
            assert cf
            text = "\n".join(ida_lines.tag_remove(line.line) for line in cf.get_pseudocode())
            report["pseudocode"][name] = text
            if name == "forward_caller":
                check(
                    "forwarders removed on pass %d" % iteration,
                    all(wrapper + "(" not in text for wrapper in wrappers),
                )
                check(
                    "indirect target load retained on pass %d" % iteration, "target_slot(" in text
                )
                check("real target retained on pass %d" % iteration, "forward_target(" in text)
            elif name == "negative_caller":
                check(
                    "return adjustment wrapper retained on pass %d" % iteration,
                    "postprocess_wrapper(" in text,
                )
                check(
                    "custom ABI wrapper retained on pass %d" % iteration,
                    "custom_wrapper(" in text,
                )
            else:
                check(
                    "RAX restoration wrapper retained on pass %d" % iteration,
                    "restore_wrapper(" in text,
                )
        for name in names:
            check(
                "native bytes unchanged: %s pass %d" % (name, iteration),
                all(ida_bytes.get_bytes(ea, len(data)) == data for ea, data in original[name]),
            )
            check(
                "function flags unchanged: %s pass %d" % (name, iteration),
                ida_funcs.get_func(address(name)).flags == flags[name],
            )
    report["passed"] = not report["errors"]
except Exception:
    report["errors"].append(traceback.format_exc())

(out / "forwarder.json").write_text(json.dumps(report, indent=2) + "\n")
print("[chernobog][forwarder] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 1)
