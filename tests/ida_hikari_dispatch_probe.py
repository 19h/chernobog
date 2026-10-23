"""Verify aliased dispatcher recovery and export compilable recovered fixture C."""

import json
import os
from pathlib import Path
import re
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_lines
import ida_name
import ida_pro
import idc

out = Path(os.environ["IDAUSR"]).parent
report = {"passed": False, "checks": [], "errors": []}


def check(name, condition):
    report["checks"].append({"name": name, "passed": bool(condition)})
    if not condition:
        report["errors"].append(name)


def address(name):
    for candidate in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return ea
    raise AssertionError("missing fixture symbol: " + name)


try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    names = ("flattened", "alias_join", "alias_escape", "partial_write", "loop_alias", "wide_state")
    for name in (*names, "helper"):
        assert idc.SetType(address(name), "unsigned int %s(unsigned int input);" % name)
    assert idc.SetType(address("wide_state"), "unsigned long long wide_state(unsigned int input);")
    assert idc.SetType(address("redirect"), "void redirect(unsigned int **p, unsigned int *q);")
    assert idc.SetType(address("observed"), "unsigned int observed;")
    assert idc.SetType(address("read_seed"), "unsigned int read_seed(void);")
    seed_name = ida_name.get_name(address("seed")).lstrip("_")
    for mode in (0, 2, 0):
        assert idc.eval_idc('chernobog_set_option("writable_const", %d);' % mode) == 1
        seed_cf = ida_hexrays.decompile(address("read_seed"), flags=ida_hexrays.DECOMP_NO_CACHE)
        seed_text = "\n".join(
            ida_lines.tag_remove(line.line) for line in seed_cf.get_pseudocode()
        ).split("{", 1)[1]
        check("live writable option %d" % mode, (seed_name in seed_text) == (mode == 0))
    functions = {name: ida_funcs.get_func(address(name)) for name in names}
    original = {
        name: ida_bytes.get_bytes(function.start_ea, function.end_ea - function.start_ea)
        for name, function in functions.items()
    }
    texts = {}
    for iteration in range(2):
        for name in names:
            failure = ida_hexrays.hexrays_failure_t()
            cf = ida_hexrays.decompile_func(functions[name], failure, ida_hexrays.DECOMP_NO_CACHE)
            assert cf, failure.desc()
            text = "\n".join(ida_lines.tag_remove(line.line) for line in cf.get_pseudocode())
            texts[name] = text
            if name == "flattened":
                check(
                    "dispatcher removed on pass %d" % iteration,
                    "switch (" not in text and "while (" not in text,
                )
                check("runtime branch retained on pass %d" % iteration, "if (" in text)
                check("helper retained on pass %d" % iteration, "helper(" in text)
            if name == "alias_join":
                check(
                    "ambiguous alias retained on pass %d" % iteration, "*" in text and "71" in text
                )
            if name == "alias_escape":
                check("escaping alias call retained on pass %d" % iteration, "redirect(" in text)
            check(
                "native bytes unchanged: %s pass %d" % (name, iteration),
                original[name]
                == ida_bytes.get_bytes(functions[name].start_ea, len(original[name])),
            )
    report["pseudocode"] = texts
    header = """#include <stdint.h>
#include <stdio.h>
#define __fastcall
#define __int64 long long
typedef uint32_t _DWORD;
typedef unsigned char _BYTE;
#define LOBYTE(x) (*((unsigned char *)&(x)))
uint32_t observed;
uint32_t calls;
uint32_t helper(uint32_t input) { ++calls; observed = input; return input ^ 0x5a; }
void redirect(uint32_t **p, uint32_t *q) { *p = q; }
"""
    harness = """
int main(void) {
    const uint32_t inputs[] = {0, 1, 2, 7, 19, 0x7fffffff, 0x80000000, 0xffffffff};
    for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i) {
        uint32_t x = inputs[i];
        calls = 0;
        uint32_t value = flattened(x);
        printf("%u %u %u %u %u %u %u %u %llu\\n", x, value, observed, calls,
               (uint32_t)alias_join(x), (uint32_t)alias_escape(x), (uint32_t)partial_write(x),
               (uint32_t)loop_alias(x), (unsigned long long)wide_state(x));
    }
    return 0;
}
"""
    # Named argument decorations are display metadata, not C syntax.
    bodies = [re.sub(r"\b(?:a[0-9]+|input|p|q):\s*", "", texts[name]) for name in names]
    (out / "recovered.c").write_text(header + "\n\n".join(bodies) + harness)
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(str(error))
    report["traceback"] = traceback.format_exc()

(out / "hikari_dispatch.json").write_text(json.dumps(report, indent=2) + "\n")
print("[chernobog][hikari-dispatch] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 1)
