"""Live model integration: bounded libc calls gate runtime string recovery."""

import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro


def finish(code, message):
    line = "[chernobog][bounded-search] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


def symbol(name):
    address = ida_name.get_name_ea(ida_idaapi.BADADDR, "_" + name)
    if address == ida_idaapi.BADADDR:
        address = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    if address == ida_idaapi.BADADDR:
        finish(2, "missing symbol " + name)
    return address


class Literals(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.values = []

    def visit_expr(self, expression):
        if expression.op == ida_hexrays.cot_str:
            self.values.append(expression.string)
        return 0


def decompile(address):
    cfunc = ida_hexrays.decompile(address, None, ida_hexrays.DECOMP_NO_CACHE)
    if cfunc is None:
        finish(4, "decompilation failed")
    literals = Literals()
    literals.apply_to(cfunc.body, None)
    return cfunc, literals.values


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")
    plugin = ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    if plugin is None:
        finish(3, "plugin load failed")
    address = symbol("bounded_search_fixture")
    output = symbol("bounded_output")
    needle = symbol("bounded_needle")
    expected = "bounded search OK"
    original_output = ida_bytes.get_bytes(output, len(expected) + 1)
    first, literals = decompile(address)
    if expected not in literals:
        finish(5, "bounded libc calls did not yield the runtime literal")
    second, literals = decompile(address)
    if expected not in literals:
        finish(6, "runtime literal missing on repeated uncached decompilation")
    (Path(os.environ["IDAUSR"]).parent / "bounded_search_pseudocode.txt").write_text(
        str(second), encoding="utf-8")
    original_needle = ida_bytes.get_bytes(needle, 4)
    try:
        # None of the three fixture bytes equals zero. The changed memchr
        # result must select the early return and invalidate the old literal.
        ida_bytes.patch_bytes(needle, bytes(4))
        changed, literals = decompile(address)
    finally:
        ida_bytes.patch_bytes(needle, original_needle)
    if expected in literals:
        finish(7, "changed memchr result retained the stale literal")
    if ida_bytes.get_bytes(output, len(expected) + 1) != original_output:
        finish(8, "runtime exploration changed IDB output bytes")
    finish(0, "PASS memchr + strnlen literal recovery and invalidation")
except BaseException as error:
    finish(99, "exception: %r" % error)
