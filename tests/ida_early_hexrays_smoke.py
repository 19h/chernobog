"""IDA batch smoke test for stage-correct early Hex-Rays analysis.

The caller supplies CHERNOBOG_PLUGIN_PATH and opens the generic-deobfuscator
ASPack 2.12 fixture.  The first entry-point call uses a pop/inc/push/return
get-PC gadget whose effective continuation is 0x403008.
"""

import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_loader
import ida_pro
import ida_xref


def finish(code, message):
    line = "[chernobog][early-hexrays-smoke] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")

    preloaded = os.environ.get("CHERNOBOG_PLUGIN_PRELOADED") == "1"
    if not preloaded:
        plugin_path = os.environ["CHERNOBOG_PLUGIN_PATH"]
        plugin = ida_loader.load_plugin(plugin_path)
        if plugin is None:
            finish(3, "plugin load failed: %s" % plugin_path)

    function = ida_funcs.get_func(0x403002)
    if function is None:
        finish(4, "fixture function at 0x403002 was not discovered")

    if not preloaded:
        # When explicitly loaded after IDA's first autoanalysis, re-plan only
        # the fixture function so ev_emu_insn creates the early-stage marker.
        ida_auto.plan_and_wait(function.start_ea, function.end_ea)

    for call_ea in (0x403002, 0x40300E):
        comment = ida_bytes.get_cmt(call_ea, True) or ""
        if "[chernobog][ida-analysis] call+pop" not in comment:
            finish(
                5,
                "native call/pop marker absent at 0x%X: %r"
                % (call_ea, comment),
            )

    marked_gadget = False
    observed_xrefs = []
    xref = ida_xref.xrefblk_t()
    valid = xref.first_from(0x403002, ida_xref.XREF_ALL)
    while valid:
        observed_xrefs.append((xref.to, xref.type, xref.iscode))
        if (
            xref.to == 0x40300A
            and (xref.type & ida_xref.XREF_MASK) == ida_xref.fl_JN
        ):
            marked_gadget = True
            break
        valid = xref.next_from()
    if not marked_gadget:
        target_flags = ida_bytes.get_flags(0x40300A)
        target_state = {
            "code": ida_bytes.is_code(target_flags),
            "head": ida_bytes.is_head(target_flags),
            "tail": ida_bytes.is_tail(target_flags),
        }
        finish(
            6,
            "fl_JN call/pop marker 0x403002 -> 0x40300A absent; "
            "xrefs=%r target=%r" % (observed_xrefs, target_state),
        )

    if not ida_bytes.is_code(ida_bytes.get_flags(0x403008)):
        finish(6, "effective continuation 0x403008 is not code")
    if ida_bytes.is_code(ida_bytes.get_flags(0x403007)):
        finish(6, "junk byte 0x403007 remains code")
    if ida_bytes.is_code(ida_bytes.get_flags(0x403013)):
        finish(6, "junk byte 0x403013 remains code")

    second_jump = False
    xref = ida_xref.xrefblk_t()
    valid = xref.first_from(0x40300E, ida_xref.XREF_ALL)
    while valid:
        if (
            xref.to == 0x403014
            and (xref.type & ida_xref.XREF_MASK) == ida_xref.fl_JN
        ):
            second_jump = True
            break
        valid = xref.next_from()
    if not second_jump:
        finish(6, "inline-pop edge 0x40300E -> 0x403014 absent")
    for address in (0x403008, 0x403014):
        if not ida_funcs.function_contains(function.start_ea, address):
            finish(6, "0x%X is outside function 0x%X" % (address, function.start_ea))

    cfunc = ida_hexrays.decompile(
        function.start_ea, None, ida_hexrays.DECOMP_NO_CACHE
    )
    if cfunc is None:
        finish(7, "decompilation failed")
    first = str(cfunc)

    second_cfunc = ida_hexrays.decompile(
        function.start_ea, None, ida_hexrays.DECOMP_NO_CACHE
    )
    if second_cfunc is None or str(second_cfunc) != first:
        finish(8, "no-cache decompilation was not stable")

    finish(
        0,
        "PASS function=0x%X pseudocode_chars=%d"
        % (function.start_ea, len(first)),
    )
except BaseException as error:
    finish(9, "exception: %r" % (error,))
