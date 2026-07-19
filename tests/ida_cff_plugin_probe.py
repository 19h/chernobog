"""Exercise Chernobog's real Hex-Rays callback on the reference CFF main."""

import time

import ida_auto
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_pro


TARGET_EA = 0x82AF0


def finish(code, message):
    line = "[chernobog][cff-plugin-probe] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")
    function_start = ida_funcs.get_func_start(TARGET_EA)
    if function_start == ida_idaapi.BADADDR or function_start != TARGET_EA:
        finish(3, "reference function 0x%X was not discovered" % TARGET_EA)

    started = time.monotonic()
    failure = ida_hexrays.hexrays_failure_t()
    cfunc = ida_hexrays.decompile_function(
        TARGET_EA, failure, ida_hexrays.DECOMP_NO_CACHE
    )
    elapsed = time.monotonic() - started
    if cfunc is None:
        finish(
            4,
            "decompilation failed after %.3f s: code=%s description=%s"
            % (elapsed, failure.code, failure.desc()),
        )

    pseudocode = "\n".join(
        ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()
    )
    case_labels = pseudocode.count("case ")
    dispatcher_markers = (
        "0x83DAC1F1",
        "0x2ED4B00E",
    )
    surviving_markers = [
        marker for marker in dispatcher_markers if marker in pseudocode
    ]
    if surviving_markers or case_labels >= 200:
        finish(
            5,
            "flattened dispatcher survived: markers=%s case_labels=%d"
            % (",".join(surviving_markers) or "none", case_labels),
        )
    finish(
        0,
        "PASS decompiled and removed dispatcher in %.3f s "
        "(pseudocode_lines=%d case_labels=%d)"
        % (elapsed, len(pseudocode.splitlines()), case_labels),
    )
except BaseException as error:
    finish(9, "exception: %r" % (error,))
