"""Parameterized no-cache Hex-Rays decompilation regression probe."""

import os
import time
from pathlib import Path

import ida_auto
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_pro


TARGET_EA = int(os.environ["CHERNOBOG_SMOKE_EA"], 0)


def finish(code, message):
    line = "[chernobog][decompile-probe] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")

    function_start = ida_funcs.get_func_start(TARGET_EA)
    if function_start == ida_idaapi.BADADDR:
        finish(3, "no function contains 0x%X" % TARGET_EA)

    started = time.monotonic()
    failure = ida_hexrays.hexrays_failure_t()
    cfunc = ida_hexrays.decompile_function(
        function_start, failure, ida_hexrays.DECOMP_NO_CACHE
    )
    elapsed = time.monotonic() - started
    if cfunc is None:
        finish(
            4,
            "FAIL function=0x%X requested=0x%X elapsed=%.3f s "
            "code=%d ea=0x%X description=%s"
            % (
                function_start,
                TARGET_EA,
                elapsed,
                failure.code,
                failure.errea,
                failure.desc(),
            ),
        )

    pseudocode = "\n".join(
        ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()
    )
    output_path = os.environ.get("CHERNOBOG_PSEUDOCODE_OUT")
    if output_path:
        Path(output_path).write_text(pseudocode + "\n", encoding="utf-8")
    finish(
        0,
        "PASS function=0x%X requested=0x%X elapsed=%.3f s "
        "pseudocode_lines=%d"
        % (
            function_start,
            TARGET_EA,
            elapsed,
            len(pseudocode.splitlines()),
        ),
    )
except BaseException as error:
    finish(9, "exception: %r" % (error,))
