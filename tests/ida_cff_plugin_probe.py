"""Exercise Chernobog's real Hex-Rays callback on the reference CFF main."""

import time

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
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
    function = ida_funcs.get_func(TARGET_EA)
    if function is None or function.start_ea != TARGET_EA:
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
    finish(0, "PASS decompiled main in %.3f s" % elapsed)
except BaseException as error:
    finish(9, "exception: %r" % (error,))
