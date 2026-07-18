"""Batch-mode smoke test for current-function rax exploration.

Run under IDA, not CPython. The caller supplies CHERNOBOG_SMOKE_EA and may
override CHERNOBOG_PLUGIN_PATH. A non-zero IDA exit code denotes a failed
precondition or action invocation; detailed rax evidence remains in IDA's log.
"""

import os

import ida_auto
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_pro


def finish(code, message):
    line = "[chernobog][smoke] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")

    plugin_path = os.environ.get(
        "CHERNOBOG_PLUGIN_PATH",
        os.path.expanduser("~/.idapro/plugins/chernobog.dylib"),
    )
    plugin = ida_loader.load_plugin(plugin_path)
    if plugin is None:
        finish(3, "plugin load failed: %s" % plugin_path)

    raw_ea = os.environ.get("CHERNOBOG_SMOKE_EA")
    if raw_ea is None:
        finish(4, "CHERNOBOG_SMOKE_EA is not set")
    address = int(raw_ea, 0)
    os.environ["CHERNOBOG_RAX_BATCH_EA"] = raw_ea
    function_start = ida_funcs.get_func_start(address)
    if function_start == ida_idaapi.BADADDR:
        finish(5, "no function contains 0x%X" % address)

    # Text-mode IDA cannot create a Qt pseudocode widget. The plugin resolves
    # the authoritative CHERNOBOG_RAX_BATCH_EA; keep the screen EA aligned for
    # diagnostic output from IDA itself.
    ida_kernwin.jumpto(function_start)

    if not ida_loader.run_plugin(plugin, 0x524158):
        finish(7, "rax batch plugin invocation failed")
    finish(0, "PASS function=0x%X" % function_start)
except BaseException as error:  # IDAPython must convert every failure to qexit.
    finish(9, "exception: %r" % (error,))
