"""Batch smoke test for Chernobog's compiled switch-dispatch detector."""

import os

import ida_auto
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_pro


def finish(code, message):
    line = "[chernobog][cff-detector-smoke] %s" % message
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
    function_start = ida_funcs.get_func_start(address)
    if function_start == ida_idaapi.BADADDR:
        finish(5, "no function contains 0x%X" % address)

    os.environ["CHERNOBOG_CFF_BATCH_EA"] = raw_ea
    if not ida_loader.run_plugin(plugin, 0x434646):
        finish(7, "CFF detector rejected function 0x%X" % function_start)
    finish(0, "PASS function=0x%X" % function_start)
except BaseException as error:
    finish(9, "exception: %r" % (error,))
