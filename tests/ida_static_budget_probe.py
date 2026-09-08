"""Measure explicit exploration of the large budget fixture inside live IDA.

The caller sets the static/execution limits with the pristine runner's --set.
The probe verifies fixture extent and successful invocations; compare the
plugin's static IDA_heads/physical counters in ida.log to validate budget work.
"""

import json
import os
from pathlib import Path
import time

import ida_auto
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro
import idautils


def finish(code, message):
    line = "[chernobog][static-budget] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")
    address = ida_name.get_name_ea(ida_idaapi.BADADDR, "_budget_fixture")
    if address == ida_idaapi.BADADDR:
        address = ida_name.get_name_ea(ida_idaapi.BADADDR, "budget_fixture")
    function = ida_funcs.get_func(address)
    if function is None or function.start_ea != address:
        finish(3, "fixture entry not found")
    heads = sum(1 for _ in idautils.FuncItems(address))
    if heads != 65537:
        finish(4, "expected 65537 fixture heads, found %d" % heads)
    plugin = ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    if plugin is None:
        finish(5, "plugin load failed")
    os.environ["CHERNOBOG_RAX_BATCH_EA"] = hex(address)
    durations = []
    for repeat in range(4):
        started = time.perf_counter_ns()
        ok = ida_loader.run_plugin(plugin, 0x524158)
        durations.append(time.perf_counter_ns() - started)
        if not ok:
            finish(6, "exploration invocation failed")
    output = Path(os.environ["IDAUSR"]).parent / "static_budget.json"
    output.write_text(json.dumps({
        "schema_version": 1,
        "function_start": address,
        "fixture_heads": heads,
        "exploration_elapsed_ns": durations,
        "static_limit": int(os.environ["CHERNOBOG_RAX_MAX_STATIC_INSNS"], 0),
    }, indent=2) + "\n", encoding="utf-8")
    finish(0, "PASS heads=%d elapsed_ns=%r" % (heads, durations))
except BaseException as error:
    finish(99, "exception: %r" % error)
