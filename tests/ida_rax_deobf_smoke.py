"""Batch smoke test for automatic rax-before-deobfuscation integration.

Run under IDA. The caller supplies CHERNOBOG_SMOKE_EA and
CHERNOBOG_PLUGIN_PATH. The selected function must be the Aldaz Frida-check
fixture used by the integration test.
"""

import os

import ida_auto
import ida_bytes
import ida_hexrays
import ida_kernwin
import ida_loader
import ida_pro


def finish(code, message):
    line = "[chernobog][deobf-smoke] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")

    plugin_path = os.environ["CHERNOBOG_PLUGIN_PATH"]
    plugin = ida_loader.load_plugin(plugin_path)
    if plugin is None:
        finish(3, "plugin load failed: %s" % plugin_path)

    function_ea = int(os.environ["CHERNOBOG_SMOKE_EA"], 0)
    # Automatic batch decompilation must trigger rax from Hex-Rays function
    # ingress; the standalone CHERNOBOG_RAX_BATCH_EA action is intentionally
    # not armed here.
    cfunc = ida_hexrays.decompile(
        function_ea, None, ida_hexrays.DECOMP_NO_CACHE
    )
    if cfunc is None:
        finish(4, "decompilation failed at 0x%X" % function_ea)

    pseudocode = str(cfunc)
    expected_literals = (
        '"WARNING"',
        '"frida"',
        '"python"',
        '"27042"',
        '"lsof -i :%@"',
        '"frida-server"',
        '"Proceso sospechoso detectado: %@"',
        '"27020"',
        '"pgrep %@"',
        '"Frida detectado en puerto %@"',
        '"frida-trace"',
    )
    missing = [value for value in expected_literals if value not in pseudocode]
    if missing:
        finish(5, "runtime literals absent from pseudocode: %s" % missing)

    # A no-cache second decompilation must not run the byte-patching MBA pass a
    # second time. The destination range is sufficient to detect the observed
    # fragment-producing regression without assuming its plaintext content.
    destination = 0x1002118A6
    before = ida_bytes.get_bytes(destination, 12)
    second = ida_hexrays.decompile(
        function_ea, None, ida_hexrays.DECOMP_NO_CACHE
    )
    after = ida_bytes.get_bytes(destination, 12)
    if second is None or before != after:
        finish(6, "duplicate decompilation changed materialized data bytes")

    finish(
        0,
        "PASS function=0x%X runtime_literals=%d"
        % (function_ea, len(expected_literals)),
    )
except BaseException as error:
    finish(9, "exception: %r" % (error,))
