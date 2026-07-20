"""IDA batch smoke test for preoptimized constants and character numforms."""

import os

import ida_auto
import ida_hexrays
import ida_kernwin
import ida_pro


def finish(code, message):
    line = "[chernobog][early-constants-smoke] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")

    string_target = 0x15F54
    heavy_target = 0x23E44
    expect_vector = os.environ.get("CHERNOBOG_EXPECT_VECTOR", "1") != "0"
    skip_heavy = os.environ.get("CHERNOBOG_SKIP_HEAVY", "0") == "1"

    failure = ida_hexrays.hexrays_failure_t()
    string_cfunc = ida_hexrays.decompile(
        string_target, failure, ida_hexrays.DECOMP_NO_CACHE
    )
    if string_cfunc is None:
        finish(
            3,
            "string function failed: %s (code=%d ea=0x%X)"
            % (str(failure), failure.code, failure.errea),
        )
    string_text = str(string_cfunc)
    has_vector = '"vector"' in string_text
    if has_vector != expect_vector:
        ida_kernwin.msg(
            "[chernobog][early-constants-smoke] string pseudocode:\n%s\n"
            % string_text
        )
        finish(
            4,
            "vector expectation=%d observed=%d pseudocode_chars=%d"
            % (expect_vector, has_vector, len(string_text)),
        )

    heavy_text = ""
    if not skip_heavy:
        heavy_failure = ida_hexrays.hexrays_failure_t()
        heavy_cfunc = ida_hexrays.decompile(
            heavy_target, heavy_failure, ida_hexrays.DECOMP_NO_CACHE
        )
        if heavy_cfunc is None:
            finish(
                5,
                "heavy function failed: %s (code=%d ea=0x%X)"
                % (
                    str(heavy_failure),
                    heavy_failure.code,
                    heavy_failure.errea,
                ),
            )
        heavy_text = str(heavy_cfunc)

    finish(
        0,
        "PASS vector=%d string_chars=%d heavy_chars=%d"
        % (has_vector, len(string_text), len(heavy_text)),
    )
except BaseException as error:
    finish(9, "exception: %r" % (error,))
