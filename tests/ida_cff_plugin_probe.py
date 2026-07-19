"""Exercise Chernobog's real Hex-Rays callback on the reference CFF main."""

import difflib
import os
import re
import time
from pathlib import Path

import ida_auto
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_pro


TARGET_EA = 0x82AF0
DECOMPILE_RUNS = 3


def finish(code, message):
    line = "[chernobog][cff-plugin-probe] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


def decompile_no_cache():
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
    return elapsed, pseudocode


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")
    function_start = ida_funcs.get_func_start(TARGET_EA)
    if function_start == ida_idaapi.BADADDR or function_start != TARGET_EA:
        finish(3, "reference function 0x%X was not discovered" % TARGET_EA)

    elapsed_runs = []
    pseudocode_runs = []
    for _ in range(DECOMPILE_RUNS):
        elapsed, pseudocode = decompile_no_cache()
        elapsed_runs.append(elapsed)
        pseudocode_runs.append(pseudocode)

    pseudocode = pseudocode_runs[-1]
    output_path = os.environ.get("CHERNOBOG_PSEUDOCODE_OUT")
    if output_path:
        Path(output_path).write_text(pseudocode + "\n", encoding="utf-8")
        for run_index, run_pseudocode in enumerate(pseudocode_runs, 1):
            Path("%s.run%d" % (output_path, run_index)).write_text(
                run_pseudocode + "\n", encoding="utf-8"
            )
    dispatcher_markers = (
        "0x83DAC1F1",
        "0x2ED4B00E",
    )
    run_metrics = []
    for run_index, run_pseudocode in enumerate(pseudocode_runs, 1):
        case_labels = run_pseudocode.count("case ")
        surviving_markers = [
            marker for marker in dispatcher_markers
            if marker in run_pseudocode
        ]
        if surviving_markers or case_labels >= 200:
            finish(
                5,
                "run %d retained flattened dispatcher: markers=%s "
                "case_labels=%d"
                % (
                    run_index,
                    ",".join(surviving_markers) or "none",
                    case_labels,
                ),
            )

        resolver_calls = re.findall(
            r"sub_521D0\((?:(?!\);).)*\);",
            run_pseudocode,
            flags=re.DOTALL,
        )
        non_neutralized = [
            call for call in resolver_calls if "a2: 0" not in call
        ]
        if len(resolver_calls) >= 8 and non_neutralized:
            finish(
                6,
                "run %d retained resolver noise in %d/%d recurrent calls"
                % (
                    run_index,
                    len(non_neutralized),
                    len(resolver_calls),
                ),
            )
        run_metrics.append(
            (
                len(run_pseudocode.splitlines()),
                case_labels,
                len(resolver_calls),
                len(resolver_calls) - len(non_neutralized),
            )
        )
    # Hex-Rays may persist type refinements discovered from the first clean
    # ctree (for this sample, _BYTE[59] converges to char[59]). Require the two
    # subsequent no-cache builds to be byte-identical so lifecycle replay is
    # deterministic after that documented one-pass convergence.
    if pseudocode_runs[-2] != pseudocode_runs[-1]:
        differences = list(
            difflib.unified_diff(
                pseudocode_runs[-2].splitlines(),
                pseudocode_runs[-1].splitlines(),
                fromfile="run%d" % (DECOMPILE_RUNS - 1),
                tofile="run%d" % DECOMPILE_RUNS,
                n=1,
            )
        )
        first_difference = next(
            (
                line for line in differences
                if (line.startswith("+") or line.startswith("-"))
                and not line.startswith("+++")
                and not line.startswith("---")
            ),
            "unknown",
        )
        finish(
            7,
            "converged no-cache decompilation output was not repeatable "
            "(first_diff=%r)" % first_difference,
        )

    lines, case_labels, resolver_count, neutralized_count = run_metrics[-1]
    finish(
        0,
        "PASS %d no-cache runs removed dispatcher in %.3f/%.3f s "
        "(pseudocode_lines=%d case_labels=%d resolver_calls=%d "
        "neutralized_args=%d)"
        % (
            DECOMPILE_RUNS,
            min(elapsed_runs),
            max(elapsed_runs),
            lines,
            case_labels,
            resolver_count,
            neutralized_count,
        ),
    )
except BaseException as error:
    finish(9, "exception: %r" % (error,))
