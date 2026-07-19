"""Scan every function for Hex-Rays failures with the active plugin set."""

import time

import ida_auto
import ida_hexrays
import ida_kernwin
import ida_pro
import idautils


def emit(message):
    line = "[chernobog][interr-scan] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)


def finish(code, message):
    emit(message)
    ida_pro.qexit(code)


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")

    functions = list(idautils.Functions())
    failures = []
    critical_failures = []
    started = time.monotonic()
    for index, function_ea in enumerate(functions, 1):
        failure = ida_hexrays.hexrays_failure_t()
        try:
            cfunc = ida_hexrays.decompile_function(
                function_ea, failure, ida_hexrays.DECOMP_NO_CACHE
            )
            if cfunc is None:
                description = failure.desc()
                record = (
                    "0x%X(code=%d,ea=0x%X,%s)"
                    % (
                        function_ea,
                        failure.code,
                        failure.errea,
                        description,
                    )
                )
                failures.append(record)
                normalized = description.upper()
                if "INTERR" in normalized or "TIME" in normalized:
                    critical_failures.append(record)
        except BaseException as error:
            record = "0x%X(exception=%r)" % (function_ea, error)
            failures.append(record)
            critical_failures.append(record)
        if index % 100 == 0:
            emit(
                "progress=%d/%d failures=%d elapsed=%.3f s"
                % (index, len(functions), len(failures), time.monotonic() - started)
            )

    elapsed = time.monotonic() - started
    if critical_failures:
        for failure in failures:
            emit("failure=%s" % failure)
        finish(
            3,
            "FAIL functions=%d critical=%d other_failures=%d elapsed=%.3f s"
            % (
                len(functions),
                len(critical_failures),
                len(failures) - len(critical_failures),
                elapsed,
            ),
        )
    for failure in failures:
        emit("non-interr=%s" % failure)
    finish(
        0,
        "PASS functions=%d critical=0 other_failures=%d elapsed=%.3f s"
        % (len(functions), len(failures), elapsed),
    )
except BaseException as error:
    finish(9, "scan exception: %r" % (error,))
