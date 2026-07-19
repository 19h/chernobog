"""Parameterized IDA batch regression for native call/pop false positives."""

import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_pro
import ida_xref


def addresses(name):
    raw = os.environ.get(name, "")
    return [int(value.strip(), 0) for value in raw.split(",") if value.strip()]


def finish(code, message):
    line = "[chernobog][native-negative-smoke] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


def has_jump_marker(source):
    xref = ida_xref.xrefblk_t()
    valid = xref.first_from(source, ida_xref.XREF_ALL)
    while valid:
        if (xref.type & ida_xref.XREF_MASK) == ida_xref.fl_JN:
            return True
        valid = xref.next_from()
    return False


try:
    ida_auto.auto_wait()
    calls = addresses("CHERNOBOG_NEGATIVE_CALLS")
    functions = addresses("CHERNOBOG_NEGATIVE_FUNCTIONS")
    decompile = addresses("CHERNOBOG_NEGATIVE_DECOMPILE")
    failures = []

    for call_ea in calls:
        comments = "\n".join(
            value
            for value in (
                ida_bytes.get_cmt(call_ea, False),
                ida_bytes.get_cmt(call_ea, True),
            )
            if value
        )
        if "[chernobog][ida-analysis] call+" in comments:
            failures.append("comment@0x%X" % call_ea)
        if has_jump_marker(call_ea):
            failures.append("fl_JN@0x%X" % call_ea)

    for function_ea in functions:
        actual_start = ida_funcs.get_func_start(function_ea)
        if actual_start != function_ea:
            failures.append("function@0x%X" % function_ea)
            flags = ida_bytes.get_flags(function_ea)
            owners = []
            owner = ida_funcs.get_func(function_ea)
            if owner is not None:
                owners.append("0x%X-0x%X" % (owner.start_ea, owner.end_ea))
            incoming = []
            xref = ida_xref.xrefblk_t()
            valid = xref.first_to(function_ea, ida_xref.XREF_ALL)
            while valid:
                incoming.append(
                    "0x%X/type=%d" % (xref.frm, xref.type)
                )
                valid = xref.next_to()
            print(
                "[chernobog][native-negative-smoke] diagnostic "
                "ea=0x%X start=0x%X code=%d head=%d tail=%d owners=%s incoming=%s"
                % (
                    function_ea,
                    actual_start,
                    ida_bytes.is_code(flags),
                    ida_bytes.is_head(flags),
                    ida_bytes.is_tail(flags),
                    ",".join(owners) or "none",
                    ",".join(incoming) or "none",
                ),
                flush=True,
            )

    if decompile and not ida_hexrays.init_hexrays_plugin():
        failures.append("hexrays")
    for function_ea in decompile:
        failure = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile(
            function_ea, failure, ida_hexrays.DECOMP_NO_CACHE
        )
        if cfunc is None:
            failures.append(
                "decompile@0x%X(code=%d,ea=0x%X)"
                % (function_ea, failure.code, failure.errea)
            )

    if failures:
        finish(2, "FAIL %s" % "; ".join(failures))
    finish(
        0,
        "PASS calls=%d functions=%d decompiled=%d"
        % (len(calls), len(functions), len(decompile)),
    )
except BaseException as error:
    finish(9, "exception: %r" % (error,))
