"""IDA batch smoke test for native and pre-MBA ACProtect CFG recovery."""

import re

import ida_auto
import ida_bytes
import ida_funcs
import ida_gdl
import ida_hexrays
import ida_kernwin
import ida_pro
import ida_xref
import idautils
import idc


def finish(code, message):
    line = "[chernobog][early-acprotect-smoke] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


def has_xref(source, target, expected_type):
    xref = ida_xref.xrefblk_t()
    valid = xref.first_from(source, ida_xref.XREF_ALL)
    while valid:
        if (
            xref.to == target
            and (xref.type & ida_xref.XREF_MASK) == expected_type
        ):
            return True
        valid = xref.next_from()
    return False


def xrefs_from(source):
    result = []
    xref = ida_xref.xrefblk_t()
    valid = xref.first_from(source, ida_xref.XREF_ALL)
    while valid:
        result.append((xref.to, xref.type, xref.iscode, xref.user))
        valid = xref.next_from()
    return result


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")

    # ACProtect: call $+1; junk; add [esp], 6; retn. The sites form a
    # reachability chain, so checking all eight detects a repair that only
    # handles the entry gadget without propagating its recovered CFG.
    cases = (
        (0x405013, 0x405019, 0x40501E),
        (0x405056, 0x40505C, 0x405061),
        (0x4050E7, 0x4050ED, 0x4050F2),
        (0x405100, 0x405106, 0x40510B),
        (0x40511F, 0x405125, 0x40512A),
        (0x405133, 0x405139, 0x40513E),
        (0x40514D, 0x405153, 0x405158),
        (0x40515C, 0x405162, 0x405167),
    )
    failures = []
    function = ida_funcs.get_func(0x405000)
    if function is None or function.start_ea != 0x405000:
        finish(3, "function 0x405000 absent")

    for call_ea, gadget_ea, continuation_ea in cases:
        comment = ida_bytes.get_cmt(call_ea, True) or ""
        if "[chernobog][ida-analysis] call+pop" not in comment:
            failures.append("marker@0x%X" % call_ea)
        if not has_xref(call_ea, gadget_ea, ida_xref.fl_JN):
            failures.append("jump@0x%X" % call_ea)
        if not ida_bytes.is_code(ida_bytes.get_flags(continuation_ea)):
            failures.append("code@0x%X" % continuation_ea)
        if not ida_funcs.function_contains(function.start_ea, continuation_ea):
            owner_ea = ida_funcs.get_func_start(continuation_ea)
            failures.append(
                "chunk@0x%X(owner=0x%X)" % (continuation_ea, owner_ea)
            )
        return_ea = gadget_ea + 4
        if not has_xref(return_ea, continuation_ea, ida_xref.fl_F):
            failures.append("flow@0x%X" % return_ea)

    orphan_blocks = []
    flowchart = ida_gdl.FlowChart(function, flags=ida_gdl.FC_PREDS)
    for block in flowchart:
        if block.start_ea != function.start_ea and not list(block.preds()):
            orphan_blocks.append(block.start_ea)
    if orphan_blocks:
        failures.append(
            "orphans=%s"
            % ",".join("0x%X" % address for address in orphan_blocks)
        )
    if failures:
        diagnostics = {
            "chunks": list(idautils.Chunks(function.start_ea)),
            "comments": {
                "0x405013": ida_bytes.get_cmt(0x405013, True),
                "0x405025": ida_bytes.get_cmt(0x405025, True),
            },
            "xrefs": {
                "0x405013": xrefs_from(0x405013),
                "0x40501D": xrefs_from(0x40501D),
                "0x405025": xrefs_from(0x405025),
                "0x405031": xrefs_from(0x405031),
                "0x405033": xrefs_from(0x405033),
            },
            "items": [
                (
                    address,
                    ida_bytes.get_item_head(address),
                    ida_bytes.get_item_end(address),
                    ida_bytes.is_code(ida_bytes.get_flags(address)),
                    idc.generate_disasm_line(address, 0),
                )
                for address in range(0x405036, 0x405041)
            ],
        }
        ida_kernwin.msg(
            "[chernobog][early-acprotect-smoke] diagnostics=%r\n"
            % diagnostics
        )
        finish(4, "native CFG incomplete: %s" % "; ".join(failures))

    failure = ida_hexrays.hexrays_failure_t()
    cfunc = ida_hexrays.decompile(
        function.start_ea, failure, ida_hexrays.DECOMP_NO_CACHE
    )
    if cfunc is None:
        stack_points = {
            "0x%X" % address: idc.get_spd(address)
            for address in (
                0x405013,
                0x405019,
                0x40501D,
                0x40501E,
                0x405025,
                0x40502B,
                0x405039,
                0x40503F,
                0x405056,
                0x40505C,
                0x405060,
                0x405061,
                0x405172,
                0x405178,
                0x40517B,
            )
        }
        ida_kernwin.msg(
            "[chernobog][early-acprotect-smoke] spd=%r\n" % stack_points
        )
        finish(
            5,
            "decompilation failed: %s (code=%d ea=0x%X)"
            % (str(failure), failure.code, failure.errea),
        )
    pseudocode = str(cfunc)
    required = {
        "loop": re.search(r"\b(for|while|do)\b", pseudocode) is not None,
        "rotation": "__ROL4__" in pseudocode,
        "key": "-17858287" in pseudocode or "0XFEEFBB11" in pseudocode.upper(),
        "count": "60" in pseudocode,
    }
    missing = [name for name, present in required.items() if not present]
    if missing:
        finish(
            6,
            "decompilation missing %s (%d characters)"
            % (", ".join(missing), len(pseudocode)),
        )

    # Exercise hxe_flowchart independently of the persisted native repair. The
    # batch harness always imports a disposable copy of the fixture. Remove the
    # adjacent return edges, force a no-cache decompilation, then restore them.
    # The in-flight flowchart pass must reconnect all effective continuations.
    removed = []
    repaired_pseudocode = ""
    repair_failure = ida_hexrays.hexrays_failure_t()
    try:
        for _, gadget_ea, continuation_ea in cases:
            return_ea = gadget_ea + 4
            ida_xref.del_cref(return_ea, continuation_ea, False)
            if not has_xref(return_ea, continuation_ea, ida_xref.fl_F):
                removed.append((return_ea, continuation_ea))
        if len(removed) != len(cases):
            finish(7, "could not stage the flowchart repair control")
        repaired = ida_hexrays.decompile(
            function.start_ea,
            repair_failure,
            ida_hexrays.DECOMP_NO_CACHE,
        )
        if repaired is None:
            finish(
                8,
                "flowchart-stage decompilation failed: %s (code=%d ea=0x%X)"
                % (
                    str(repair_failure),
                    repair_failure.code,
                    repair_failure.errea,
                ),
            )
        repaired_pseudocode = str(repaired)
    finally:
        for return_ea, continuation_ea in removed:
            ida_xref.add_cref(return_ea, continuation_ea, ida_xref.fl_F)

    repaired_required = {
        "loop": re.search(r"\b(for|while|do)\b", repaired_pseudocode)
        is not None,
        "rotation": "__ROL4__" in repaired_pseudocode,
        "key": "-17858287" in repaired_pseudocode
        or "0XFEEFBB11" in repaired_pseudocode.upper(),
        "count": "60" in repaired_pseudocode,
    }
    repaired_missing = [
        name for name, present in repaired_required.items() if not present
    ]
    if repaired_missing:
        finish(
            8,
            "flowchart-stage output missing %s (%d characters)"
            % (", ".join(repaired_missing), len(repaired_pseudocode)),
        )

    finish(
        0,
        "PASS function=0x405000 gadgets=%d blocks=%d pseudocode_chars=%d "
        "flowchart_control_chars=%d"
        % (
            len(cases),
            flowchart.size,
            len(pseudocode),
            len(repaired_pseudocode),
        ),
    )
except BaseException as error:
    finish(9, "exception: %r" % (error,))
