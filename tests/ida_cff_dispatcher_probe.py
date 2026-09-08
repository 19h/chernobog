"""Read-only microcode topology diagnostic for recurrent switch rejection.

The selected function and dispatcher addresses are supplied by CHERNOBOG_SMOKE_EA
and CHERNOBOG_DISPATCH_EA, defaulting to the reference ELF. Use an isolated raw
input and CHERNOBOG_DISABLE=1 to inspect the decompiler without transformations.
Set CHERNOBOG_CFF_DUMP_GLBOPT=1 to include the later global-optimization form.
Set CHERNOBOG_CFF_REQUIRE_SWITCH=1 to assert that the LOCOPT microcode retains
every native switch case and target after the table's lowcase normalization,
including the indirect-read regression.
"""

import json
import os
from pathlib import Path

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_nalt
import ida_pro
import ida_xref


TARGET_EA = int(os.environ.get("CHERNOBOG_SMOKE_EA", "0x82AF0"), 0)
DISPATCH_EA = int(os.environ.get("CHERNOBOG_DISPATCH_EA", "0x82C65"), 0)


def emit(message):
    line = "[chernobog][cff-dispatcher-probe] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)


def finish(code, message):
    emit(message)
    ida_pro.qexit(code)


def block_record(block):
    instructions = []
    instruction = block.head
    while instruction is not None:
        instructions.append({
            "ea": instruction.ea,
            "opcode": instruction.opcode,
            "text": instruction.dstr(),
        })
        instruction = instruction.next
    return {
        "serial": block.serial, "start": block.start, "end": block.end,
        "type": block.type, "pred": list(block.predset),
        "succ": [block.succ(index) for index in range(block.nsucc())],
        "instructions": instructions,
    }


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")
    function = ida_funcs.get_func(TARGET_EA)
    if function is None:
        finish(3, "function not found")
    records = []
    maturities = [("LOCOPT", ida_hexrays.MMAT_LOCOPT)]
    if os.environ.get("CHERNOBOG_CFF_DUMP_GLBOPT") == "1":
        maturities.append(("GLBOPT1", ida_hexrays.MMAT_GLBOPT1))
    for label, maturity in maturities:
        failure = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(
            ida_hexrays.mba_ranges_t(function), failure, None,
            ida_hexrays.DECOMP_NO_CACHE, maturity,
        )
        if mba is None:
            finish(4, "%s generation failed: %s" % (label, failure.desc()))
        dispatch = None
        switch = None
        native_switch = None
        for index in range(mba.qty):
            block = mba.get_mblock(index)
            if block.start <= DISPATCH_EA < block.end:
                dispatch = block
            if block.nsucc() >= 8 and (switch is None or block.nsucc() > switch.nsucc()):
                switch = block
            if block.tail is not None and ida_nalt.get_switch_info(block.tail.ea) is not None:
                native_switch = block
        if switch is None:
            switch = native_switch
        if dispatch is None or switch is None:
            finish(5, "%s dispatcher or switch absent" % label)
        metadata = ida_nalt.get_switch_info(switch.tail.ea)
        native_cases = []
        if metadata is not None:
            decoded = ida_xref.calc_switch_cases(switch.tail.ea, metadata)
            native_cases = [
                {"values": [int(value) for value in decoded.cases[index]],
                 "target": int(target)}
                for index, target in enumerate(decoded.targets)
            ]
        record = {
            "maturity": label, "qty": mba.qty,
            "dispatcher": dispatch.serial, "switch": switch.serial,
            "tail_is_jtbl": switch.tail.opcode == ida_hexrays.m_jtbl,
            "tail_is_ijmp": switch.tail.opcode == ida_hexrays.m_ijmp,
            "native_cases": native_cases,
            "native_lowcase": int(metadata.get_lowcase()) if metadata is not None else None,
            "micro_cases": [
                {"values": [int(value) for value in switch.tail.r.c.values[index]],
                 "target_block": int(target)}
                for index, target in enumerate(switch.tail.r.c.targets)
            ] if switch.tail.opcode == ida_hexrays.m_jtbl else [],
            "blocks": [block_record(mba.get_mblock(index)) for index in sorted(
                set(range(min(16, mba.qty)))
                | {dispatch.serial, switch.serial}
                | set(dispatch.succ(index) for index in range(dispatch.nsucc()))
            )],
        }
        records.append(record)
        emit("maturity=%s qty=%d dispatch=%d switch=%d successors=%r switch_tail=%s"
             % (label, mba.qty, dispatch.serial, switch.serial,
                [dispatch.succ(index) for index in range(dispatch.nsucc())],
                switch.tail.dstr()))
    destination = Path(os.environ["IDAUSR"]).parent / "cff_dispatcher.json"
    destination.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    if os.environ.get("CHERNOBOG_CFF_REQUIRE_SWITCH") == "1":
        original = records[0]
        if not original["tail_is_jtbl"] or not original["native_cases"]:
            finish(6, "native switch lost its microcode case map")
        # Regenerate only when a second maturity was explicitly requested;
        # otherwise mba still owns the LOCOPT data inspected above.
        if len(records) != 1:
            finish(7, "switch assertion requires the LOCOPT-only probe")
        mask = (1 << (8 * switch.tail.l.size)) - 1
        native_mapping = {
            (value - original["native_lowcase"]) & mask: case["target"]
            for case in original["native_cases"] for value in case["values"]
        }
        micro_mapping = {
            value & mask: case["target_block"]
            for case in original["micro_cases"] for value in case["values"]
        }
        if set(native_mapping) != set(micro_mapping):
            finish(8, "native/microcode switch case keys differ")
        for value, target_ea in native_mapping.items():
            target = mba.get_mblock(micro_mapping[value])
            if (not target.start <= target_ea < target.end
                    or micro_mapping[value] not in [switch.succ(index)
                                                   for index in range(switch.nsucc())]):
                finish(9, "native/microcode target differs for case %s" % value)
    finish(0, "PASS output=%s" % destination)
except BaseException as error:
    finish(9, "exception: %r" % error)
