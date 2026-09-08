"""Count actual IDP analysis callbacks for fixed raw prefix decoder controls.

The observer returns zero, changes no bytes or database metadata, and is active
only during explicit decode_insn calls. The same probe applies to old and new
plugins; matched outputs determine the reduction in recursive decoder events.
"""
import collections
import json
import os
from pathlib import Path

import ida_allins
import ida_auto
import ida_bytes
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_name
import ida_pro
import ida_ua


CASES = {
    "np_plain_add": (3, False), "np_plain_nop": (1, False),
    "np_rep_add": (1, True), "np_repne_add": (1, True),
    "np_pause": (2, False), "np_rep_ret": (2, False),
    "np_rep_movsb": (2, False), "np_repne_cmpsb": (2, False),
    "np_mandatory_sse": (4, False), "np_rex_train": (5, False),
    "np_operand_train": (5, False),
}
REPEATS = 32


def finish(code, message):
    line = "[chernobog][native-prefix-gate] " + message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


def address(name):
    result = ida_name.get_name_ea(ida_idaapi.BADADDR, "_" + name)
    if result == ida_idaapi.BADADDR:
        result = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    if result == ida_idaapi.BADADDR:
        raise RuntimeError("missing symbol " + name)
    return result


class DecodeObserver(ida_idp.IDP_Hooks):
    def __init__(self):
        super().__init__()
        self.active = False
        self.events = collections.Counter()

    def ev_ana_insn(self, instruction):
        if self.active:
            self.events[int(instruction.ea)] += 1
        return 0


def instruction_record(instruction):
    return {
        "size": instruction.size, "itype": instruction.itype,
        "feature": instruction.get_canon_feature(),
        "auxpref": int(instruction.auxpref), "segpref": int(instruction.segpref),
        "insnpref": int(instruction.insnpref), "flags": int(instruction.flags),
        "operands": [{key: int(getattr(operand, key)) for key in
                      ("type", "dtype", "reg", "value", "addr", "flags",
                       "specval", "specflag1", "specflag2", "specflag3", "specflag4")}
                     for operand in instruction.ops if operand.type != ida_ua.o_void],
    }


try:
    ida_auto.auto_wait()
    observer = DecodeObserver()
    if not observer.hook():
        raise RuntimeError("IDP observer installation failed")
    records = []
    for name, (expected_size, redundant) in CASES.items():
        start = address(name)
        raw_before = ida_bytes.get_bytes(start, 8)
        observer.events.clear()
        decoded = []
        for _ in range(REPEATS):
            instruction = ida_ua.insn_t()
            observer.active = True
            size = ida_ua.decode_insn(instruction, start)
            observer.active = False
            if size != expected_size:
                raise RuntimeError("%s: decoded size %d, expected %d" %
                                   (name, size, expected_size))
            if redundant and instruction.itype != ida_allins.NN_nop:
                raise RuntimeError(name + ": redundant prefix was not preserved as a one-byte NOP")
            decoded.append(instruction_record(instruction))
        if any(record != decoded[0] for record in decoded):
            raise RuntimeError(name + ": repeated instruction semantics differ")
        if ida_bytes.get_bytes(start, 8) != raw_before:
            raise RuntimeError(name + ": native bytes changed")
        records.append({"name": name, "start": start, "repeats": REPEATS,
                        "raw_hex": raw_before.hex(), "instruction": decoded[0],
                        "analysis_events": sum(observer.events.values()),
                        "events_by_address": dict(observer.events)})
    observer.unhook()
    destination = Path(os.environ["IDAUSR"]).parent / "native_prefix_gate.json"
    destination.write_text(json.dumps(records, indent=2) + "\n")
    finish(0, "PASS cases=%d decode_calls=%d output=%s" %
           (len(records), len(records) * REPEATS, destination))
except BaseException as error:
    finish(9, "exception: %r" % error)
