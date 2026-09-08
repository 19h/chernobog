"""Record guarded recurrent-switch CFGs in an isolated raw-binary IDA run.

The associated native fixture has eleven eight-state dispatchers. Address metadata
uses function-relative offsets so table data does not split function extents.
The GLBOPT3 interpreter checks concrete native-reference inputs independently of
the plugin's solver and fails on unsupported or uninitialized microcode values.
"""
import json
import hashlib
import os
from pathlib import Path

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_name
import ida_pro
import ida_bytes
import ida_lines
import ida_idp
import idautils

NAMES = (
    "rg_positive", "rg_late_guard", "rg_unknown_guard", "rg_global_effect",
    "rg_escaped_state", "rg_recurrence_register", "rg_middle_entry",
    "rg_register_effect", "rg_entry_cycle",
    "rg_restored_selector", "rg_corrupted_restore",
)


def encode(value):
    return (((value ^ 0x2468ACE0) - 0x13579BDF) ^ 0x9E3779B9) & 0xFFFFFFFF


SCENARIOS = {
    "rg_positive": [(0, 255)],
    "rg_late_guard": [(0, None)],
    "rg_unknown_guard": [(encode(4), 255), (encode(9), None), (encode(8), None)],
    "rg_global_effect": [(0, 255)],
    "rg_escaped_state": [(0, 255)],
    "rg_recurrence_register": [(0, 255)],
    "rg_middle_entry": [(0, None)],
    "rg_register_effect": [(0, 36)],
    "rg_entry_cycle": [(1, 255), (2, None)],
    "rg_restored_selector": [(0, 256), (1, 257)],
    "rg_corrupted_restore": [(0, None), (1, None)],
}


def emit(message):
    line = "[chernobog][recurrent-guard] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)


def finish(code, message):
    emit(message)
    ida_pro.qexit(code)


def address(name):
    result = ida_name.get_name_ea(ida_idaapi.BADADDR, "_" + name)
    if result == ida_idaapi.BADADDR:
        result = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    if result == ida_idaapi.BADADDR:
        raise RuntimeError("missing symbol " + name)
    return result


class InstructionAddresses(ida_hexrays.minsn_visitor_t):
    def __init__(self, mba):
        super().__init__()
        self.mba = mba
        self.records = []

    def visit_minsn(self):
        self.records.append({"ea": int(self.curins.ea),
                             "real_ea": int(self.mba.map_fict_ea(self.curins.ea)),
                             "opcode": self.curins.opcode})
        return 0


def block_record(block):
    instructions = []
    instruction = block.head
    while instruction is not None:
        instructions.append({
            "ea": int(instruction.ea),
            "real_ea": int(block.mba.map_fict_ea(instruction.ea)),
            "opcode": instruction.opcode,
            "text": instruction.dstr(),
        })
        instruction = instruction.next
    addresses = InstructionAddresses(block.mba)
    block.for_all_insns(addresses)
    return {
        "serial": block.serial, "start": int(block.start), "end": int(block.end),
        "type": block.type, "pred": list(block.predset),
        "succ": [block.succ(index) for index in range(block.nsucc())],
        "instructions": instructions,
        "instruction_addresses": addresses.records,
    }


def snapshot_bytes(ranges):
    result = []
    for start, end in ranges:
        data = ida_bytes.get_bytes(start, end - start)
        if data is None or len(data) != end - start:
            raise RuntimeError("unreadable function bytes at 0x%X" % start)
        result.append({"start": start, "end": end, "hex": data.hex(),
                       "sha256": hashlib.sha256(data).hexdigest()})
    return result


def verify_instruction_addresses(blocks, native_heads, reference_eas):
    mapped = []
    for block in blocks:
        for instruction in block["instruction_addresses"]:
            ea, real_ea = instruction["ea"], instruction["real_ea"]
            if ea == real_ea or real_ea == ida_idaapi.BADADDR:
                continue
            if real_ea not in native_heads:
                raise RuntimeError("fictional EA 0x%X maps outside native instructions: 0x%X"
                                   % (ea, real_ea))
            mapped.append({"ea": ea, "real_ea": real_ea,
                           "present_at_LOCOPT": real_ea in reference_eas})
    return mapped


class FixtureInterpreter:
    """Little-endian byte storage, bounded to 256 basic-block executions.

    Runtime is O(B * I * W), space O(S), where B <= 256, I is instructions
    and nested expression nodes per block, W <= 8 bytes, S is touched storage.
    None means no return within the bound, not an inferred nontermination proof.
    """
    STACK = 0x700000000000

    def __init__(self, mba, argument):
        self.mba = mba
        self.memory = {}
        self.registers = {}
        self.trace = []
        self.rdi = ida_hexrays.reg2mreg(ida_idp.str2reg("rdi"))
        self.rax = ida_hexrays.reg2mreg(ida_idp.str2reg("rax"))
        self.store(self.registers, self.rdi, 8, argument)
        self.store(self.memory, address("rg_guard_hits"), 4, 0)
        self.store(self.memory, address("rg_escape_ptr"), 8, 0)

    @staticmethod
    def store(storage, start, size, value):
        if not 0 < size <= 8:
            raise RuntimeError("unsupported store width %d" % size)
        for index in range(size):
            storage[start + index] = (value >> (8 * index)) & 255

    @staticmethod
    def read(storage, start, size):
        if not 0 < size <= 8:
            raise RuntimeError("unsupported read width %d" % size)
        # Missing bytes are an error rather than an invented zero value.
        return sum(storage[start + index] << (8 * index) for index in range(size))

    def location(self, operand):
        if operand.t == ida_hexrays.mop_r:
            return self.registers, int(operand.r)
        if operand.t == ida_hexrays.mop_S:
            return self.memory, self.STACK + int(operand.s.off)
        if operand.t == ida_hexrays.mop_v:
            return self.memory, int(operand.g)
        raise RuntimeError("unsupported lvalue " + operand.dstr())

    def value(self, operand):
        if operand.t == ida_hexrays.mop_n:
            return int(operand.nnn.value) & ((1 << (8 * operand.size)) - 1)
        if operand.t == ida_hexrays.mop_d:
            return self.expression(operand.d, operand.size)
        if operand.t == ida_hexrays.mop_a:
            storage, location = self.location(operand.a)
            if storage is not self.memory:
                raise RuntimeError("address of nonmemory operand")
            return location
        storage, location = self.location(operand)
        return self.read(storage, location, operand.size)

    def expression(self, instruction, width):
        opcode = instruction.opcode
        left = self.value(instruction.l)
        if opcode in (ida_hexrays.m_mov, ida_hexrays.m_xdu, ida_hexrays.m_low):
            result = left
        elif opcode == ida_hexrays.m_xds:
            bits = 8 * instruction.l.size
            result = left - (1 << bits) if left & (1 << (bits - 1)) else left
        else:
            right = self.value(instruction.r)
            operations = {
                ida_hexrays.m_add: lambda: left + right,
                ida_hexrays.m_sub: lambda: left - right,
                ida_hexrays.m_xor: lambda: left ^ right,
                ida_hexrays.m_and: lambda: left & right,
                ida_hexrays.m_or: lambda: left | right,
                ida_hexrays.m_mul: lambda: left * right,
                ida_hexrays.m_shl: lambda: left << right,
                ida_hexrays.m_shr: lambda: left >> right,
            }
            if opcode not in operations:
                raise RuntimeError("unsupported expression " + instruction.dstr())
            result = operations[opcode]()
        return result & ((1 << (8 * width)) - 1)

    def run(self):
        current = 0
        for _ in range(256):
            self.trace.append(current)
            block = self.mba.get_mblock(current)
            successor = None
            instruction = block.head
            while instruction is not None:
                opcode = instruction.opcode
                if opcode == ida_hexrays.m_nop:
                    pass
                elif opcode == ida_hexrays.m_goto:
                    successor = int(instruction.l.b)
                elif opcode == ida_hexrays.m_jtbl:
                    selector = self.value(instruction.l)
                    cases = instruction.r.c
                    successor = None
                    default = None
                    for index, target in enumerate(cases.targets):
                        values = list(cases.values[index])
                        if not values:
                            default = int(target)
                        if selector in values:
                            successor = int(target)
                    if successor is None:
                        successor = default
                    if successor is None:
                        raise RuntimeError("switch has no matching/default edge")
                elif opcode in (ida_hexrays.m_jz, ida_hexrays.m_jnz,
                                ida_hexrays.m_ja, ida_hexrays.m_jb,
                                ida_hexrays.m_jae, ida_hexrays.m_jbe,
                                ida_hexrays.m_jl, ida_hexrays.m_jge):
                    left, right = self.value(instruction.l), self.value(instruction.r)
                    bits = 8 * instruction.l.size
                    sign = 1 << (bits - 1)
                    signed_left = left - (1 << bits) if left & sign else left
                    signed_right = right - (1 << bits) if right & sign else right
                    predicates = {
                        ida_hexrays.m_jz: left == right, ida_hexrays.m_jnz: left != right,
                        ida_hexrays.m_ja: left > right, ida_hexrays.m_jb: left < right,
                        ida_hexrays.m_jae: left >= right, ida_hexrays.m_jbe: left <= right,
                        ida_hexrays.m_jl: signed_left < signed_right,
                        ida_hexrays.m_jge: signed_left >= signed_right,
                    }
                    successor = int(instruction.d.b) if predicates[opcode] else current + 1
                elif opcode == ida_hexrays.m_stx:
                    self.store(self.memory, self.value(instruction.d),
                               instruction.l.size, self.value(instruction.l))
                else:
                    storage, location = self.location(instruction.d)
                    self.store(storage, location, instruction.d.size,
                               self.expression(instruction, instruction.d.size))
                instruction = instruction.next
            if not block.nsucc():
                return self.read(self.registers, self.rax, 8)
            if successor is None:
                if block.nsucc() != 1:
                    raise RuntimeError("ambiguous implicit edge")
                successor = block.succ(0)
            if successor not in [block.succ(index) for index in range(block.nsucc())]:
                raise RuntimeError("instruction edge missing from CFG")
            current = successor
        return None


def verify_semantics(mba, name):
    observations = []
    for argument, expected in SCENARIOS[name]:
        interpreter = FixtureInterpreter(mba, argument)
        observed = interpreter.run()
        if observed != expected:
            raise RuntimeError("%s(%d): microcode=%r native-reference=%r" %
                               (name, argument, observed, expected))
        counter = interpreter.read(interpreter.memory, address("rg_guard_hits"), 4)
        if name == "rg_global_effect" and counter != 8:
            raise RuntimeError("dispatcher counter=%d, expected 8" % counter)
        observations.append({"argument": argument, "result": observed,
                             "expected": expected, "global_counter": counter,
                             "block_trace": interpreter.trace})
    return observations


try:
    import ida_idaapi
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")
    function_ranges = {name: [(int(start), int(end))
                              for start, end in idautils.Chunks(address(name))]
                       for name in NAMES}
    if any(not ranges for ranges in function_ranges.values()):
        raise RuntimeError("fixture function has no native ranges")
    original_bytes = {name: snapshot_bytes(ranges)
                      for name, ranges in function_ranges.items()}
    records = []
    for name in NAMES:
        start = address(name)
        function = ida_funcs.get_func(start)
        if function is None or function.start_ea != start:
            raise RuntimeError("missing function " + name)
        offsets = address(name + "_offsets")
        sites = [start + ida_bytes.get_dword(offsets + index * 4) for index in range(11)]
        record = {"name": name, "start": start, "dispatcher_ea": sites[0],
                  "guard_ea": sites[1], "switch_ea": sites[2],
                  "case_eas": sites[3:], "microcode": []}
        native_heads = {int(ea) for first, last in function_ranges[name]
                        for ea in idautils.Heads(first, last)
                        if ida_bytes.is_code(ida_bytes.get_flags(ea))}
        reference_eas = set()
        for label, maturity in (("LOCOPT", ida_hexrays.MMAT_LOCOPT),
                                ("GLBOPT3", ida_hexrays.MMAT_GLBOPT3)):
            failure = ida_hexrays.hexrays_failure_t()
            mba = ida_hexrays.gen_microcode(
                ida_hexrays.mba_ranges_t(function), failure, None,
                ida_hexrays.DECOMP_NO_CACHE, maturity,
            )
            if mba is None:
                raise RuntimeError("%s %s: %s" % (name, label, failure.desc()))
            mba.verify(True)
            blocks = [block_record(mba.get_mblock(index)) for index in range(mba.qty)]
            if label == "LOCOPT":
                reference_eas = {instruction["real_ea"] for block in blocks
                                 for instruction in block["instruction_addresses"]
                                 if instruction["real_ea"] != ida_idaapi.BADADDR}
            mapped_addresses = verify_instruction_addresses(
                blocks, native_heads, reference_eas)
            switch_count = sum(instruction["opcode"] == ida_hexrays.m_jtbl
                               for block in blocks for instruction in block["instructions"])
            record["microcode"].append({"maturity": label, "qty": mba.qty,
                                        "switch_count": switch_count, "blocks": blocks,
                                        "fictional_address_mappings": mapped_addresses})
            if label == "GLBOPT3":
                record["native_reference_checks"] = verify_semantics(mba, name)
            emit("%s %s blocks=%d switches=%d" % (name, label, mba.qty, switch_count))
        cfunc = ida_hexrays.decompile(start)
        if cfunc is None:
            raise RuntimeError("decompile failed " + name)
        record["pseudocode"] = "\n".join(ida_lines.tag_remove(line.line)
                                             for line in cfunc.get_pseudocode())
        records.append(record)
    # Compare every original function range only after all eleven functions
    # have been transformed and decompiled, catching cross-function changes.
    for record in records:
        name = record["name"]
        after_bytes = snapshot_bytes(function_ranges[name])
        if after_bytes != original_bytes[name]:
            raise RuntimeError("native IDB bytes changed in " + name)
        record["native_byte_integrity"] = {
            "before": original_bytes[name], "after": after_bytes, "unchanged": True,
        }
    destination = Path(os.environ["IDAUSR"]).parent / "recurrent_guard.json"
    destination.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    finish(0, "PASS output=%s" % destination)
except BaseException as error:
    finish(9, "exception: %r" % error)
