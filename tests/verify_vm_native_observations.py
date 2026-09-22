"""Independent concrete scalar replay of corroborated native VM observations.

Capstone supplies instruction decoding; Python integers supply effects. This
oracle does not import Chernobog recognition, semantics, or transition checking.
Unsupported instructions fail the verification instead of counting as coverage.
"""

import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_OP_REG, CS_OP_IMM, CS_OP_MEM

ARITH = 0x8D5


def state_registers(state, mode):
    result = {}
    for item in state["registers"].split(";"):
        reg, width, value = item.split(":")
        reg, width, value = int(reg), int(width), int(value, 0)
        assert width == mode // 8 and reg not in result
        result[reg] = value
    base = 0x100 if mode == 64 else 0x200
    return [result[base + i] for i in range(16 if mode == 64 else 8)], result[
        0x12 if mode == 64 else 0x13
    ]


def alias(name):
    families = [
        ("rax", "eax", "ax", "al", "ah"),
        ("rcx", "ecx", "cx", "cl", "ch"),
        ("rdx", "edx", "dx", "dl", "dh"),
        ("rbx", "ebx", "bx", "bl", "bh"),
        ("rsp", "esp", "sp", "spl"),
        ("rbp", "ebp", "bp", "bpl"),
        ("rsi", "esi", "si", "sil"),
        ("rdi", "edi", "di", "dil"),
    ]
    families += [(f"r{i}", f"r{i}d", f"r{i}w", f"r{i}b") for i in range(8, 16)]
    for index, family in enumerate(families):
        if name in family:
            part = family.index(name)
            return index, (64, 32, 16, 8, 8)[part], 8 if part == 4 else 0
    raise AssertionError("unsupported register alias")


def replay_step(insn, entry, output, accesses, mode, memory):
    regs, flags = state_registers(entry, mode)
    expected_regs, expected_flags = state_registers(output, mode)
    mask = (1 << mode) - 1
    checked_flags = ARITH
    cursor = 0

    def get_reg(reg):
        name = insn.reg_name(reg)
        if name in ("riz", "eiz"):
            return 0
        if name in ("rip", "eip"):
            return insn.address + insn.size
        index, bits, shift = alias(name)
        return (regs[index] >> shift) & ((1 << bits) - 1)

    def set_reg(reg, value):
        index, bits, shift = alias(insn.reg_name(reg))
        value &= (1 << bits) - 1
        if bits == 32 or bits == mode:
            regs[index] = value
        else:
            field = ((1 << bits) - 1) << shift
            regs[index] = (regs[index] & ~field) | (value << shift)

    def address(op):
        assert not op.mem.segment
        return (
            (get_reg(op.mem.base) if op.mem.base else 0)
            + (get_reg(op.mem.index) * op.mem.scale if op.mem.index else 0)
            + op.mem.disp
        ) & mask

    def access(kind, addr, size, value=None):
        nonlocal cursor
        assert cursor < len(accesses)
        row = accesses[cursor]
        cursor += 1
        assert row["kind"] == kind and int(row["address"], 0) == addr and int(row["size"]) == size
        actual = int(row["value"], 0)
        assert 0 <= actual < 1 << (size * 8)
        if value is not None:
            assert actual == value & ((1 << (size * 8)) - 1)
        for offset in range(size):
            loc, byte = (addr + offset) & mask, (actual >> (8 * offset)) & 255
            if kind == "read" and loc in memory:
                assert memory[loc] == byte
            memory[loc] = byte
        return actual

    def read(op):
        if op.type == CS_OP_REG:
            return get_reg(op.reg)
        if op.type == CS_OP_IMM:
            return op.imm
        assert op.type == CS_OP_MEM
        return access("read", address(op), op.size)

    def write(op, value):
        if op.type == CS_OP_REG:
            set_reg(op.reg, value)
        else:
            assert op.type == CS_OP_MEM
            access("write", address(op), op.size, value)

    def flag(bit, value):
        nonlocal flags
        flags = (flags | bit) if value else (flags & ~bit)

    def arithmetic(a, b, bits, subtract=False, logical=False):
        nonlocal checked_flags
        m = (1 << bits) - 1
        a, b = a & m, b & m
        result = ((a - b) if subtract else (a + b)) & m
        if logical:
            result = a
            flag(1, False)
            flag(0x800, False)
            checked_flags &= ~0x10
        else:
            flag(1, a < b if subtract else a + b > m)
            flag(0x10, (a ^ b ^ result) & 0x10)
            flag(0x800, ((a ^ b) if subtract else ~(a ^ b)) & (a ^ result) & (1 << (bits - 1)))
        flag(4, (result & 255).bit_count() % 2 == 0)
        flag(0x40, result == 0)
        flag(0x80, result & (1 << (bits - 1)))
        return result

    ops, mnemonic = insn.operands, insn.mnemonic
    target = insn.address + insn.size
    if mnemonic in ("mov", "movzx", "movsxd", "movsx"):
        value = read(ops[1])
        if mnemonic in ("movsxd", "movsx"):
            bits = ops[1].size * 8
            value = (value ^ (1 << (bits - 1))) - (1 << (bits - 1))
        write(ops[0], value)
    elif mnemonic in ("add", "sub", "cmp", "xor", "test", "and", "or"):
        a, b, bits = read(ops[0]), read(ops[1]), ops[0].size * 8
        if mnemonic in ("xor", "test", "and", "or"):
            value = a ^ b if mnemonic == "xor" else a | b if mnemonic == "or" else a & b
            value = arithmetic(value, 0, bits, logical=True)
        else:
            value = arithmetic(a, b, bits, subtract=mnemonic in ("sub", "cmp"))
        if mnemonic not in ("cmp", "test"):
            write(ops[0], value)
    elif mnemonic in ("inc", "dec", "neg", "not", "bswap"):
        a, bits = read(ops[0]), ops[0].size * 8
        if mnemonic in ("inc", "dec"):
            carry = flags & 1
            value = arithmetic(a, 1, bits, subtract=mnemonic == "dec")
            flag(1, carry)
        elif mnemonic == "neg":
            value = arithmetic(0, a, bits, subtract=True)
        elif mnemonic == "not":
            value = ~a
        else:
            assert bits in (32, 64)
            value = int.from_bytes(a.to_bytes(bits // 8, "little"), "big")
        write(ops[0], value)
    elif mnemonic in ("rol", "ror"):
        a, count, bits = read(ops[0]), read(ops[1]), ops[0].size * 8
        count &= 63 if bits == 64 else 31
        value, reduced, m = a, count % bits, (1 << bits) - 1
        if count:
            if reduced:
                value = (
                    ((a << reduced) | (a >> (bits - reduced))) & m
                    if mnemonic == "rol"
                    else ((a >> reduced) | (a << (bits - reduced))) & m
                )
            flag(1, value & 1 if mnemonic == "rol" else value >> (bits - 1))
            if count == 1:
                flag(
                    0x800,
                    (
                        ((value >> (bits - 1)) ^ (flags & 1))
                        if mnemonic == "rol"
                        else ((value >> (bits - 1)) ^ (value >> (bits - 2))) & 1
                    ),
                )
            else:
                checked_flags &= ~0x800
        write(ops[0], value)
    elif mnemonic in ("stc", "clc", "cmc"):
        flag(1, True if mnemonic == "stc" else False if mnemonic == "clc" else not flags & 1)
    elif mnemonic == "push":
        value = read(ops[0])
        size = 2 if ops[0].size == 2 else mode // 8
        regs[4] = (regs[4] - size) & mask
        access("write", regs[4], size, value)
    elif mnemonic == "pop":
        size = ops[0].size
        value = access("read", regs[4], size)
        regs[4] = (regs[4] + size) & mask
        write(ops[0], value)
    elif mnemonic == "ret":
        assert not ops
        target = access("read", regs[4], mode // 8)
        regs[4] = (regs[4] + mode // 8) & mask
    elif mnemonic == "jmp":
        target = read(ops[0]) & mask
    elif mnemonic != "nop":
        raise AssertionError("unsupported concrete instruction: " + mnemonic)
    assert cursor == len(accesses), "unmodeled access"
    assert regs == expected_regs, "GPR mismatch"
    assert (flags ^ expected_flags) & checked_flags == 0, (
        f"defined flag mismatch at {insn.address:#x} {insn.mnemonic} {insn.op_str}: "
        f"expected={flags:#x} captured={expected_flags:#x} mask={checked_flags:#x}"
    )
    assert target == int(output["site"], 0), "successor mismatch"


def verify_row(trace, row):
    mode = trace["address_bits"]
    begin, end = int(row["sequence"], 0), int(row["output_sequence"], 0)
    path = [p for p in trace["execution"] if begin <= int(p["sequence"]) < end]
    entries = {
        int(s["sequence"]): s for s in trace["states"] if s["kind"] == "native instruction entry"
    }
    exits = [
        s for s in trace["states"] if s["kind"] == "transfer target" and int(s["sequence"]) == end
    ]
    assert len(exits) == 1 and int(exits[0]["site"], 0) == int(row["target"], 0)
    assert [(int(p["site"], 0), int(p["size"])) for p in path] == [
        (int(item.split(":")[0], 0), int(item.split(":")[1]))
        for item in row["instruction_spans"].split(";")
        if item
    ]
    heads = {int(h["site"], 0): h for h in trace["heads"]}
    decoder = Cs(CS_ARCH_X86, CS_MODE_64 if mode == 64 else CS_MODE_32)
    decoder.detail = True
    memory, counts = {}, Counter()
    for index, point in enumerate(path):
        sequence, ea = int(point["sequence"]), int(point["site"], 0)
        output = entries[int(path[index + 1]["sequence"])] if index + 1 < len(path) else exits[0]
        until = int(output["sequence"])
        accesses = [d for d in trace["data"] if sequence < int(d["sequence"]) < until]
        assert all(int(d["site"], 0) == ea for d in accesses)
        encoded = bytes.fromhex(heads[ea]["bytes"])
        instructions = list(decoder.disasm(encoded, ea))
        assert len(instructions) == 1 and instructions[0].size == len(encoded) == int(point["size"])
        replay_step(instructions[0], entries[sequence], output, accesses, mode, memory)
        counts[instructions[0].mnemonic] += 1
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    digest = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
    report = json.loads(args.report.read_text())
    assert report["passed"] and report["native_check"]
    result = {
        "schema": 1,
        "passed": False,
        "source_sha256": digest(__file__),
        "report_sha256": digest(args.report),
        "capstone_version": capstone.__version__,
        "capture_sha256": {},
        "transitions": 0,
        "instructions": {},
        "negative_controls": 0,
    }
    counts, examples = Counter(), {}
    for run in report["runs"]:
        path = args.report.parent / run["label"] / "vm_native_inputs.json"
        assert digest(path) == run["artifact_sha256"][path.name]
        result["capture_sha256"][run["label"]] = digest(path)
        capture = json.loads(path.read_text())
        assert capture["passed"]
        for cap in capture["captures"]:
            trace = cap["trace"]
            for row in trace["native_observations"]["records"]:
                assert row["semantic_validation"] == "corroborated for captured transition"
                counts.update(verify_row(trace, row))
                result["transitions"] += 1
                examples.setdefault(trace["address_bits"], (trace, row))
    for trace, row in examples.values():
        for mutation in ("gpr", "flags", "target", "read"):
            changed = copy.deepcopy(trace)
            begin, end = int(row["sequence"], 0), int(row["output_sequence"], 0)
            output = next(
                s
                for s in changed["states"]
                if s["kind"] == "transfer target" and int(s["sequence"]) == end
            )
            if mutation in ("gpr", "flags"):
                reg = (
                    (0x100 if trace["address_bits"] == 64 else 0x200)
                    if mutation == "gpr"
                    else (0x12 if trace["address_bits"] == 64 else 0x13)
                )
                values = [item.split(":") for item in output["registers"].split(";")]
                for item in values:
                    if int(item[0]) == reg:
                        item[2] = hex(int(item[2], 0) ^ 1)
                output["registers"] = ";".join(":".join(item) for item in values)
            elif mutation == "target":
                output["site"] = hex(int(output["site"], 0) ^ 1)
            else:
                access = next(
                    d
                    for d in changed["data"]
                    if begin < int(d["sequence"]) < end and d["kind"] == "read"
                )
                access["value"] = hex(int(access["value"], 0) ^ 1)
            try:
                verify_row(changed, row)
            except AssertionError:
                result["negative_controls"] += 1
            else:
                raise AssertionError("corrupted transition accepted")
    assert result["transitions"] and result["negative_controls"] == 4 * len(examples)
    result["instructions"], result["passed"] = dict(counts), True
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "capture_sha256"}))


if __name__ == "__main__":
    main()
