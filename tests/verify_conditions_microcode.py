"""Check generated condition IR against executed x86 fixture observations.

The interpreter admits MOV, zero extension, byte-addressed stores, the typed
read intrinsics and NOP. Unsupported microcode fails the audit. Initial states are at the SETcc
or CMOV boundary after the fixture's XOR; no production evaluator is imported.
"""

import argparse
import json
from pathlib import Path

CC = dict(
    zip(
        ("o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"),
        (0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0),
    )
)
NEGATIVE = {"vc_cm_segment", "vc_cm_address", "vc_unknown", "vc_depth", "vc_alternate"}
DECODE_ONLY = {"vc_cm_segment", "vc_cm_address"}
MEMORY = {
    "vc_cm_mem_true",
    "vc_cm_mem_false",
    "vc_cm_mem16_true",
    "vc_cm_mem16_false",
    "vc_cm_mem32_true",
    "vc_cm_mem32_false",
}
ORDER = {"vc_cm_order_true", "vc_cm_order_false"}
READS = MEMORY | ORDER
GPRS = (
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
)


def memory_width(name, word):
    assert name in READS
    return 2 if "mem16" in name else 4 if "mem32" in name or name in ORDER else word


def expected(row, word=8):
    name, destination, source = row["name"], row["destination"], row["source"]
    memory = row["memory_before"]
    suffix = name.removeprefix("vc_")
    if suffix in CC:
        return (destination & ~255) | CC[suffix], memory
    if suffix.startswith("cm_") and suffix[3:] in CC:
        return source if CC[suffix[3:]] else destination, memory
    value = name.endswith("_true")
    if name in ORDER:
        return (0x11223344 if value else destination & 0xFFFFFFFF), (
            memory & ~0xFFFFFFFF
        ) | 0x55667788
    if name in MEMORY:
        width = memory_width(name, word)
        mask = (1 << (8 * width)) - 1
        result = (destination & ~mask) | (memory & mask) if value else destination
        if width == 4:
            result &= mask
        return result, memory
    if suffix.startswith("ah_"):
        return (destination & ~0xFF00) | (int(value) << 8), memory
    if suffix.startswith("mem_"):
        return destination, (memory & ~255) | int(value)
    if suffix.startswith("cm16_"):
        return ((destination & ~0xFFFF) | (source & 0xFFFF)) if value else destination, memory
    if suffix.startswith("cm32_"):
        return (source if value else destination) & 0xFFFFFFFF, memory
    raise AssertionError("unexpected oracle case " + name)


class ReadFault(Exception):
    def __init__(self, address):
        self.address = address


def walk(instructions):
    for insn in instructions:
        yield insn
        for op in (insn["left"], insn["right"], insn["destination"]):
            if "instruction" in op:
                yield from walk([op["instruction"]])
            for arg in op.get("call", {}).get("arguments", []):
                if "instruction" in arg:
                    yield from walk([arg["instruction"]])


class Machine:
    def __init__(self, row, registers, opcodes, word=8):
        self.registers, self.opcodes = registers, opcodes
        self.word = word
        self.gprs = tuple(name for name in GPRS if name in registers)
        self.regs = {}
        self.reads = []
        self.pointer = 0x200000
        self.memory = {self.pointer + i: (i * 37 + row["seed"]) & 255 for i in range(-16, 24)}
        for i in range(8):
            self.memory[self.pointer + i] = (row["memory_before"] >> (8 * i)) & 255
        for i, name in enumerate(self.gprs):
            self.write(
                registers[name],
                word,
                (0x1728394050607080 * (i + 1) + row["seed"]) & ((1 << 64) - 1),
            )
        inputs = (
            {
                "rax": row["destination"],
                "rcx": 0,
                "rsi": row["source"],
                "rdi": row["destination"],
                "rdx": self.pointer,
            }
            if word == 8
            else {
                "rax": row["destination"],
                "rcx": self.pointer if "mem" in row["name"] or row["name"] in ORDER else 0,
                "rdx": row["source"],
            }
        )
        for name, value in inputs.items():
            self.write(registers[name], word, value)
        self.write(registers["ds"], 2, 0)
        for name, value in {"cf": 0, "zf": 1, "sf": 0, "of": 0, "pf": 1}.items():
            self.write(registers[name], 1, value)
        self.initial = dict(self.regs)
        self.initial_memory = dict(self.memory)

    def write(self, register, size, value):
        assert size in (1, 2, 4, 8), "unsupported register width"
        for i in range(size):
            self.regs[register + i] = (value >> (8 * i)) & 255

    def read(self, op):
        assert op["size"] in (1, 2, 4, 8), "unsupported operand width"
        if "value" in op:
            return op["value"] & ((1 << (8 * op["size"])) - 1)
        if "instruction" in op:
            assert op["instruction"]["opcode"] == self.opcodes["m_call"], "unsupported nested IR"
            return self.call(op["instruction"])
        assert "register" in op, "unsupported operand " + op["text"]
        return sum(self.regs[op["register"] + i] << (8 * i) for i in range(op["size"]))

    def call(self, insn):
        helper = insn["left"].get("helper")
        widths = {"__chernobog_read_u16": 2, "__chernobog_read_u32": 4, "__chernobog_read_u64": 8}
        assert helper in widths, "unmodeled helper"
        width = widths[helper]
        info = insn["destination"]["call"]
        assert len(info["arguments"]) == 1 and info["return_size"] == width
        assert not info["flags"] & 0x30, "read marked pure or without side effects"
        assert info["spoiled"] == "", "read intrinsic spoils architectural state"
        assert info["all_memory_visible"], "read dependencies missing"
        address = self.read(info["arguments"][0])
        self.reads.append((address, width))
        for i in range(width):
            if address + i not in self.memory:
                raise ReadFault(address + i)
        return sum(self.memory[address + i] << (8 * i) for i in range(width))

    def execute(self, instructions):
        assert instructions, "empty replacement"
        for insn in instructions:
            code, left, right, destination = (
                insn[key] for key in ("opcode", "left", "right", "destination")
            )
            if code == self.opcodes["m_nop"]:
                continue
            if code == self.opcodes["m_call"]:
                self.call(insn)
                continue
            if code in (self.opcodes["m_mov"], self.opcodes["m_xdu"]):
                assert "register" in destination, "non-register assignment"
                if code == self.opcodes["m_mov"]:
                    assert left["size"] == destination["size"]
                else:
                    assert left["size"] < destination["size"]
                self.write(destination["register"], destination["size"], self.read(left))
            elif code == self.opcodes["m_stx"]:
                assert self.read(right) == 0, "non-flat segment"
                address, value = self.read(destination), self.read(left)
                for i in range(left["size"]):
                    assert address + i in self.memory, "store outside admitted window"
                    self.memory[address + i] = (value >> (8 * i)) & 255
            else:
                raise AssertionError("unsupported IR " + insn["text"])

    def verify(self, row):
        result = self.read({"size": self.word, "register": self.registers["rax"]})
        assert result == row["result"], (row["name"], row["seed"], "RAX")
        memory = dict(self.initial_memory)
        for i in range(8):
            memory[self.pointer + i] = (row["memory_after"] >> (8 * i)) & 255
        assert self.memory == memory, (row["name"], row["seed"], "memory/guard bytes")
        for name in self.gprs[1:] + ("cf", "zf", "sf", "of", "pf", "ds"):
            width = self.word if name in self.gprs else 2 if name == "ds" else 1
            register = self.registers[name]
            assert all(
                self.regs[register + i] == self.initial[register + i] for i in range(width)
            ), name
        assert row["flags"] == 0x44, (row["name"], row["seed"], "native status flags")
        wanted_reads = (
            [(self.pointer, memory_width(row["name"], self.word))] if row["name"] in READS else []
        )
        assert self.reads == wanted_reads, "unconditional read count/width/address"


def verify(on, off, rows):
    assert not on["errors"] and not off["errors"]
    assert on["enabled"] and not off["enabled"]
    assert on["registers"] == off["registers"] and on["opcodes"] == off["opcodes"]
    word = on["word_bytes"]
    assert word in (4, 8) and word == off["word_bytes"]
    index = lambda report: {(r["name"], r["phase"]): r for r in report["records"]}
    enabled, disabled = index(on), index(off)
    assert len(enabled) == len(on["records"]) == len(disabled) == 58
    assert enabled.keys() == disabled.keys()
    accepted = {}
    for key, record in enabled.items():
        baseline = disabled[key]
        assert record["native"] == baseline["native"], "native byte mutation"
        assert not any(baseline["delta"].values()), "disabled filter consumed instruction"
        should_fold = record["name"] not in NEGATIVE and record["phase"] not in (
            "patched_unknown",
            "alternate_entry",
            "snippet",
        )
        counter = "codegen_cmov" if record["name"].startswith("vc_cm") else "codegen_setcc"
        assert record["delta"] == {
            k: int(
                should_fold
                and (k == counter or (k == "codegen_cmov_memory" and record["name"] in READS))
            )
            for k in baseline["delta"]
        }, key
        if should_fold:
            assert record["snippet"] != baseline["snippet"], "no IR substitution"
            if record["phase"] == "initial":
                accepted[record["name"]] = record
            else:
                assert (
                    record["snippet"] == enabled[record["name"], "initial"]["snippet"]
                ), "restored IR differs"
        else:
            assert record["blocks"] == baseline["blocks"], "rejected case changed IR"
    assert len(accepted) == 48
    native = {(r["name"], r["seed"]): r for r in rows}
    names = {name for name, phase in enabled if phase == "initial"} - DECODE_ONLY
    assert len(native) == len(rows) == 51 * 128
    assert native.keys() == {(name, seed) for name in names for seed in range(128)}
    comparisons = 0
    for name, record in accepted.items():
        for seed in range(128):
            row = native[name, seed]
            assert expected(row, word) == (row["result"], row["memory_after"]), (
                name,
                seed,
                "native oracle",
            )
            machine = Machine(row, on["registers"], on["opcodes"], word)
            machine.execute(record["snippet"])
            machine.verify(row)
            comparisons += 1
    # Falsification probes must fail independently of the production filter.
    import copy

    mutations = [("vc_ne", "constant"), ("vc_ah_true", "alias")]
    mutations.append(("vc_cm_mem_false", "missing_read"))
    mutations.extend(
        ("vc_cm_mem_false", effect)
        for effect in ("pure_read", "invisible_memory", "wrong_read_width")
    )
    if word == 8:
        mutations.append(("vc_cm32_false", "upper"))
    for name, mutation in mutations:
        snippet = copy.deepcopy(accepted[name]["snippet"])
        if mutation == "constant":
            snippet[0]["left"]["value"] ^= 1
        elif mutation == "upper":
            snippet = [i for i in snippet if i["opcode"] != on["opcodes"]["m_xdu"]]
        elif mutation == "missing_read":
            snippet = [
                i
                for i in snippet
                if not any(n["opcode"] == on["opcodes"]["m_call"] for n in walk([i]))
            ]
        elif mutation in ("pure_read", "invisible_memory", "wrong_read_width"):
            call = next(i for i in walk(snippet) if "helper" in i["left"])
            if mutation == "pure_read":
                call["destination"]["call"]["flags"] |= 0x20
            elif mutation == "invisible_memory":
                call["destination"]["call"]["all_memory_visible"] = False
            else:
                call["left"]["helper"] = "__chernobog_read_u16"
                call["destination"]["call"]["return_size"] = 2
        else:
            snippet[0]["destination"]["register"] = on["registers"]["rax"]
        caught = False
        try:
            machine = Machine(native[name, 1], on["registers"], on["opcodes"], word)
            machine.execute(snippet)
            machine.verify(native[name, 1])
        except AssertionError:
            caught = True
        assert caught, "audit failed to detect " + mutation
    return {
        "captures_per_mode": len(enabled),
        "accepted_functions": len(accepted),
        "native_records": len(rows),
        "effect_comparisons": comparisons,
        "mutation_controls": len(mutations),
        "word_bytes": word,
    }


def verify_optimized(report):
    assert not report["errors"] and report["enabled"]
    word, seen = report["word_bytes"], set()
    for record in report["records"]:
        if record["phase"] != "initial" or record["name"] not in READS:
            continue
        calls = [
            i
            for b in record["blocks"]
            for i in walk(b["instructions"])
            if i["left"].get("helper", "").startswith("__chernobog_read_")
        ]
        width = memory_width(record["name"], word)
        assert len(calls) == 1, "optimized read missing or duplicated"
        call = calls[0]
        assert call["left"]["helper"] == "__chernobog_read_u" + str(width * 8)
        assert call["destination"]["call"]["return_size"] == width
        assert not call["destination"]["call"]["flags"] & 0x30
        assert call["destination"]["call"]["spoiled"] == ""
        info = call["destination"]["call"]
        # Hex-Rays normalizes visibility to live regions. These fixtures use
        # argument pointers; GLBLOW retains the unknown global-memory read.
        assert info["all_memory_visible"] or "GLBLOW" in info["visible_memory"]
        assert record["ctree"] and record["ctree"].count(call["left"]["helper"] + "(") == 1
        if record["name"] in ORDER:
            events = []
            for block in record["blocks"]:
                for insn in walk(block["instructions"]):
                    if insn["opcode"] == report["opcodes"]["m_stx"]:
                        events.append(("store", insn["left"].get("value")))
                    elif insn["left"].get("helper", "").startswith("__chernobog_read_"):
                        events.append(("read", width))
            assert events == [("store", 0x11223344), ("read", 4), ("store", 0x55667788)], events
        seen.add(record["name"])
    assert seen == READS
    return {"maturity": report["maturity"], "preserved_reads": len(seen)}


def verify_faults(report, rows, _mutation_tests=True):
    assert not report["errors"] and report["enabled"]
    records = {r["name"]: r for r in report["records"] if r["phase"] == "initial"}
    assert len(rows) == 144
    keys = {(r["name"], r["seed"], r["available_bytes"]) for r in rows}
    word = report["word_bytes"]
    assert keys == {
        (name, seed, available)
        for name in MEMORY
        for seed in range(8)
        for available in (0, memory_width(name, word) - 1, memory_width(name, word))
    }
    faults = 0
    for row in rows:
        width = memory_width(row["name"], word)
        assert row["width_bytes"] == width and row["flags"] == 0x44
        record = records[row["name"]]
        modeled = {**row, "source": 0, "memory_before": 0xA7A7A7A7A7A7A7A7}
        machine = Machine(modeled, report["registers"], report["opcodes"], word)
        machine.memory = {machine.pointer + i: 0xA7 for i in range(row["available_bytes"])}
        memory_before = dict(machine.memory)
        fault = None
        try:
            machine.execute(record["snippet"])
        except ReadFault as error:
            fault = error.address
        assert machine.reads == [(machine.pointer, width)]
        assert machine.memory == memory_before
        result = machine.read({"size": word, "register": report["registers"]["rax"]})
        assert result == row["result"]
        if row["available_bytes"] < width:
            assert row["signal"] in (7, 10, 11)  # Linux/macOS SIGBUS or SIGSEGV.
            assert fault == machine.pointer + row["available_bytes"]
            assert row["fault_byte_offset"] == row["available_bytes"]
            assert row["fault_instruction_offset"] == record["sites"][0] - record["entry"]
            assert result == row["destination"], "destination modified before read fault"
            faults += 1
        else:
            assert row["signal"] == 0 and fault is None
            assert result == expected(modeled, word)[0]
        for name in machine.gprs[1:] + ("cf", "zf", "sf", "of", "pf"):
            size = word if name in machine.gprs else 1
            register = report["registers"][name]
            assert all(
                machine.regs[register + i] == machine.initial[register + i] for i in range(size)
            )
    assert faults == 96
    if _mutation_tests:
        import copy

        for mutation in ("missing_read", "early_destination_write"):
            altered = copy.deepcopy(report)
            record = next(
                r
                for r in altered["records"]
                if r["name"] == "vc_cm_mem_false" and r["phase"] == "initial"
            )
            if mutation == "missing_read":
                record["snippet"] = [
                    i
                    for i in record["snippet"]
                    if not any(n["opcode"] == report["opcodes"]["m_call"] for n in walk([i]))
                ]
            else:
                early = copy.deepcopy(record["snippet"][0])
                early["opcode"] = report["opcodes"]["m_mov"]
                early["left"] = {"size": word, "value": 0, "text": "mutation: zero"}
                early["destination"] = {
                    "size": word,
                    "register": report["registers"]["rax"],
                    "text": "mutation: architectural destination",
                }
                record["snippet"].insert(0, early)
            caught = False
            try:
                verify_faults(altered, rows, _mutation_tests=False)
            except AssertionError:
                caught = True
            assert caught, "fault audit failed to detect " + mutation
    return {
        "observations": len(rows),
        "faults": faults,
        "successful_boundary_reads": len(rows) - faults,
        "mutation_controls": 2 if _mutation_tests else 0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("enabled", type=Path)
    parser.add_argument("disabled", type=Path)
    parser.add_argument("native", type=Path)
    args = parser.parse_args()
    result = verify(
        json.loads(args.enabled.read_text()),
        json.loads(args.disabled.read_text()),
        [json.loads(line) for line in args.native.read_text().splitlines()],
    )
    print(json.dumps({"status": "pass", **result}, sort_keys=True))


if __name__ == "__main__":
    main()
