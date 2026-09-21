"""Independent scalar interpreter for the captured GLBOPT1 fixture microcode.

Only the explicitly handled straight-line IR is accepted. This finite oracle
checks result and the fixture's observable memory cell; it is not a general IR
interpreter or a proof of all ISA flags/exceptions.
"""
import json
import sys
from pathlib import Path


def mask(size):
    assert size in (1, 2, 4, 8), "unsupported scalar width"
    return (1 << (size * 8)) - 1


class Machine:
    def __init__(self):
        self.registers, self.memory = {}, {}

    @staticmethod
    def read(storage, address, size):
        return sum(storage[address + i] << (8 * i) for i in range(size))

    @staticmethod
    def write(storage, address, size, value):
        for i in range(size):
            storage[address + i] = (value >> (8 * i)) & 255

    def operand(self, value):
        kind, size = value["kind_name"], value["bytes"]
        if kind == "mop_n":
            result = value["value"]
        elif kind == "mop_r":
            result = self.read(self.registers, value["register"], size)
        elif kind == "mop_S":
            result = self.read(self.memory, 0x30000 + value["offset"], size)
        elif kind == "mop_v":
            result = self.read(self.memory, value["address"], size)
        elif kind == "mop_d":
            assert size == value["instruction"]["destination"]["bytes"], "nested size mismatch"
            result = self.expression(value["instruction"])
        else:
            raise AssertionError("unsupported operand: " + kind)
        return result & mask(size)

    def expression(self, insn):
        op, size = insn["opcode"], insn["destination"]["bytes"]
        left = self.operand(insn["left"])
        if op in ("m_mov", "m_xdu", "m_low"):
            result = left
        elif op == "m_xds":
            bits = insn["left"]["bytes"] * 8
            result = left - (1 << bits) if left & (1 << (bits - 1)) else left
        elif op == "m_high":
            result = left >> (8 * (insn["left"]["bytes"] - size))
        elif op == "m_bnot":
            result = ~left
        elif op == "m_neg":
            result = -left
        elif op == "m_ldx":
            assert left == 0, "fixture requires a flat segment"
            result = self.read(self.memory, self.operand(insn["right"]), size)
        else:
            right = self.operand(insn["right"])
            operations = {"m_add": lambda: left + right, "m_sub": lambda: left - right,
                          "m_mul": lambda: left * right, "m_and": lambda: left & right,
                          "m_or": lambda: left | right, "m_xor": lambda: left ^ right}
            assert op in operations, "unsupported opcode: " + op
            result = operations[op]()
        return result & mask(size)

    def execute(self, insn):
        if insn["opcode"] == "m_stx":
            assert self.operand(insn["right"]) == 0, "fixture requires a flat segment"
            self.write(self.memory, self.operand(insn["destination"]), insn["left"]["bytes"],
                       self.operand(insn["left"]))
            return
        value = self.expression(insn)
        dest = insn["destination"]
        if dest["kind_name"] == "mop_r":
            self.write(self.registers, dest["register"], dest["bytes"], value)
        elif dest["kind_name"] == "mop_S":
            self.write(self.memory, 0x30000 + dest["offset"], dest["bytes"], value)
        else:
            raise AssertionError("unsupported destination")


def inputs():
    for seed in (0x390FE14891, 0x9827136AB5):
        state = seed

        def next_value():
            nonlocal state
            state ^= (state << 13) & mask(8)
            state ^= state >> 7
            state ^= (state << 17) & mask(8)
            return state

        for trial in range(256):
            x = 0 if trial == 0 else mask(8) if trial == 1 else next_value()
            y = mask(8) if trial == 0 else 1 if trial == 1 else next_value()
            yield x, y, next_value()


def check_capture(report):
    comparisons = 0
    for record in report["records"]:
        name = record["name"]
        capture = next(c for c in record["captures"] if c["maturity"] == 5)
        cases = list(inputs())
        if name == "mba_truncate8":
            cases += [(x, y, 0) for x in range(256) for y in range(256)]
        for x, y, z in cases:
            machine = Machine()
            for register, value in {"rdi": 0x10000 if name.startswith("mba_alias_") else x,
                                    "rsi": y, "rdx": z, "rsp": 0x20000, "ds": 0}.items():
                machine.write(machine.registers, report["abi"][register], 2 if register == "ds" else 8, value)
            machine.write(machine.memory, 0x10000, 4, x)
            for block in capture["blocks"]:
                for insn in block["instructions"]:
                    machine.execute(insn)
            a, b = x & mask(4), y & mask(4)
            memory_expected = a
            if name == "mba_demorgan32": expected = a & b
            elif name == "mba_carry64": expected = (x + y) & mask(8)
            elif name in ("mba_carry32", "mba_stack32", "mba_order32"): expected = (a + b) & mask(4)
            elif name == "mba_truncate8": expected = (a + b) & 255
            elif name == "mba_extend_not": expected = (~a) & 255
            elif name == "mba_not_extend": expected = (~(a & 255)) & mask(4)
            elif name == "mba_alias_write":
                expected, memory_expected = a ^ b, b
            elif name == "mba_alias_partial":
                memory_expected = (a & 0xFFFF0000) | (b & 65535)
                expected = a ^ memory_expected
            else: raise AssertionError("unclassified fixture")
            actual = machine.read(machine.registers, report["abi"]["rax"], 8)
            assert actual == expected, (name, "result", x, y, actual, expected)
            assert machine.read(machine.memory, 0x10000, 4) == memory_expected, (name, "memory", x, y)
            comparisons += 1
    return comparisons


def main():
    assert len(sys.argv) == 3, "provide baseline and enabled artifact directories"
    reports = []
    runs = []
    for directory in sys.argv[1:]:
        root = Path(directory)
        run = json.loads((root / "run.json").read_text())
        report = json.loads((root / "mba_shapes.json").read_text())
        assert run["runner_return_code"] == 0 and run["artifacts_unchanged"]
        assert not report["errors"] and len(report["records"]) == 10
        assert all(c["passed"] for c in report["checks"])
        reports.append(report)
        runs.append(run)
    for field in ("input_sha256", "plugin_sha256", "script_sha256", "ida_sha256"):
        assert runs[0][field] == runs[1][field], "paired artifact mismatch: " + field
    counts = [check_capture(report) for report in reports]
    for record in reports[0]["records"]:
        assert record["statistics"]["instance_verified"] == 0, "baseline used plugin proofs"
    for record in reports[1]["records"]:
        if record["name"] in ("mba_demorgan32", "mba_carry32", "mba_carry64", "mba_stack32", "mba_order32"):
            assert record["statistics"]["instance_verified"] > 0, "missing production proof"
    print(json.dumps({"status": "PASS", "comparisons_per_run": counts,
                      "compared_result_bits": 64, "observable_memory_cell_bytes": 4,
                      "seeds": ["0x390fe14891", "0x9827136ab5"]}))


if __name__ == "__main__":
    main()
