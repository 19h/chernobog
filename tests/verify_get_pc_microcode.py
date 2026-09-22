"""Execute the admitted get-PC fixture IR under a bounded flat-memory model.

This interpreter is independent of the production classifier and generator.
It compares architectural registers, represented status flags, SP and every
byte in its stack window both at the first continuation and at function exit.
Unsupported IR is an error, never a successful comparison or counterexample.
"""

import argparse
import json
from pathlib import Path


class UnsupportedIR(RuntimeError):
    pass


class EffectMismatch(RuntimeError):
    pass


def mask(size):
    if size not in (1, 2, 4, 8):
        raise UnsupportedIR("unsupported scalar width")
    return (1 << (8 * size)) - 1


class Machine:
    def __init__(self, record, seed):
        self.word = 4 if record["name"].startswith("gp32_") else 8
        self.seed = seed
        self.regs = {}
        self.initial_sp = self.sp = 0x100000 + seed * 0x100
        self.caller = 0x0F00DEAD
        self.memory = {self.sp + i: ((i + 71) * 37 + seed) & 255 for i in range(-64, 64)}
        self.store(self.sp, self.word, self.caller)
        self.code, self.blocks, self.addresses, self.architecture = [], {}, {}, {}
        for block in record["blocks"]:
            if block["instructions"]:
                self.blocks[block["index"]] = len(self.code)
            for insn in block["instructions"]:
                self.addresses.setdefault(insn["ea"], len(self.code))
                self.code.append(insn)
                for op in (insn["left"], insn["right"], insn["destination"]):
                    if "register" not in op:
                        continue
                    name = op["text"].split(".")[0]
                    if name in ("rax", "eax", "r11", "cf", "of", "zf", "pf", "sf"):
                        normalized = "ax" if name in ("rax", "eax") else name
                        prior = self.architecture.get(normalized)
                        if prior is None or prior[1] < op["size"]:
                            self.architecture[normalized] = (op["register"], op["size"])
        self.root = record.get("entry_ea") or next(
            x["ea"] for x in record["native"] if x["text"].startswith("call")
        )
        self.continuation = self.root + (8 if record["name"] == "gp_adjust" else 5)
        for name, bit in (("cf", 0), ("pf", 1), ("zf", 3), ("sf", 4), ("of", 5)):
            if name in self.architecture:
                number, _ = self.architecture[name]
                self.regs[number] = (seed >> bit) & 1
        self.pc = self.addresses[self.root]

    def reg(self, number, size):
        return sum(
            self.regs.get(number + i, ((number + i) * 29 + self.seed * 11) & 255) << (8 * i)
            for i in range(size)
        )

    def load(self, address, size):
        if any(address + i not in self.memory for i in range(size)):
            raise UnsupportedIR("read outside bounded stack")
        return sum(self.memory[address + i] << (8 * i) for i in range(size))

    def store(self, address, size, value):
        if any(address + i not in self.memory for i in range(size)):
            raise UnsupportedIR("write outside bounded stack")
        for i in range(size):
            self.memory[address + i] = (value >> (8 * i)) & 255

    def read(self, op):
        if "value" in op:
            return op["value"] & mask(op["size"])
        if "register" in op:
            if op["text"].split(".")[0] in ("rsp", "esp"):
                return self.sp & mask(op["size"])
            return self.reg(op["register"], op["size"])
        raise UnsupportedIR("unsupported value operand: " + op["text"])

    def write(self, op, value):
        if "register" not in op:
            raise UnsupportedIR("unsupported destination: " + op["text"])
        value &= mask(op["size"])
        if op["text"].split(".")[0] in ("rsp", "esp"):
            self.sp = value
        for i in range(op["size"]):
            self.regs[op["register"] + i] = (value >> (8 * i)) & 255

    def snapshot(self):
        return {
            "sp": self.sp,
            "memory": dict(self.memory),
            "registers": {name: self.reg(*where) for name, where in self.architecture.items()},
        }

    def jump(self, op):
        if "block" in op:
            if op["block"] not in self.blocks:
                raise UnsupportedIR("branch to empty block")
            self.pc = self.blocks[op["block"]]
        elif "address" in op and op["address"] in self.addresses:
            self.pc = self.addresses[op["address"]]
        else:
            raise UnsupportedIR("branch outside admitted function")

    def run(self):
        boundary = None
        for _ in range(128):
            if self.pc >= len(self.code):
                raise UnsupportedIR("instruction stream exhausted")
            insn = self.code[self.pc]
            if boundary is None and insn["ea"] == self.continuation:
                boundary = self.snapshot()
            self.pc += 1
            op = insn["text"].split()[0]
            left, right, dest = insn["left"], insn["right"], insn["destination"]
            if op == "nop":
                continue
            if op in ("mov", "xdu"):
                self.write(dest, self.read(left))
            elif op == "push":
                self.sp = (self.sp - left["size"]) & mask(self.word)
                self.store(self.sp, left["size"], self.read(left))
            elif op == "pop":
                value = self.load(self.sp, dest["size"])
                self.sp = (self.sp + dest["size"]) & mask(self.word)
                self.write(dest, value)
            elif op == "ldx":
                self.write(dest, self.load(self.read(right), dest["size"]))
            elif op == "stx":
                self.store(self.read(dest), left["size"], self.read(left))
            elif op == "goto":
                self.jump(left)
            elif op == "ijmp":
                target = self.read(dest)
                if target == self.caller:
                    if boundary is None:
                        raise UnsupportedIR("continuation was never executed")
                    return {"boundary": boundary, "exit": self.snapshot()}
                if target not in self.addresses:
                    raise UnsupportedIR(
                        "indirect transfer outside admitted function: target=%x SP=%x"
                        % (target, self.sp)
                    )
                self.pc = self.addresses[target]
            elif op in ("add", "cfadd", "ofadd", "setz", "setp", "sets"):
                a = self.read(left)
                b = self.read(right) if op in ("add", "cfadd", "ofadd", "setz") else 0
                word_mask = mask(left["size"])
                total = (a + b) & word_mask
                if op == "add":
                    value = total
                elif op == "cfadd":
                    value = int(a + b > word_mask)
                elif op == "ofadd":
                    value = int(bool((~(a ^ b) & (a ^ total)) & (1 << (8 * left["size"] - 1))))
                elif op == "setz":
                    value = int(a == b)
                elif op == "setp":
                    value = int((a & 255).bit_count() % 2 == 0)
                else:
                    value = a >> (8 * left["size"] - 1)
                self.write(dest, value)
            else:
                raise UnsupportedIR("unsupported operation: " + op)
        raise UnsupportedIR("execution budget exhausted")


def load(directory):
    path = Path(directory)
    report = json.loads((path / "run.json").read_text())
    assert report["runner_return_code"] == 0 and report["artifacts_unchanged"]
    assert not report["internal_error_found"]
    capture = json.loads((path / "get_pc_microcode.json").read_text())
    assert not capture["errors"]
    selected = {
        r["name"]: r
        for r in capture["records"]
        if r["name"]
        in (
            "gp_call",
            "gp_adjust",
            "gp_backward",
            "gp_nonzero",
            "gp32_call",
            "gp32_backward",
            "gp32_nonzero",
        )
    }
    assert selected
    return report, selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("standard")
    parser.add_argument("candidate", nargs="?")
    parser.add_argument("--expect-mismatch", action="store_true")
    parser.add_argument("--require-direct", action="store_true")
    parser.add_argument("--guards", action="store_true")
    args = parser.parse_args()
    baseline_report, baseline = load(args.standard)
    if args.guards:
        checked = 0
        for name, record in baseline.items():
            if record.get("callee_only"):
                sites = {i["ea"] for i in record["native"] if i["text"].startswith("retn")}
            else:
                assert record["context"].get("alternate_source") is not None
                sites = {record["context"]["return"]}
            assert sites, name + ": no guarded return"
            for site in sites:
                operations = [
                    i["text"].split()[0]
                    for b in record["blocks"]
                    for i in b["instructions"]
                    if i["ea"] == site
                ]
                assert "ijmp" in operations and "goto" not in operations, (
                    name + ": guarded return was resolved"
                )
                checked += 1
        print("PASS indirect_guard_sites=%d" % checked)
        return
    assert args.candidate, "candidate capture is required"
    actual_report, actual = load(args.candidate)
    for key in ("input_sha256", "ida_sha256"):
        assert baseline_report[key] == actual_report[key], "artifact mismatch: " + key
    assert baseline.keys() == actual.keys()
    comparisons, mismatches = 0, []
    for name in baseline:
        if args.require_direct:
            context = actual[name]["context"]
            assert context is not None
            transfers = [
                i
                for b in actual[name]["blocks"]
                for i in b["instructions"]
                if i["ea"] == context["return"] and i["text"].startswith("goto")
            ]
            assert len(transfers) == 1, name + ": exact return was not lowered"
            target = transfers[0]["left"]
            if "block" in target:
                target_ea = next(
                    b["start"] for b in actual[name]["blocks"] if b["index"] == target["block"]
                )
            else:
                target_ea = target.get("address")
            assert target_ea == context["continuation"], name + ": wrong direct target"
        for seed in range(64):
            expected = Machine(baseline[name], seed).run()
            result = Machine(actual[name], seed).run()
            word = 4 if name.startswith("gp32_") else 8
            initial_sp = 0x100000 + seed * 0x100
            boundary_delta = -word if name.endswith("nonzero") else 0
            assert (
                expected["boundary"]["sp"] == initial_sp + boundary_delta
            ), "reference boundary SP"
            assert expected["exit"]["sp"] == initial_sp + word, "reference exit SP"
            assert expected["exit"]["registers"]["ax"] == 7, "reference return value"
            root = baseline[name].get("entry_ea") or next(
                i["ea"] for i in baseline[name]["native"] if i["text"].startswith("call")
            )
            expected_pc = root + (8 if name == "gp_adjust" else 5)
            slot = sum(
                expected["boundary"]["memory"][initial_sp - word + i] << (8 * i)
                for i in range(word)
            )
            assert slot == expected_pc, "reference CALL-slot bytes"
            for phase in ("boundary", "exit"):
                comparisons += 1
                if expected[phase] != result[phase]:
                    mismatches.append((name, seed, phase))
    if args.expect_mismatch:
        assert mismatches, "legacy negative control did not falsify equivalence"
        print(
            "PASS expected_legacy_counterexamples=%d comparisons=%d"
            % (len(mismatches), comparisons)
        )
    else:
        if mismatches:
            raise EffectMismatch(str(mismatches[:4]))
        print(
            "PASS effect_comparisons=%d functions=%d seeds=64 boundaries=2"
            % (comparisons, len(baseline))
        )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        detail = str(error).replace(str(Path.cwd()), "<repo>").replace(str(Path.home()), "<home>")
        print("FAIL " + type(error).__name__ + ": " + detail)
        raise SystemExit(1)
