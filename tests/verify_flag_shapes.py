"""Replay actual flag SDK trees against the retained native result bytes."""

import argparse
import copy
import hashlib
import json
from pathlib import Path

from mba_matching_diagnostics import require
from verify_flag_values import cases
from verify_mba_shapes import Machine, mask

NAMES = (
    "flags8",
    "flags16",
    "flags32",
    "flags64",
    "flag_parity_zero32",
    "flag_parity_one32",
    "flag_parity_compare32",
    "flag_overflow_zero8",
    "flag_overflow_one8",
)
CONSTANTS = {
    "flag_parity_zero32": 1,
    "flag_parity_one32": 0,
    "flag_overflow_zero8": 0,
    "flag_overflow_one8": 1,
}


class FlagMachine(Machine):
    def expression(self, insn):
        op = insn["opcode"]
        if op not in ("m_cfadd", "m_ofadd", "m_seto", "m_setp"):
            return super().expression(insn)
        require(
            insn["properties"] == 0 and insn["destination"]["bytes"] == 1, "integer flag metadata"
        )
        width = insn["left"]["bytes"]
        require(width == insn["right"]["bytes"], "flag input width")
        x, y = self.operand(insn["left"]), self.operand(insn["right"])
        sign = 1 << (width * 8 - 1)
        signed = lambda v: v - 2 * sign if v & sign else v
        return int(
            {
                "m_cfadd": lambda: x + y > mask(width),
                "m_ofadd": lambda: not -sign <= signed(x) + signed(y) < sign,
                "m_seto": lambda: not -sign <= signed(x) - signed(y) < sign,
                "m_setp": lambda: ((x - y) & 255).bit_count() % 2 == 0,
            }[op]()
        )


def check(record, abi, native_cases):
    name = record["name"]
    require(record["native_bytes_unchanged"], "native bytes changed")
    stage = next(s for s in record["captures"] if s["maturity"] == 5)
    width = {"flags8": 1, "flags16": 2, "flags32": 4, "flags64": 8}.get(name)
    population = native_cases[width] if width else native_cases[1] + native_cases[4]
    if name in CONSTANTS:
        population = [(0, 0, None)]
    checks = 0
    for x, y, expected in population:
        machine = FlagMachine()
        for register, value in {
            "rdi": x,
            "rsi": y,
            "rdx": 0x10000,
            "rsp": 0x20000,
            "ds": 0,
        }.items():
            machine.write(machine.registers, abi[register], 2 if register == "ds" else 8, value)
        for block in stage["blocks"]:
            for instruction in block["instructions"]:
                machine.execute(instruction)
        if width:
            actual = bytes(machine.read(machine.memory, 0x10000 + i, 1) for i in range(4))
            require(actual == expected, "SDK flag memory result: " + name)
            checks += 4
        else:
            actual = machine.read(machine.registers, abi["rax"], 1)
            value = CONSTANTS[name] if expected is None else expected[3]
            require(actual == value, "SDK parity return: " + name)
            checks += 1
    return checks


def audit(before, after, native):
    reports, runs = [], []
    for directory in (before, after):
        run = json.loads((directory / "run.json").read_text())
        report = json.loads((directory / "flag_shapes.json").read_text())
        require(run["runner_return_code"] == 0 and run["artifacts_unchanged"], "SDK process")
        require(
            not report["errors"] and tuple(r["name"] for r in report["records"]) == NAMES,
            "SDK population",
        )
        require(all(len(r["captures"]) == 4 for r in report["records"]), "SDK maturity population")
        reports.append(report)
        runs.append(run)
    for field in ("input_sha256", "script_sha256", "ida_sha256", "chernobog_environment_sha256"):
        require(runs[0][field] == runs[1][field], "paired SDK input differs: " + field)
    require(reports[0]["abi"] == reports[1]["abi"], "paired ABI")
    require(len(native) == 262912, "native byte population")
    native_cases = {width: [] for width in (1, 2, 4, 8)}
    for index, (width, x, y) in enumerate(cases()):
        native_cases[width].append((x, y, native[4 * index : 4 * index + 4]))
    counts = [
        sum(check(record, report["abi"], native_cases) for record in report["records"])
        for report in reports
    ]
    changed = []
    for prior, current in zip(reports[0]["records"], reports[1]["records"]):
        old, new = prior["captures"][-1]["blocks"], current["captures"][-1]["blocks"]
        if prior["name"] in CONSTANTS and old != new:
            require(
                old != new
                and prior["statistics"]["instance_verified"] == 0
                and current["statistics"]["instance_verified"] > 0,
                "missing production flag admission",
            )
            intrinsic = "__SETP__" if "parity" in prior["name"] else "__OFADD__"
            require(
                intrinsic in prior["ctree"] and intrinsic not in current["ctree"],
                "flag ctree not simplified",
            )
            changed.append(prior["name"])
        else:
            require(old == new, "unrelated symbolic flag tree changed")
    require(set(changed) >= {"flag_parity_zero32", "flag_parity_one32"}, "parity gaps unchanged")
    wrong = copy.deepcopy(reports[1]["records"][4])
    instruction = next(i for b in wrong["captures"][-1]["blocks"] for i in b["instructions"])
    require(instruction["left"]["kind_name"] == "mop_n", "constant parity result absent")
    instruction["left"]["value"] ^= 1
    try:
        check(wrong, reports[1]["abi"], native_cases)
    except ValueError:
        rejected = True
    else:
        raise ValueError("wrong parity constant accepted")
    return {
        "passed": True,
        "checks_per_profile": counts,
        "functions_per_profile": len(NAMES),
        "captures_per_profile": 4 * len(NAMES),
        "changed_glbopt1_functions": changed,
        "wrong_constant_rejected": rejected,
        "native_sha256": hashlib.sha256(native).hexdigest(),
        "scope": "normal-completion scalar GLBOPT1 trees, four observed flag bytes and low-byte parity returns; no arbitrary CFG, fault or concurrent-memory claim",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("before", "after", "native", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.before, args.after, args.native.read_bytes())
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
