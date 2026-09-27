"""Integer result/memory oracle for actual predicate SDK captures."""

import argparse
import copy
import hashlib
import json
from pathlib import Path

from mba_matching_diagnostics import require
from verify_mba_shapes import Machine

NAMES = (
    "predicate_or_odd32",
    "predicate_and_zero32",
    "predicate_unsigned_bound32",
    "predicate_signed_negative8",
    "predicate_zext_not8",
    "predicate_alias_write32",
)


class PredicateMachine(Machine):
    def expression(self, insn):
        op = insn["opcode"]
        if op not in (
            "m_lnot",
            "m_sets",
            "m_setz",
            "m_setnz",
            "m_setb",
            "m_setae",
            "m_seta",
            "m_setbe",
            "m_setl",
            "m_setge",
            "m_setg",
            "m_setle",
        ):
            return super().expression(insn)
        require(insn["properties"] == 0, "predicate effects outside integer oracle")
        left = self.operand(insn["left"])
        width = insn["left"]["bytes"]
        bits = 8 * width
        if op == "m_lnot":
            return int(left == 0)
        require(insn["destination"]["bytes"] == 1, "set result width")
        if op == "m_sets":
            return (left >> (bits - 1)) & 1
        require(width == insn["right"]["bytes"], "comparison width mismatch")
        right = self.operand(insn["right"])
        signed_left = left - (1 << bits) if left & (1 << (bits - 1)) else left
        signed_right = right - (1 << bits) if right & (1 << (bits - 1)) else right
        return int(
            {
                "m_setz": lambda: left == right,
                "m_setnz": lambda: left != right,
                "m_setb": lambda: left < right,
                "m_setae": lambda: left >= right,
                "m_seta": lambda: left > right,
                "m_setbe": lambda: left <= right,
                "m_setl": lambda: signed_left < signed_right,
                "m_setge": lambda: signed_left >= signed_right,
                "m_setg": lambda: signed_left > signed_right,
                "m_setle": lambda: signed_left <= signed_right,
            }[op]()
        )


def check(record, abi):
    name = record["name"]
    capture = next(c for c in record["captures"] if c["maturity"] == 5)
    require(record["native_bytes_unchanged"], "native mutation")
    cases = (
        ((x, y) for x in range(256) for y in range(256))
        if name == "predicate_alias_write32"
        else ((x, 0) for x in (*range(256), 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF))
    )
    checks = 0
    for x, y in cases:
        machine = PredicateMachine()
        for register, value in {
            "rdi": 0x10000 if name == "predicate_alias_write32" else x,
            "rsi": y,
            "rdx": 0,
            "rsp": 0x20000,
            "ds": 0,
        }.items():
            machine.write(machine.registers, abi[register], 2 if register == "ds" else 8, value)
        machine.write(machine.memory, 0x10000, 4, x)
        for block in capture["blocks"]:
            for insn in block["instructions"]:
                machine.execute(insn)
        expected = (
            int(x == y)
            if name == "predicate_alias_write32"
            else (
                int((x & 255) >= 128)
                if name == "predicate_signed_negative8"
                else int(name in ("predicate_or_odd32", "predicate_and_zero32"))
            )
        )
        actual = machine.read(machine.registers, abi["rax"], 8)
        require(actual == expected, f"predicate result: {name} x={x} y={y}")
        expected_memory = y if name == "predicate_alias_write32" else x
        require(
            machine.read(machine.memory, 0x10000, 4) == expected_memory,
            "predicate observable memory",
        )
        checks += 1
    return checks


def audit(before_dir, after_dir):
    reports, runs = [], []
    for directory in (before_dir, after_dir):
        run = json.loads((directory / "run.json").read_text())
        report = json.loads((directory / "predicate_shapes.json").read_text())
        require(run["runner_return_code"] == 0 and run["artifacts_unchanged"], "actual SDK process")
        require(not report["errors"], "SDK capture failure")
        require(tuple(r["name"] for r in report["records"]) == NAMES, "predicate population")
        require(all(len(r["captures"]) == 4 for r in report["records"]), "SDK stage population")
        reports.append(report)
        runs.append(run)
    for field in ("input_sha256", "script_sha256", "ida_sha256"):
        require(runs[0][field] == runs[1][field], "paired artifact differs: " + field)
    require(reports[0]["abi"] == reports[1]["abi"], "ABI changed")
    comparisons = [sum(check(r, report["abi"]) for r in report["records"]) for report in reports]
    before, after = [r["records"][4] for r in reports]
    require(before["statistics"]["instance_verified"] == 0, "prior predicate proof")
    require(after["statistics"]["instance_verified"] > 0, "new typed predicate proof absent")
    old, new = [r["captures"][-1]["blocks"] for r in (before, after)]
    require(old != new, "width comparison not changed")
    instructions = [i for block in new for i in block["instructions"]]
    require(
        len(instructions) == 1
        and instructions[0]["opcode"] == "m_mov"
        and instructions[0]["left"]["value"] == 0,
        "width comparison not reduced to zero",
    )
    for index in (0, 1, 2, 3, 5):
        require(
            reports[0]["records"][index]["captures"][-1]["blocks"]
            == reports[1]["records"][index]["captures"][-1]["blocks"],
            "unrelated predicate result or alias capture changed",
        )
    wrong = copy.deepcopy(after)
    next(i for block in wrong["captures"][-1]["blocks"] for i in block["instructions"])["left"][
        "value"
    ] = 1
    try:
        check(wrong, reports[1]["abi"])
    except ValueError:
        corruption_rejected = True
    else:
        raise ValueError("false folded predicate accepted")
    pins = {
        str(directory / name): hashlib.sha256((directory / name).read_bytes()).hexdigest()
        for directory in (before_dir, after_dir)
        for name in ("run.json", "predicate_shapes.json", "ida.log")
    }
    return {
        "passed": True,
        "comparisons_per_profile": comparisons,
        "native_functions_per_profile": 6,
        "sdk_captures_per_profile": 24,
        "changed_glbopt1_functions": ["predicate_zext_not8"],
        "typed_proofs": after["statistics"]["instance_verified"],
        "false_constant_rejected": corruption_rejected,
        "artifact_sha256": pins,
        "scope": "straight-line scalar result and one memory cell on normal completion; no fault, concurrent-memory, all-ISA flag or protected recovery claim",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path)
    parser.add_argument("--after", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.archive is not None:
        require(args.before is None and args.after is None, "choose archive or raw captures")
        evidence = json.loads(args.archive.read_text())
        snapshots = evidence["captured_glbopt1"]
        canonical = json.dumps(snapshots, sort_keys=True, separators=(",", ":")).encode()
        require(
            hashlib.sha256(canonical).hexdigest() == evidence["captured_glbopt1_sha256"],
            "archive snapshot digest",
        )
        comparisons = []
        for profile in ("prior", "candidate"):
            report = snapshots[profile]
            require(tuple(r["name"] for r in report["records"]) == NAMES, "archive population")
            comparisons.append(sum(check(r, report["abi"]) for r in report["records"]))
        result = {
            "passed": True,
            "comparisons_per_profile": comparisons,
            "archive_sha256": hashlib.sha256(args.archive.read_bytes()).hexdigest(),
            "scope": "integer replay of archived GLBOPT1 result and memory snapshots; no current SDK applicability claim",
        }
    else:
        require(args.before is not None and args.after is not None, "provide paired captures")
        result = audit(args.before, args.after)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
