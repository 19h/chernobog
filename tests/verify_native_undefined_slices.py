"""Audit file-backed closed dependence slices with Capstone and symbolic functions.

This proves independence of defined observations under conservative instruction
dependencies. It does not select a hardware result for an undefined operand.
The concrete output oracle remains the paired corpus's unprotected main.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import capstone
from capstone import x86_const as x86
import z3

from verify_vm_native_region_decode import segments

CF, PF, AF, ZF, SF, OF = (1 << i for i in range(6))
ALL = 63
CONDITIONS = {
    "o": OF,
    "no": OF,
    "b": CF,
    "ae": CF,
    "e": ZF,
    "ne": ZF,
    "be": CF | ZF,
    "a": CF | ZF,
    "s": SF,
    "ns": SF,
    "p": PF,
    "np": PF,
    "l": SF | OF,
    "ge": SF | OF,
    "le": ZF | SF | OF,
    "g": ZF | SF | OF,
}
ALIASES = [
    ("al", "ax", "eax", "rax", "ah"),
    ("cl", "cx", "ecx", "rcx", "ch"),
    ("dl", "dx", "edx", "rdx", "dh"),
    ("bl", "bx", "ebx", "rbx", "bh"),
    ("spl", "sp", "esp", "rsp"),
    ("bpl", "bp", "ebp", "rbp"),
    ("sil", "si", "esi", "rsi"),
    ("dil", "di", "edi", "rdi"),
    *[(f"r{i}b", f"r{i}w", f"r{i}d", f"r{i}") for i in range(8, 16)],
]


def gpr(name):
    return next((1 << i for i, names in enumerate(ALIASES) if name in names), 0)


def dependencies(insn, row):
    """Independent operand inventory plus explicit implicit/conditional effects."""
    ops, name = insn.operands, insn.mnemonic
    assert name in {
        "bswap",
        "mov",
        "movabs",
        "movsx",
        "movsxd",
        "movzx",
        "lea",
        "not",
        "neg",
        "add",
        "sub",
        "adc",
        "sbb",
        "cmp",
        "and",
        "or",
        "xor",
        "test",
        "inc",
        "dec",
        "rol",
        "ror",
        "rcl",
        "rcr",
        "shl",
        "sal",
        "shr",
        "sar",
        "bt",
        "bts",
        "btr",
        "btc",
        "clc",
        "stc",
        "cmc",
        "push",
        "pop",
        "cdq",
        "cqo",
        "cwd",
        "cbw",
        "cwde",
        "cdqe",
        "bsf",
        "bsr",
        "xchg",
        "jmp",
        "nop",
        *["cmov" + c for c in CONDITIONS],
        *["set" + c for c in CONDITIONS],
    }, name
    read_ids, _ = insn.regs_access()
    reads = sum({gpr(insn.reg_name(i)) for i in read_ids})
    addresses = 0
    for op in ops:
        if op.type == x86.X86_OP_MEM:
            addresses |= gpr(insn.reg_name(op.mem.base)) | gpr(insn.reg_name(op.mem.index))
    reads &= ~addresses
    # Removing address bits from Capstone's combined set must not remove a
    # register also used as a value. Reintroduce all explicit read operands.
    for op in ops:
        if op.type == x86.X86_OP_REG and op.access & capstone.CS_AC_READ:
            reads |= gpr(insn.reg_name(op.reg))
    if name in {"bsf", "bsr"} or name.startswith("cmov"):
        reads |= gpr(insn.reg_name(ops[0].reg))
    if name == "lea":
        reads |= addresses
        addresses = 0
    if name in {"push", "pop"}:
        addresses |= 1 << 4
        reads &= ~(1 << 4)
    if name in {"cdq", "cqo", "cwd", "cbw", "cwde", "cdqe"}:
        reads |= 1
    if name in {"xor", "sub"} and all(op.type == x86.X86_OP_REG for op in ops):
        if ops[0].reg == ops[1].reg:
            reads = 0
    writes = 0
    replaces = 0
    for op in ops:
        if op.type == x86.X86_OP_REG and op.access & capstone.CS_AC_WRITE:
            bit = gpr(insn.reg_name(op.reg))
            writes |= bit
            if op.size >= 4:
                replaces |= bit
    if name in {"cdq", "cqo", "cwd"}:
        writes, replaces = 4, 0 if name == "cwd" else 4
    if name in {"cbw", "cwde", "cdqe"}:
        writes, replaces = 1, 0 if name == "cbw" else 1
    if name in {"push", "pop"}:
        writes &= ~(1 << 4)
        replaces &= ~(1 << 4)
    if name == "bswap" and ops[0].size == 2:
        bit = gpr(insn.reg_name(ops[0].reg))
        assert row["undefined_registers"] == bit and bit != 16
        assert row["writes"] == bit and not row["reads"] and not row["replaces"]
        return
    assert not row["undefined_registers"]
    if name not in {"bsf", "bsr"}:
        assert not row["nondeterministic_registers"]
    assert reads & ~row["reads"] == 0, (name, "missing value dependence")
    assert addresses & ~row["addresses"] == 0, (name, "missing address dependence")
    assert writes & ~row["writes"] == 0, (name, "missing destination")
    assert row["replaces"] & ~replaces == 0, (name, "invalid whole-register replacement")
    observer = name == "push" or any(
        op.type == x86.X86_OP_MEM and op.access & capstone.CS_AC_WRITE for op in ops
    )
    if observer:
        assert reads & ~row["observable"] == 0
    flags_read = CF if name in {"adc", "sbb", "rcl", "rcr", "cmc"} else 0
    if name.startswith("cmov") or name.startswith("set"):
        flags_read = CONDITIONS[name[4:] if name.startswith("cmov") else name[3:]]
        assert row["conditional"] == name.startswith("cmov")
    flags_written, constants, undefined = 0, 0, 0
    if name in {"add", "sub", "adc", "sbb", "cmp", "neg"}:
        flags_written = ALL
    elif name in {"and", "or", "xor", "test"}:
        flags_written, constants, undefined = ALL, CF | OF, AF
    elif name in {"inc", "dec"}:
        flags_written = ALL & ~CF
    elif name in {"rol", "ror", "rcl", "rcr", "shl", "sal", "shr", "sar"}:
        flags_written = ALL if name in {"shl", "sal", "shr", "sar"} else CF | OF
        undefined = AF | OF if flags_written == ALL else OF
        if name in {"shl", "sal", "shr"}:
            undefined |= CF
        assert row["may_preserve_flags"]
    elif name in {"bt", "bts", "btr", "btc"}:
        flags_written, undefined = ALL, ALL & ~CF
    elif name in {"bsf", "bsr"}:
        flags_written, undefined = ALL, ALL & ~ZF
        assert row["nondeterministic_registers"] == gpr(insn.reg_name(ops[0].reg))
    elif name in {"clc", "stc", "cmc"}:
        flags_written = CF
        constants = 0 if name == "cmc" else CF
    # Conservative unknown ZF for BT is accepted; it cannot erase dependence.
    assert row["flag_reads"] == flags_read
    assert row["flag_writes"] == flags_written
    assert row["flag_constants"] == constants
    assert row["flag_undefined"] == undefined


def prove(slice_record, cs, at):
    steps = slice_record["steps"]
    assert 1 < len(steps) <= 64
    initial = [z3.BitVec(f"initial_r{i}", 64) for i in range(16)]
    initial_flags = [z3.Bool(f"initial_f{i}") for i in range(6)]
    states = [(initial.copy(), initial_flags.copy()) for _ in range(2)]
    different = []
    for index, row in enumerate(steps):
        pc, next_pc = int(row["site"], 0), int(row["next"], 0)
        encoded = bytes.fromhex(row["bytes"])
        assert encoded == at(pc, len(encoded))
        insn = next(cs.disasm(encoded, pc), None)
        assert insn and insn.size == len(encoded)
        assert next_pc == (insn.operands[0].imm if insn.mnemonic == "jmp" else pc + insn.size)
        assert index == 0 or int(steps[index - 1]["next"], 0) == pc
        dependencies(insn, row)
        for i in range(16):
            if not row["unknown_registers"] & (1 << i):
                different.append(states[0][0][i] != states[1][0][i])
        for i in range(6):
            if not row["unknown_flags"] & (1 << i):
                different.append(states[0][1][i] != states[1][1][i])
        for i in range(16):
            if (row["addresses"] | row["observable"]) & (1 << i):
                different.append(states[0][0][i] != states[1][0][i])
        for side, (registers, flags) in enumerate(states):
            inputs = [registers[i] for i in range(16) if row["reads"] & (1 << i)]
            inputs += [flags[i] for i in range(6) if row["flag_reads"] & (1 << i)]
            output = registers.copy()
            for i in range(16):
                if row["undefined_registers"] & (1 << i) or row["nondeterministic_registers"] & (
                    1 << i
                ):
                    output[i] = z3.BitVec(f"undefined_{index}_{i}_{side}", 64)
                elif row["writes"] & (1 << i):
                    args = inputs.copy()
                    if row["conditional"] or not row["replaces"] & (1 << i):
                        args.append(registers[i])
                    function = z3.Function(
                        f"effect_{index}_r{i}", *[x.sort() for x in args], z3.BitVecSort(64)
                    )
                    output[i] = function(*args)
            next_flags = flags.copy()
            for i in range(6):
                bit = 1 << i
                if not row["flag_writes"] & bit:
                    continue
                if row["flag_undefined"] & bit:
                    next_flags[i] = z3.Bool(f"undefined_f{index}_{i}_{side}")
                else:
                    args = [] if row["flag_constants"] & bit else inputs.copy()
                    if row["may_preserve_flags"]:
                        args.append(flags[i])
                    function = z3.Function(
                        f"effect_{index}_f{i}", *[x.sort() for x in args], z3.BoolSort()
                    )
                    next_flags[i] = function(*args)
            states[side] = output, next_flags
    assert int(slice_record["entry"], 0) == int(steps[0]["site"], 0)
    assert slice_record["destination"] == steps[0]["undefined_registers"]
    assert int(slice_record["end"], 0) == int(steps[-1]["next"], 0)
    different += [a != b for a, b in zip(states[0][0] + states[0][1], states[1][0] + states[1][1])]
    solver = z3.Solver()
    solver.set(timeout=5000)
    solver.add(z3.Or(*different))
    assert solver.check() == z3.unsat, "slice can influence an observable or surviving output"
    return len(steps)


def controls(cs):
    template = {
        "reads": 0,
        "writes": 0,
        "replaces": 0,
        "addresses": 0,
        "observable": 0,
        "undefined_registers": 0,
        "nondeterministic_registers": 0,
        "flag_reads": 0,
        "flag_writes": 0,
        "flag_constants": 0,
        "flag_undefined": 0,
        "conditional": False,
        "may_preserve_flags": False,
        "unknown_registers": 0,
        "unknown_flags": 0,
    }

    def rows(codes, fields):
        pc, steps, raw = 0x1000, [], b""
        for code, values in zip(codes, fields):
            encoded = bytes.fromhex(code)
            steps.append(
                dict(template, site=hex(pc), next=hex(pc + len(encoded)), bytes=code, **values)
            )
            raw += encoded
            pc += len(encoded)
        return {"entry": "0x1000", "end": hex(pc), "destination": 128, "steps": steps}, raw

    first = {"writes": 128, "undefined_registers": 128}
    kill = {"writes": 128, "replaces": 128, "unknown_registers": 128}
    positive, raw = rows(["660fcf", "bf37000000"], [first, kill])
    prove(positive, cs, lambda pc, count: raw[pc - 0x1000 : pc - 0x1000 + count])
    trials = [
        rows(["660fcf", "bf37000000"], [first, dict(kill, unknown_registers=0)]),
        rows(["660fcf", "66bf3700"], [first, dict(kill, replaces=0)]),
        rows(
            ["660fcf", "488907", "bf37000000"],
            [
                first,
                {"reads": 1, "observable": 1, "addresses": 128, "unknown_registers": 128},
                kill,
            ],
        ),
        rows(
            ["660fcf", "4080c701", "bf37000000"],
            [
                first,
                {"reads": 128, "writes": 128, "flag_writes": 63, "unknown_registers": 128},
                dict(kill, unknown_flags=63),
            ],
        ),
    ]
    for trial, raw in trials:
        try:
            prove(trial, cs, lambda pc, count: raw[pc - 0x1000 : pc - 0x1000 + count])
        except AssertionError as error:
            assert str(error) == "slice can influence an observable or surviving output"
        else:
            raise AssertionError("unsafe dependence control accepted")
    return {"positive": 1, "refuted": len(trials)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--corpus-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    report = json.loads(args.report.read_text())
    corpus = json.loads(args.corpus_report.read_text())
    assert report["passed"] and report["corpus_report_sha256"] == digest(args.corpus_report)
    expected = {
        "original": corpus["original_sha256"],
        **{r["label"]: r["sha256"] for r in corpus["protection"]},
    }
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True
    control_results = controls(cs)
    result = {
        "passed": False,
        "capstone_version": capstone.__version__,
        "z3_version": z3.get_version_string(),
        "report_sha256": digest(args.report),
        "source_sha256": digest(Path(__file__)),
        "unique_slices": 0,
        "symbolic_steps": 0,
        "slice_occurrences": 0,
        "completed_runs": 0,
        "abstract_steps": 0,
        "captures": {},
    }
    seen = set()
    result["controls"] = control_results
    for run in report["runs"]:
        label = run["label"]
        binary = args.corpus_report.parent / label
        assert digest(binary) == expected[label] == run["input_sha256"]
        raw = binary.read_bytes()
        spans = segments(raw)

        def at(address, count):
            values = [
                raw[o + address - v : o + address - v + count]
                for v, o, n in spans
                if v <= address and address + count <= v + n
            ]
            assert len(values) == 1
            return values[0]

        capture_path = args.report.parent / label / "region_temporal.json"
        assert digest(capture_path) == run["artifact_sha256"]["region_temporal.json"]
        result["captures"][label] = digest(capture_path)
        capture = json.loads(capture_path.read_text())
        assert not capture["errors"]
        for trace in capture["traces"]:
            mask, flag_mask = trace["unknown_register_mask"], trace["unknown_flag_mask"]
            for row in trace["final_registers"]:
                reg = int(row["reg"])
                assert not (0x100 <= reg < 0x110 and mask & (1 << (reg - 0x100)))
                assert not (flag_mask and reg in {0x12, 0x13})
            result["completed_runs"] += int(trace["native_temporal_complete"])
            result["abstract_steps"] += trace["abstract_instruction_count"]
            for record in trace["undefined_result_slices"]:
                result["slice_occurrences"] += 1
                key = label, json.dumps(
                    {k: v for k, v in record.items() if k != "sequence"}, sort_keys=True
                )
                if key not in seen:
                    result["symbolic_steps"] += prove(record, cs, at)
                    seen.add(key)
    assert seen
    result["unique_slices"] = len(seen)
    result["passed"] = True
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "captures"}, sort_keys=True))


if __name__ == "__main__":
    main()
