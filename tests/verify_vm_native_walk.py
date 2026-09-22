"""Independent decode and scalar/stack checks for recorded native admissions."""

import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_OP_REG


def verify_transfer(trace, step):
    mode = trace["address_bits"]
    width = mode // 8
    source, target, sequence = int(step["source"], 0), int(step["target"], 0), int(step["sequence"])
    heads = {int(h["site"], 0): h for h in trace["heads"]}
    decoder = Cs(CS_ARCH_X86, CS_MODE_64 if mode == 64 else CS_MODE_32)
    decoder.detail = True
    encoded = bytes.fromhex(heads[source]["bytes"])
    insn = next(decoder.disasm(encoded, source))
    assert insn.size == len(encoded)
    states = [
        s
        for s in trace["states"]
        if int(s["sequence"]) == sequence
        and s["kind"] == "transfer target"
        and int(s["site"], 0) == target
        and int(s["source"], 0) == source
    ]
    edges = [
        e
        for e in trace["edges"]
        if int(e["sequence"]) == sequence
        and int(e["source"], 0) == source
        and int(e["target"], 0) == target
    ]
    assert len(states) == len(edges) == 1
    registers = {}
    for item in states[0]["registers"].split(";"):
        reg, size, value = item.split(":")
        registers[int(reg)] = (int(size), int(value, 0))
    sp_id = 0x104 if mode == 64 else 0x204
    assert registers[sp_id][0] == width
    sp = registers[sp_id][1]
    visits = [p for p in trace["execution"] if int(p["sequence"]) < sequence]
    assert visits and int(visits[-1]["site"], 0) == source
    begin = int(visits[-1]["sequence"])
    memory = [d for d in trace["data"] if begin < int(d["sequence"]) < sequence]
    assert all(int(d["site"], 0) == source for d in memory)
    if insn.mnemonic == "ret":
        assert edges[0]["kind"] == "return"
        adjustment = insn.operands[0].imm if insn.operands else 0
        assert len(memory) == 1 and memory[0]["kind"] == "read"
        read = memory[0]
        assert int(read["size"]) == width and int(read["value"], 0) == target
        assert int(read["address"], 0) + width + adjustment == sp
        return "near_return"
    assert insn.mnemonic in {"jmp", "call"} and len(insn.operands) == 1
    operand = insn.operands[0]
    assert operand.type == CS_OP_REG and operand.size == width
    names = (
        ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] + [f"r{i}" for i in range(8, 16)]
        if mode == 64
        else ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
    )
    reg = (0x100 if mode == 64 else 0x200) + names.index(insn.reg_name(operand.reg))
    assert registers[reg][0] == width
    value = registers[reg][1]
    if insn.mnemonic == "call":
        assert edges[0]["kind"] == "call" and len(memory) == 1 and memory[0]["kind"] == "write"
        write = memory[0]
        assert int(write["size"]) == width and int(write["value"], 0) == source + insn.size
        assert int(write["address"], 0) == sp
        if reg == sp_id:
            value += width
        kind = "register_call"
    else:
        assert edges[0]["kind"] == "jump" and not memory
        kind = "register_jump"
    assert value & ((1 << mode) - 1) == target
    return kind


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    digest = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
    report = json.loads(args.report.read_text())
    assert report["passed"] and report["native_walk"]
    result = {
        "schema": 1,
        "passed": False,
        "source_sha256": digest(__file__),
        "report_sha256": digest(args.report),
        "capstone_version": capstone.__version__,
        "capture_sha256": {},
        "transfers": {},
        "admitted": 0,
        "rejected": 0,
        "separate_run_prefix_differences": {},
        "negative_controls": 0,
    }
    counts, differences, examples = Counter(), Counter(), {}
    for run in report["runs"]:
        path = args.report.parent / run["label"] / "vm_native_inputs.json"
        assert digest(path) == run["artifact_sha256"][path.name]
        result["capture_sha256"][run["label"]] = digest(path)
        capture = json.loads(path.read_text())
        assert capture["passed"]
        for row in capture["captures"]:
            trace = row["trace"]
            for field, equal in row["separate_run_prefix_equal"].items():
                differences[field] += not equal
            for step in trace["native_admissions"]:
                kind = verify_transfer(trace, step)
                counts[kind] += 1
                result["admitted" if step["admitted"] == "true" else "rejected"] += 1
                examples.setdefault(kind, (trace, step))
    # Falsification: mutate the reported target consistently in the edge/state
    # records, retaining the original source operand/read. The oracle must reject.
    for trace, step in examples.values():
        changed = copy.deepcopy(trace)
        candidate = dict(step)
        candidate["target"] = hex(int(step["target"], 0) ^ 1)
        for edge in changed["edges"]:
            if edge["sequence"] == step["sequence"]:
                edge["target"] = candidate["target"]
        for state in changed["states"]:
            if state["sequence"] == step["sequence"] and state["kind"] == "transfer target":
                state["site"] = candidate["target"]
        try:
            verify_transfer(changed, candidate)
        except AssertionError:
            result["negative_controls"] += 1
        else:
            raise AssertionError("altered target admitted")
    assert counts and result["negative_controls"] == len(examples)
    result["transfers"] = dict(counts)
    result["separate_run_prefix_differences"] = dict(differences)
    result["passed"] = True
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "capture_sha256"}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(type(error).__name__, file=sys.stderr)
        sys.exit(1)
