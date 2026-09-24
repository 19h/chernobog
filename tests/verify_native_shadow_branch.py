"""Verify a protected Morok input branch against QEMU and IDA checkpoint replay."""

import argparse
import copy
import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RSP

from verify_native_shadow_boundary_memory import translate
from verify_native_shadow_states import REGISTER_NAMES, register_values

ROOT = 0x430000
COMPARE = 0x430315
BRANCH = 0x43031A
TARGET = 0x43042B
FALLTHROUGH = 0x430320
SHADOW_OFFSET = COMPARE - ROOT
FIRST_DIFFERENCE = 21979
LIMIT = 32768


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decoded_pair(shadow):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    first = next(decoder.disasm(shadow[:16], COMPARE), None)
    second = next(decoder.disasm(shadow[5:21], BRANCH), None)
    assert first is not None and first.address == COMPARE and first.size == 5
    assert first.mnemonic == "cmp" and len(first.operands) == 2
    memory, immediate = first.operands
    assert memory.type == X86_OP_MEM and memory.size == 4
    assert memory.mem.base == X86_REG_RSP and memory.mem.index == 0
    assert memory.mem.disp == 12
    assert immediate.type == X86_OP_IMM and immediate.imm == 1
    assert second is not None and second.address == BRANCH and second.size == 6
    assert second.mnemonic == "jne" and len(second.operands) == 1
    assert second.operands[0].type == X86_OP_IMM and second.operands[0].imm == TARGET
    return first, second


def verify_case(ida, runtime, long_path, binary_hash, input_hash, full_shadow, suffix):
    trace = ida["capture"]
    assert not ida["errors"] and all(check["passed"] for check in ida["checks"])
    assert ida["inventory_before"] == ida["inventory_after"]
    assert ida["root_info"]["is_tail"] and ida["root_info"]["item_head"] == hex(ROOT)
    assert ida["shadow_sha256"] == hashlib.sha256(suffix).hexdigest()
    assert runtime["binary_sha256"] == long_path["binary_sha256"] == binary_hash
    assert runtime["input_sha256"] == long_path["input_sha256"] == input_hash
    assert runtime["entry_packed_65536_sha256"] == hashlib.sha256(full_shadow).hexdigest()
    assert runtime["branch_packed_65536_sha256"] == long_path["entry_packed_65536_sha256"]
    assert runtime["branch_packed_65536_sha256"] == hashlib.sha256(full_shadow).hexdigest()
    assert long_path["budget"] == len(long_path["entries"]) == LIMIT
    assert long_path["entry_pc"] == hex(ROOT)
    assert long_path["entries"][FIRST_DIFFERENCE - 2]["pc"] == hex(COMPARE)
    assert long_path["entries"][FIRST_DIFFERENCE - 1]["pc"] == hex(BRANCH)
    assert long_path["entries"][FIRST_DIFFERENCE]["pc"] == runtime["successor_registers"]["rip"]
    assert (
        long_path["entries"][FIRST_DIFFERENCE - 2]["bytes_16_hex"]
        == runtime["compare_bytes_16_hex"]
    )
    assert (
        bytes.fromhex(runtime["compare_bytes_16_hex"])
        == full_shadow[SHADOW_OFFSET : SHADOW_OFFSET + 16]
    )
    assert trace["available"] and trace["ran"] and trace["observed_tail_checkpoint"]
    assert trace["runtime_shadow"] and trace["runtime_data"]
    assert trace["entry_state_replay"] and trace["native_state_capture_complete"]
    assert trace["observed_entry_sp"] == runtime["compare_registers"]["rsp"]
    assert trace["entry_stack_below_bytes"] == runtime["stack_below"] == 1024
    assert trace["entry_stack_bytes"] == runtime["stack_above"] == 128
    assert trace["data_bytes"] == runtime["data_length"] == 1696
    assert trace["data_start"] == runtime["data_start"]
    assert len(bytes.fromhex(runtime["compare_data_hex"])) == 1696
    assert trace["instruction_count"] == trace["instruction_budget"] == 2
    assert trace["stop"] == "instruction-budget"
    assert not trace["function_evidence_published"] and not trace["vm_identity_proved"]
    assert trace["root"] == hex(COMPARE) and trace["shadow_start"] == hex(COMPARE)
    assert trace["shadow_bytes"] == len(suffix)
    assert trace["stop_pc"] == runtime["successor_registers"]["rip"]
    assert [(row["site"], int(row["size"])) for row in trace["execution"]] == [
        (hex(COMPARE), 5),
        (hex(BRANCH), 6),
    ]
    heads = {int(row["site"], 16): row for row in trace["heads"]}
    assert bytes.fromhex(heads[COMPARE]["bytes"]) == suffix[:5]
    assert bytes.fromhex(heads[BRANCH]["bytes"]) == suffix[5:11]
    stack = bytes.fromhex(runtime["compare_stack_hex"])
    assert len(stack) == 1024 + 128
    word = struct.unpack_from("<I", stack, 1024 + 12)[0]
    assert word in (1, 2)
    assert trace["data"] == [
        {
            "address": hex(int(trace["entry_sp"], 16) + 12),
            "kind": "read",
            "sequence": "1",
            "site": hex(COMPARE),
            "size": "4",
            "value": hex(word),
        }
    ]
    observed = (
        runtime["compare_registers"],
        runtime["branch_registers"],
        runtime["successor_registers"],
    )
    assert [row["rip"] for row in observed] == [
        hex(COMPARE),
        hex(BRANCH),
        hex(FALLTHROUGH if word == 1 else TARGET),
    ]
    assert bool(int(observed[1]["eflags"], 16) & (1 << 6)) == (word == 1)
    sp = int(trace["entry_sp"], 16)
    observed_sp = int(observed[0]["rsp"], 16)
    assert (sp & 0xFFF) == (observed_sp & 0xFFF)
    rows = [
        register_values(row) for row in trace["states"] if row["kind"] == "native instruction entry"
    ]
    assert len(rows) == 2
    final = {int(row["reg"]): int(row["value"], 16) for row in trace["final_registers"]}
    assert set(final) == set(rows[0]) == set(rows[1])
    for state, actual in zip((*rows, final), observed):
        assert state[16] == int(actual["rip"], 16)
        assert state[18] == int(actual["eflags"], 16)
        for index, name in enumerate(REGISTER_NAMES):
            assert translate(state[256 + index], sp, observed_sp)[0] == int(actual[name], 16)
    assert ida["stack_word_mutation"]["original"] == word
    assert ida["stack_word_mutation"]["changed"] == 3 - word
    assert ida["stack_word_mutation"]["stop_pc"] == hex(TARGET if word == 1 else FALLTHROUGH)
    assert ida["stack_word_mutation"]["data"] == [
        {
            "address": hex(sp + 12),
            "kind": "read",
            "sequence": "1",
            "site": hex(COMPARE),
            "size": "4",
            "value": hex(3 - word),
        }
    ]
    return {
        "stack_word": word,
        "successor": observed[2]["rip"],
        "exact_register_values": 3 * (16 + 2),
        "exact_stack_reads": 1,
        "inventory_unchanged": True,
        "negative_probe_checks": sum(
            "rejected" in row["case"] or "requires" in row["case"] for row in ida["checks"]
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "pair_report",
        "binary",
        "second_binary",
        "full_shadow",
        "suffix_shadow",
        "first_input",
        "second_input",
        "first_long",
        "second_long",
        "first_prefix",
        "second_prefix",
        "first_runtime",
        "second_runtime",
        "first_ida",
        "second_ida",
        "output",
    ):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args()
    paired = json.loads(args.pair_report.read_text())
    binary_hash = sha(args.binary)
    assert binary_hash == sha(args.second_binary)
    assert paired["artifact_sha256"]["first"] == paired["artifact_sha256"]["second"] == binary_hash
    full_shadow = args.full_shadow.read_bytes()
    suffix = args.suffix_shadow.read_bytes()
    assert len(full_shadow) == 65536 and suffix == full_shadow[SHADOW_OFFSET:]
    decoded_pair(suffix)
    case_names = ("valid_v14_1", "valid_v14_0")
    paths = (
        (args.first_input, args.first_long, args.first_prefix, args.first_runtime, args.first_ida),
        (
            args.second_input,
            args.second_long,
            args.second_prefix,
            args.second_runtime,
            args.second_ida,
        ),
    )
    results = []
    loaded = []
    for name, (input_path, long_path, prefix_path, runtime_path, ida_path) in zip(
        case_names, paths
    ):
        input_hash = sha(input_path)
        case = paired["cases"][name]
        assert case["input_sha256"] == input_hash and case["paired_equal"]
        assert case["exit_code"] == 0
        long = json.loads(long_path.read_text())
        prefix = json.loads(prefix_path.read_text())
        assert prefix["binary_sha256"] == binary_hash
        assert prefix["input_sha256"] == input_hash
        assert prefix["entry_packed_65536_sha256"] == long["entry_packed_65536_sha256"]
        assert long["entries"][:4094] == prefix["reported_path"]
        assert long["entries"][4094]["pc"] == prefix["boundary_registers"]["rip"]
        runtime = json.loads(runtime_path.read_text())
        ida = json.loads(ida_path.read_text())
        assert ida["observation_sha256"] == sha(runtime_path)
        result = verify_case(ida, runtime, long, binary_hash, input_hash, full_shadow, suffix)
        results.append(result)
        loaded.append((ida, runtime, long))
    first, second = loaded
    difference = next(
        (
            index
            for index, (a, b) in enumerate(zip(first[2]["entries"], second[2]["entries"]))
            if a != b
        ),
        None,
    )
    assert difference == FIRST_DIFFERENCE
    assert results[0]["stack_word"] == 1 and results[1]["stack_word"] == 2
    assert results[0]["successor"] == hex(FALLTHROUGH)
    assert results[1]["successor"] == hex(TARGET)
    assert (
        paired["cases"][case_names[0]]["stdout_sha256"]
        != paired["cases"][case_names[1]]["stdout_sha256"]
    )
    mutated = dict(
        first[1], successor_registers=dict(first[1]["successor_registers"], rip=hex(TARGET))
    )
    rejected = False
    try:
        verify_case(
            first[0], mutated, first[2], binary_hash, sha(args.first_input), full_shadow, suffix
        )
    except AssertionError:
        rejected = True
    assert rejected
    changed_stack = bytearray.fromhex(first[1]["compare_stack_hex"])
    struct.pack_into("<I", changed_stack, 1024 + 12, 2)
    mutated_stack = dict(first[1], compare_stack_hex=changed_stack.hex())
    stack_rejected = False
    try:
        verify_case(
            first[0],
            mutated_stack,
            first[2],
            binary_hash,
            sha(args.first_input),
            full_shadow,
            suffix,
        )
    except AssertionError:
        stack_rejected = True
    assert stack_rejected
    mutated_ida = copy.deepcopy(first[0])
    branch_state = next(
        row
        for row in mutated_ida["capture"]["states"]
        if row["kind"] == "native instruction entry" and row["site"] == hex(BRANCH)
    )
    branch_state["registers"] = branch_state["registers"].replace("18:8:0x246", "18:8:0x206")
    assert branch_state["registers"] != next(
        row["registers"]
        for row in first[0]["capture"]["states"]
        if row["kind"] == "native instruction entry" and row["site"] == hex(BRANCH)
    )
    flags_rejected = False
    try:
        verify_case(
            mutated_ida, first[1], first[2], binary_hash, sha(args.first_input), full_shadow, suffix
        )
    except AssertionError:
        flags_rejected = True
    assert flags_rejected
    report = {
        "schema": 1,
        "source_sha256": sha(Path(__file__)),
        "pair_report_sha256": sha(args.pair_report),
        "binary_sha256": binary_hash,
        "full_shadow_sha256": sha(args.full_shadow),
        "suffix_shadow_sha256": sha(args.suffix_shadow),
        "inputs": dict(zip(case_names, (sha(args.first_input), sha(args.second_input)))),
        "first_different_reported_entry": difference,
        "common_reported_entries": difference,
        "branch_site": hex(BRANCH),
        "cases": dict(zip(case_names, results)),
        "exact_scalar_register_values": sum(row["exact_register_values"] for row in results),
        "wrong_successor_rejected": rejected,
        "wrong_stack_word_rejected": stack_rejected,
        "wrong_branch_flags_rejected": flags_rejected,
        "scope": "one observed two-instruction checkpoint per input; no whole-path replay or VM identity",
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
