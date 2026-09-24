"""Compare a Morok native replay with same-process defined x86-64 flag states."""

import argparse
import copy
import hashlib
import json
from collections import Counter
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86_const import X86_OP_IMM

from verify_native_shadow_boundary_memory import (
    final_register_comparison,
    memory_projection,
    translate,
)
from verify_native_shadow_states import REGISTER_NAMES, align, register_values

ROOT = 0x430000
BOUNDARY = 0x40C89B
FLAGS = {"CF": 0, "PF": 2, "AF": 4, "ZF": 6, "SF": 7, "OF": 11}
STATUS_MASK = sum(1 << bit for bit in FLAGS.values())
CF = 1 << FLAGS["CF"]
PF = 1 << FLAGS["PF"]
AF = 1 << FLAGS["AF"]
ZF = 1 << FLAGS["ZF"]
SF = 1 << FLAGS["SF"]
OF = 1 << FLAGS["OF"]
PRESERVE = {
    "mov",
    "movabs",
    "movzx",
    "lea",
    "jne",
    "je",
    "sete",
    "push",
    "pop",
    "call",
    "ret",
    "jmp",
    "pause",
}
ARITHMETIC = {"add", "sub", "cmp", "lock cmpxchg", "lock xadd"}
LOGICAL = {"xor", "and", "test"}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def next_defined_mask(mask, instruction):
    mnemonic = instruction.mnemonic
    if mnemonic in PRESERVE:
        return mask
    if mnemonic in ARITHMETIC:
        return STATUS_MASK
    if mnemonic in LOGICAL:
        return STATUS_MASK & ~AF
    if mnemonic == "imul":
        return CF | OF
    if mnemonic not in {"shl", "shr", "rol"}:
        raise AssertionError("unclassified flag effect: " + mnemonic)
    assert len(instruction.operands) == 2 and instruction.operands[1].type == X86_OP_IMM
    width = instruction.operands[0].size * 8
    assert width in (32, 64)
    count = instruction.operands[1].imm & (63 if width == 64 else 31)
    if count == 0:
        return mask
    assert 0 < count < width
    if mnemonic == "rol":
        return (mask & (PF | AF | ZF | SF)) | CF | (OF if count == 1 else 0)
    return CF | PF | ZF | SF | (OF if count == 1 else 0)


def verify_run(ida_path, runtime_path, binary_hash, input_hash, shadow_hash):
    ida = json.loads(ida_path.read_text())
    runtime = json.loads(runtime_path.read_text())
    trace = ida["capture"]
    assert not ida["errors"] and all(row["passed"] for row in ida["checks"])
    assert ida["inventory_before"] == ida["inventory_after"]
    assert runtime["binary_sha256"] == binary_hash
    assert runtime["input_sha256"] == input_hash
    assert runtime["entry_packed_65536_sha256"] == ida["shadow_sha256"] == shadow_hash
    assert ida["boundary_report_sha256"] == sha(runtime_path)
    assert runtime["entry_registers"] == runtime["entries"][0]["registers"]
    assert len(runtime["entries"]) == len(runtime["reported_path"]) == 4094
    assert runtime["reported_path"] == [
        {"pc": row["pc"], "bytes_16_hex": row["bytes_16_hex"]} for row in runtime["entries"]
    ]
    assert trace["available"] and trace["ran"] and trace["entry_state_replay"]
    assert trace["runtime_shadow"] and trace["runtime_data"]
    assert trace["native_state_capture_complete"] and trace["shadow_instruction_states"]
    assert trace["instruction_count"] == 4096 and trace["stop_pc"] == hex(BOUNDARY)
    assert trace["stop"] == "instruction-budget" and trace["plan_truncated"]
    assert not trace["function_evidence_published"] and not trace["vm_identity_proved"]
    assert trace["data_newly_loaded_bytes"] == 128
    assert int(runtime["entry_registers"]["rip"], 16) == ROOT
    assert int(runtime["boundary_registers"]["rip"], 16) == BOUNDARY
    heads = {int(row["site"], 16): row for row in trace["heads"]}
    entries = runtime["entries"] + [{"pc": runtime["boundary_registers"]["rip"]}]
    mapping, skipped, complete = align(trace["execution"], entries, heads, trace["stop_pc"])
    assert complete and len(mapping) == 4094
    assert skipped == ["0x40d63f", "0x40c1a2"]
    states = {
        row["sequence"]: register_values(row)
        for row in trace["states"]
        if row["kind"] == "native instruction entry"
    }
    assert len(states) == len(trace["execution"]) == 4096
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    synthetic_sp = int(trace["entry_sp"], 16)
    observed_sp = int(runtime["entry_registers"]["rsp"], 16)
    assert trace["observed_entry_sp"] == runtime["entry_registers"]["rsp"]
    assert (synthetic_sp & 0xFFF) == (observed_sp & 0xFFF)
    defined_mask = STATUS_MASK
    mask_counts = Counter()
    mnemonics = Counter()
    defined_bits = Counter()
    sf_after_imul_disagreements = of_after_multibit_shift_disagreements = 0
    exact_gprs = exact_raw_flags = exact_defined_states = exact_defined_bits = 0
    undefined_differing_bits = 0
    mutations = None
    previous_mnemonic = None
    previous_shift_count = 0
    for index, visit in enumerate(trace["execution"]):
        address = int(visit["site"], 16)
        head = heads[address]
        encoded = bytes.fromhex(head["bytes"])
        decoded = next(decoder.disasm(encoded, address), None)
        assert decoded is not None and decoded.size == len(encoded) == int(head["size"])
        mnemonics[decoded.mnemonic] += 1
        if decoded.mnemonic in {"je", "jne", "sete"}:
            assert defined_mask & ZF
        if index in mapping:
            observed = entries[mapping[index]]
            assert encoded == bytes.fromhex(observed["bytes_16_hex"])[: len(encoded)]
            candidate = states[visit["sequence"]]
            actual = observed["registers"]
            assert candidate[16] == int(actual["rip"], 16)
            for reg_index, name in enumerate(REGISTER_NAMES):
                value, _ = translate(candidate[256 + reg_index], synthetic_sp, observed_sp)
                exact_gprs += value == int(actual[name], 16)
            difference = candidate[18] ^ int(actual["eflags"], 16)
            assert difference & ~STATUS_MASK == 0
            exact_raw_flags += difference == 0
            exact_defined_states += (difference & defined_mask) == 0
            exact_defined_bits += defined_mask.bit_count() - (difference & defined_mask).bit_count()
            undefined_differing_bits += (difference & STATUS_MASK & ~defined_mask).bit_count()
            mask_counts[hex(defined_mask)] += 1
            for name, bit in FLAGS.items():
                defined_bits[name] += bool(defined_mask & (1 << bit))
            if previous_mnemonic is not None:
                sf_after_imul_disagreements += previous_mnemonic == "imul" and bool(difference & SF)
                of_after_multibit_shift_disagreements += (
                    previous_mnemonic in {"shl", "shr"}
                    and previous_shift_count > 1
                    and bool(difference & OF)
                )
            if mutations is None and difference and (difference & defined_mask) == 0:
                known_bit = defined_mask & -defined_mask
                undefined_bit = (difference & STATUS_MASK & ~defined_mask) & -(
                    difference & STATUS_MASK & ~defined_mask
                )
                assert known_bit and undefined_bit
                mutations = {
                    "defined_bit_flip_rejected": ((difference ^ known_bit) & defined_mask) != 0,
                    "undefined_bit_flip_ignored": ((difference ^ undefined_bit) & defined_mask)
                    == 0,
                    "raw_mask_rejects": (difference & STATUS_MASK) != 0,
                }
        defined_mask = next_defined_mask(defined_mask, decoded)
        previous_mnemonic = decoded.mnemonic
        previous_shift_count = (
            decoded.operands[1].imm & (63 if decoded.operands[0].size == 8 else 31)
            if decoded.mnemonic in {"shl", "shr"}
            else 0
        )
    assert exact_gprs == 4094 * 16
    assert exact_raw_flags == 3418
    assert exact_defined_states == 4094
    assert exact_defined_bits == sum(defined_bits.values())
    assert sf_after_imul_disagreements > 0 and of_after_multibit_shift_disagreements > 0
    assert mutations is not None and all(mutations.values())
    assert sum(mask_counts.values()) == 4094
    assert set(mnemonics) == PRESERVE | ARITHMETIC | LOGICAL | {"imul", "shl", "shr", "rol"}
    assert sum(mnemonics.values()) == 4096
    assert final_register_comparison(trace, runtime) == {
        "gpr_mismatches": {},
        "gpr_exact": 16,
        "rip_exact": True,
        "rflags_exact": True,
    }
    projection = memory_projection(trace, runtime, trace["final_writes"])
    assert projection["data_exact"] and projection["stack_exact"]
    assert projection["candidate_written_bytes"] == 142
    assert projection["translated_stack_pointer_words"] == 3
    changed = copy.deepcopy(trace["final_writes"])
    byte = bytearray.fromhex(changed[0]["bytes"])
    byte[0] ^= 1
    changed[0]["bytes"] = byte.hex()
    assert not memory_projection(trace, runtime, changed)["data_exact"]
    return {
        "ida_sha256": sha(ida_path),
        "runtime_sha256": sha(runtime_path),
        "aligned_entries": len(mapping),
        "omitted_gdb_entry_sites": skipped,
        "exact_gprs": exact_gprs,
        "exact_raw_rflags": exact_raw_flags,
        "exact_defined_flag_states": exact_defined_states,
        "exact_defined_flag_bits": exact_defined_bits,
        "defined_bit_counts": dict(sorted(defined_bits.items())),
        "undefined_differing_bits": undefined_differing_bits,
        "sf_after_imul_disagreements": sf_after_imul_disagreements,
        "of_after_multibit_shift_disagreements": of_after_multibit_shift_disagreements,
        "defined_mask_counts": dict(sorted(mask_counts.items())),
        "instruction_mnemonics": dict(sorted(mnemonics.items())),
        "exact_boundary_registers": 18,
        "exact_boundary_window_bytes": 2848,
        "negative_controls": mutations,
        "database_inventory_unchanged": True,
        "gdb_step_loop_elapsed_ns": runtime["elapsed_ns"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "binary",
        "second_binary",
        "input",
        "shadow",
        "second_shadow",
        "first_ida",
        "second_ida",
        "first_runtime",
        "second_runtime",
        "output",
    ):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args()
    assert args.binary.read_bytes() == args.second_binary.read_bytes()
    assert args.shadow.read_bytes() == args.second_shadow.read_bytes()
    binary_hash, input_hash, shadow_hash = sha(args.binary), sha(args.input), sha(args.shadow)
    runs = [
        verify_run(
            getattr(args, label + "_ida"),
            getattr(args, label + "_runtime"),
            binary_hash,
            input_hash,
            shadow_hash,
        )
        for label in ("first", "second")
    ]
    assert runs[0]["defined_mask_counts"] == runs[1]["defined_mask_counts"]
    assert runs[0]["instruction_mnemonics"] == runs[1]["instruction_mnemonics"]
    runtime_reports = [
        json.loads(getattr(args, label + "_runtime").read_text()) for label in ("first", "second")
    ]
    assert runtime_reports[0]["entry_data_hex"] == runtime_reports[1]["entry_data_hex"]
    assert runtime_reports[0]["boundary_data_hex"] == runtime_reports[1]["boundary_data_hex"]
    assert runtime_reports[0]["reported_path"] == runtime_reports[1]["reported_path"]
    report = {
        "schema": 1,
        "source_sha256": sha(Path(__file__)),
        "binary_sha256": binary_hash,
        "input_sha256": input_hash,
        "shadow_sha256": shadow_hash,
        "runs": runs,
        "total_exact_gprs": sum(run["exact_gprs"] for run in runs),
        "total_exact_defined_flag_states": sum(run["exact_defined_flag_states"] for run in runs),
        "total_exact_defined_flag_bits": sum(run["exact_defined_flag_bits"] for run in runs),
        "total_exact_boundary_registers": 36,
        "total_exact_boundary_window_bytes": 5696,
        "scope": "same-process observed entry windows, instruction registers and bounded boundary",
        "not_established": [
            "equality of architecturally undefined flag values",
            "intermediate memory equivalence outside sampled entry and final windows",
            "other inputs, later execution, logical VM identity or ordinary function evidence",
        ],
        "passed": True,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": True, "runs": runs}, indent=2))


if __name__ == "__main__":
    main()
