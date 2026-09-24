"""Verify two bounded Morok entry-state replays against protected QEMU runs."""

import argparse
import copy
import hashlib
import json
from collections import Counter
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from verify_native_candidate_trace import elf64_load_segments
from verify_native_shadow_states import (
    REGISTER_NAMES,
    STATUS_BITS,
    align,
    candidate,
    register_values,
    runtime,
)

MASK64 = (1 << 64) - 1


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sample_states(trace):
    execution = {row["sequence"]: index for index, row in enumerate(trace["execution"])}
    states = {}
    for row in trace["states"]:
        if row["kind"] != "native instruction entry":
            continue
        index = execution[row["sequence"]]
        assert row["site"] == trace["execution"][index]["site"] and index not in states
        states[index] = register_values(row)
    assert len(states) == len(execution) == 4096
    return states


def compare(states, entries, mapping, observed_sp, translated_sp):
    matches = Counter()
    flag_matches = Counter()
    mismatches = {}
    all_flags = 0
    for candidate_index, runtime_index in sorted(mapping.items()):
        candidate_regs = states[candidate_index]
        runtime_regs = entries[runtime_index]["registers"]
        for index, name in enumerate(REGISTER_NAMES):
            value = candidate_regs[256 + index]
            displacement = value - translated_sp
            if -0x8000 <= displacement <= 0x8000:
                value = (observed_sp + displacement) & MASK64
            actual = int(runtime_regs[name], 16)
            if value == actual:
                matches[name] += 1
            elif name not in mismatches:
                mismatches[name] = {
                    "candidate_index": candidate_index,
                    "candidate": hex(value),
                    "runtime": hex(actual),
                }
        flag_difference = candidate_regs[18] ^ int(runtime_regs["eflags"], 16)
        all_flags += (flag_difference & 0x8D5) == 0
        for name, bit in STATUS_BITS.items():
            flag_matches[name] += (flag_difference & (1 << bit)) == 0
    return {
        "aligned_entries": len(mapping),
        "exact_gpr_matches_after_explicit_stack_translation": dict(matches),
        "first_gpr_mismatch": mismatches,
        "status_bit_matches": dict(flag_matches),
        "all_six_status_bits_match": all_flags,
        "all_gprs_match": len(mapping) == 4094
        and all(matches[name] == len(mapping) for name in REGISTER_NAMES),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "binary",
        "second_binary",
        "input",
        "shadow",
        "second_shadow",
        "old_first_ida",
        "old_second_ida",
        "first_ida",
        "second_ida",
        "old_first_runtime",
        "old_second_runtime",
        "first_runtime",
        "second_runtime",
        "output",
    ):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args()
    image = args.binary.read_bytes()
    shadow = args.shadow.read_bytes()
    assert image == args.second_binary.read_bytes()
    assert shadow == args.second_shadow.read_bytes() and len(shadow) == 65536
    segments = elf64_load_segments(image)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    comparisons = []
    captured_states = []
    checks = {}
    hashes = {
        name: digest(getattr(args, name))
        for name in (
            "binary",
            "second_binary",
            "input",
            "shadow",
            "second_shadow",
            "old_first_ida",
            "old_second_ida",
            "first_ida",
            "second_ida",
            "old_first_runtime",
            "old_second_runtime",
            "first_runtime",
            "second_runtime",
        )
    }
    checks["binary_pair_identical"] = hashes["binary"] == hashes["second_binary"]
    checks["shadow_pair_identical"] = hashes["shadow"] == hashes["second_shadow"]
    for label in ("first", "second"):
        ida_path = getattr(args, label + "_ida")
        runtime_path = getattr(args, label + "_runtime")
        prior_ida = getattr(args, "old_" + label + "_ida")
        prior_runtime = getattr(args, "old_" + label + "_runtime")
        capture = candidate(ida_path, prior_ida, image, segments, shadow, decoder)
        observed = runtime(
            runtime_path, prior_runtime, hashes["binary"], hashes["input"], hashes["shadow"]
        )
        ida_report = json.loads(ida_path.read_text())
        runtime_report = json.loads(runtime_path.read_text())
        trace = ida_report["capture"]
        entry = runtime_report["entry_registers"]
        assert entry == observed["entries"][0]["registers"]
        assert len(bytes.fromhex(runtime_report["entry_stack_128_hex"])) == 128
        assert trace["entry_state_replay"] and trace["native_state_capture_complete"]
        assert trace["observed_entry_sp"] == entry["rsp"]
        assert trace["entry_stack_bytes"] == 128
        assert trace["stack_relative_gpr_mask"] == (1 << 4) | (1 << 5) | (1 << 13)
        assert not ida_report["errors"] and all(item["passed"] for item in ida_report["checks"])
        assert ida_report["inventory_before"] == ida_report["inventory_after"]
        assert all(capture["checks"].values()) and all(observed["checks"].values())
        mapping, skipped, complete = align(
            capture["visits"], observed["entries"], capture["heads"], capture["stop_pc"]
        )
        states = sample_states(trace)
        captured_states.append(states)
        observed_sp = int(entry["rsp"], 16)
        translated_sp = int(trace["entry_sp"], 16)
        result = compare(states, observed["entries"], mapping, observed_sp, translated_sp)
        result["gdb_omitted_sites"] = skipped
        result["aligned_boundary_complete"] = complete
        result["shadow_stack_read_count"] = sum(
            row["kind"] == "read" and translated_sp <= int(row["address"], 16) < translated_sp + 128
            for row in trace["data"]
        )
        assert result["all_gprs_match"] and complete
        altered_entries = copy.deepcopy(observed["entries"])
        index = mapping[0]
        altered = int(altered_entries[index]["registers"]["rax"], 16) ^ 1
        altered_entries[index]["registers"]["rax"] = hex(altered)
        result["gpr_mutation_rejected"] = not compare(
            states, altered_entries, mapping, observed_sp, translated_sp
        )["all_gprs_match"]
        assert result["gpr_mutation_rejected"]
        comparisons.append(result)
        checks[label + "_capture_and_runtime"] = True
        checks[label + "_all_gprs"] = result["all_gprs_match"]
        checks[label + "_mutation_rejected"] = result["gpr_mutation_rejected"]
    checks["same_entry_normalized_gpr_trace"] = captured_states[0] == captured_states[1]
    report = {
        "schema": 1,
        "checks": checks,
        "input_sha256": hashes,
        "bounds": {
            "planned_heads": 16335,
            "entered_instructions_per_run": 4096,
            "aligned_entries_per_run": 4094,
            "gprs": 16,
            "total_exact_gpr_comparisons": 2 * 4094 * 16,
        },
        "runs": comparisons,
        "scope": "bounded caller-supplied entry-state replay; physical stack addresses translated",
        "not_established": [
            "full RFLAGS equality",
            "stack-byte consumption in this prefix",
            "complete plan",
            "other inputs",
            "VM state or ownership",
        ],
    }
    assert all(checks.values())
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("[chernobog][shadow-replay] PASS")


if __name__ == "__main__":
    main()
