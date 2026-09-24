"""Compare bounded shadow instruction states with two protected QEMU runs."""

import argparse
import copy
import hashlib
import json
from collections import Counter
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from verify_native_candidate_trace import elf64_load_segments
from verify_native_shadow_trace import mapped_bytes

ROOT = 0x430000
REGISTER_NAMES = (
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
GDB_NAMES = set(REGISTER_NAMES) | {"rip", "eflags"}
STATUS_BITS = {"CF": 0, "PF": 2, "AF": 4, "ZF": 6, "SF": 7, "OF": 11}
MASK64 = (1 << 64) - 1


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def register_values(row):
    values = {}
    for fragment in row["registers"].split(";"):
        reg, width, value = fragment.split(":")
        reg = int(reg)
        assert reg not in values and int(width) == 8
        values[reg] = int(value, 16)
    assert set(values) == {16, 18} | set(range(256, 272))
    return values


def candidate(path, old_path, image, segments, shadow, decoder):
    report = json.loads(path.read_text())
    trace = report["capture"]
    old = json.loads(old_path.read_text())["shadow"]
    heads = {int(row["site"], 16): row for row in trace["heads"]}
    assert len(heads) == len(trace["heads"]) == 16335
    head_mismatch = []
    for address, row in heads.items():
        encoded = bytes.fromhex(row["bytes"])
        decoded = next(decoder.disasm(encoded, address), None)
        if (
            mapped_bytes(image, segments, shadow, address, len(encoded)) != encoded
            or decoded is None
            or decoded.size != len(encoded)
            or len(encoded) != int(row["size"])
        ):
            head_mismatch.append(hex(address))
    visits = trace["execution"]
    execution_by_sequence = {row["sequence"]: index for index, row in enumerate(visits)}
    assert len(visits) == len(execution_by_sequence) == 4096
    states = {}
    for row in trace["states"]:
        if row["kind"] != "native instruction entry":
            continue
        index = execution_by_sequence[row["sequence"]]
        assert index not in states and row["site"] == visits[index]["site"]
        states[index] = register_values(row)
    checks = {
        "probe": not report["errors"] and all(row["passed"] for row in report["checks"]),
        "inventory_unchanged": report["inventory_before"] == report["inventory_after"],
        "shadow_hash": report["shadow_sha256"] == hashlib.sha256(shadow).hexdigest(),
        "same_prior_path_and_edges": all(
            trace[key] == old[key] for key in ("heads", "execution", "edges", "stop", "stop_pc")
        ),
        "sampled_complete": trace["native_state_capture_requested"]
        and trace["native_state_capture_complete"]
        and trace["shadow_instruction_states"]
        and not trace["native_walk"]
        and not trace["region_code_changed"]
        and not trace["function_evidence_published"]
        and not trace["vm_identity_proved"]
        and len(states) == len(visits) == trace["instruction_count"] == 4096,
        "all_head_bytes_and_decodes": not head_mismatch,
    }
    return {
        "report_sha256": digest(path),
        "old_report_sha256": digest(old_path),
        "planned_heads": len(heads),
        "entered_instructions": len(visits),
        "sampled_instruction_states": len(states),
        "checks": checks,
        "head_mismatches": head_mismatch,
        "visits": visits,
        "states": states,
        "heads": heads,
        "stop_pc": trace["stop_pc"],
        "inventory": report["inventory_before"],
    }


def runtime(path, old_path, binary_hash, input_hash, shadow_hash):
    report = json.loads(path.read_text())
    old = json.loads(old_path.read_text())
    entries = report["entries"]
    assert len(entries) == report["instruction_limit"] == 4096
    for row in entries:
        assert set(row["registers"]) == GDB_NAMES
        assert row["pc"] == row["registers"]["rip"]
        assert all(0 <= int(value, 16) <= MASK64 for value in row["registers"].values())
        assert len(bytes.fromhex(row["bytes_16_hex"])) == 16
    checks = {
        "binary_hash": report["binary_sha256"] == binary_hash,
        "input_hash": report["input_sha256"] == input_hash,
        "mapped_shadow_hash": report["entry_packed_65536_sha256"] == shadow_hash,
        "same_prior_pc_bytes": all(
            row["pc"] == previous["pc"] and row["bytes_16_hex"] == previous["bytes_16_hex"]
            for row, previous in zip(entries, old["instructions"])
        )
        and len(entries) == len(old["instructions"]),
        "bounded_stop": report["stop"] == old["stop"] == "instruction-limit"
        and report["next_pc"] == old["next_pc"],
    }
    return {
        "report_sha256": digest(path),
        "old_report_sha256": digest(old_path),
        "reported_entries": len(entries),
        "elapsed_ns": report["elapsed_ns"],
        "checks": checks,
        "entries": entries,
    }


def align(visits, entries, heads, stop_pc):
    mapping = {}
    skipped = []
    candidate_index = runtime_index = 0
    while candidate_index < len(visits) and runtime_index < len(entries):
        if visits[candidate_index]["site"] == entries[runtime_index]["pc"]:
            mapping[candidate_index] = runtime_index
            candidate_index += 1
            runtime_index += 1
            continue
        if not candidate_index or candidate_index + 1 >= len(visits):
            break
        omitted = visits[candidate_index]
        previous = visits[candidate_index - 1]
        address = int(omitted["site"], 16)
        preceding = int(previous["site"], 16)
        next_pc = int(entries[runtime_index]["pc"], 16)
        encoded = bytes.fromhex(heads[address]["bytes"])
        window = bytes.fromhex(entries[runtime_index - 1]["bytes_16_hex"])
        size = int(previous["size"])
        if not (
            entries[runtime_index]["pc"] == visits[candidate_index + 1]["site"]
            and int(heads[address]["flow"]) == 0
            and preceding + size == address
            and address + int(omitted["size"]) == next_pc
            and window[size : size + len(encoded)] == encoded
        ):
            break
        skipped.append(omitted["site"])
        candidate_index += 1
    complete = (
        candidate_index == len(visits)
        and runtime_index < len(entries)
        and entries[runtime_index]["pc"] == stop_pc
        and len(skipped) == 2
    )
    return mapping, skipped, complete


def compare(states, entries, mapping):
    initial_candidate = states[0]
    initial_runtime = entries[0]["registers"]
    entry_equal = [
        name
        for index, name in enumerate(REGISTER_NAMES)
        if initial_candidate[256 + index] == int(initial_runtime[name], 16)
    ]
    exact = Counter()
    relative = Counter()
    flag_bits = Counter()
    all_six_status_bits_match = 0
    distinct = {name: set() for name in REGISTER_NAMES}
    changed = Counter()
    previous = {}
    first_mismatch = {}
    for candidate_index, runtime_index in sorted(mapping.items()):
        candidate_regs = states[candidate_index]
        runtime_regs = entries[runtime_index]["registers"]
        assert candidate_regs[16] == int(runtime_regs["rip"], 16)
        for index, name in enumerate(REGISTER_NAMES):
            candidate_value = candidate_regs[256 + index]
            runtime_value = int(runtime_regs[name], 16)
            distinct[name].add(candidate_value)
            if name in previous:
                changed[name] += candidate_value != previous[name]
            previous[name] = candidate_value
            exact[name] += candidate_value == runtime_value
            relative[name] += (candidate_value - initial_candidate[256 + index]) & MASK64 == (
                runtime_value - int(initial_runtime[name], 16)
            ) & MASK64
            if candidate_value != runtime_value and name not in first_mismatch:
                first_mismatch[name] = candidate_index
        candidate_flags = candidate_regs[18]
        runtime_flags = int(runtime_regs["eflags"], 16)
        all_six_status_bits_match += int(((candidate_flags ^ runtime_flags) & 0x8D5) == 0)
        for name, bit in STATUS_BITS.items():
            flag_bits[name] += bool(candidate_flags & (1 << bit)) == bool(
                runtime_flags & (1 << bit)
            )
    checks = {
        "entry_equal_registers_match_all_mapped_entries": bool(entry_equal)
        and all(exact[name] == len(mapping) for name in entry_equal),
        "relative_stack_pointer_matches_all_mapped_entries": relative["rsp"] == len(mapping),
        "matched_result_register_changes": "rax" in entry_equal
        and exact["rax"] == len(mapping)
        and len(distinct["rax"]) > 1,
    }
    return {
        "aligned_entries": len(mapping),
        "entry_equal_registers": entry_equal,
        "exact_register_matches": dict(exact),
        "relative_register_matches": dict(relative),
        "distinct_candidate_register_values": {
            name: len(values) for name, values in distinct.items()
        },
        "candidate_register_changes": dict(changed),
        "status_bit_matches": dict(flag_bits),
        "all_six_status_bits_match": all_six_status_bits_match,
        "first_register_mismatch_candidate_index": first_mismatch,
        "checks": checks,
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
    second_shadow = args.second_shadow.read_bytes()
    assert image == args.second_binary.read_bytes()
    assert shadow == second_shadow and len(shadow) == 65536
    segments = elf64_load_segments(image)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    candidates = [
        candidate(path, old, image, segments, shadow, decoder)
        for path, old in (
            (args.first_ida, args.old_first_ida),
            (args.second_ida, args.old_second_ida),
        )
    ]
    runtimes = [
        runtime(path, old, digest(args.binary), digest(args.input), digest(args.shadow))
        for path, old in (
            (args.first_runtime, args.old_first_runtime),
            (args.second_runtime, args.old_second_runtime),
        )
    ]
    same_candidate_states = candidates[0]["states"] == candidates[1]["states"]
    same_runtime_pc_bytes = all(
        left["pc"] == right["pc"] and left["bytes_16_hex"] == right["bytes_16_hex"]
        for left, right in zip(runtimes[0]["entries"], runtimes[1]["entries"])
    )
    cross_run_register_matches = Counter()
    for left, right in zip(runtimes[0]["entries"], runtimes[1]["entries"]):
        for name in REGISTER_NAMES:
            cross_run_register_matches[name] += left["registers"][name] == right["registers"][name]
    comparisons = []
    mappings = []
    for candidate_report, runtime_report in zip(candidates, runtimes):
        mapping, skipped, complete = align(
            candidate_report["visits"],
            runtime_report["entries"],
            candidate_report["heads"],
            candidate_report["stop_pc"],
        )
        result = compare(candidate_report["states"], runtime_report["entries"], mapping)
        result["omitted_gdb_entry_sites"] = skipped
        result["candidate_boundary_reached"] = complete
        comparisons.append(result)
        mappings.append(mapping)
    mutated_rax = copy.deepcopy(runtimes[0]["entries"])
    mutated_rax[1]["registers"]["rax"] = hex(int(mutated_rax[1]["registers"]["rax"], 16) ^ 1)
    negative_rax_rejected = not compare(candidates[0]["states"], mutated_rax, mappings[0])[
        "checks"
    ]["entry_equal_registers_match_all_mapped_entries"]
    mutated_rsp = copy.deepcopy(runtimes[0]["entries"])
    mutated_rsp[1]["registers"]["rsp"] = hex(int(mutated_rsp[1]["registers"]["rsp"], 16) ^ 1)
    negative_rsp_rejected = not compare(candidates[0]["states"], mutated_rsp, mappings[0])[
        "checks"
    ]["relative_stack_pointer_matches_all_mapped_entries"]
    for row in candidates:
        for key in ("visits", "states", "heads", "stop_pc"):
            row.pop(key)
    for row in runtimes:
        row.pop("entries")
    passed = (
        all(all(row["checks"].values()) for row in candidates + runtimes + comparisons)
        and all(row["candidate_boundary_reached"] for row in comparisons)
        and same_candidate_states
        and same_runtime_pc_bytes
        and negative_rax_rejected
        and negative_rsp_rejected
    )
    output = {
        "schema": 1,
        "source_sha256": digest(Path(__file__)),
        "binary_sha256": digest(args.binary),
        "input_sha256": digest(args.input),
        "shadow_sha256": digest(args.shadow),
        "second_shadow_sha256": digest(args.second_shadow),
        "candidate_states_match": same_candidate_states,
        "runtime_pc_bytes_match": same_runtime_pc_bytes,
        "cross_run_register_matches": dict(cross_run_register_matches),
        "negative_rax_mutation_rejected": negative_rax_rejected,
        "negative_rsp_mutation_rejected": negative_rsp_rejected,
        "candidates": candidates,
        "runtimes": runtimes,
        "comparisons": comparisons,
        "passed": passed,
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": passed,
                "aligned_entries": [row["aligned_entries"] for row in comparisons],
                "entry_equal_registers": comparisons[0]["entry_equal_registers"],
                "entry_equal_exact": {
                    name: comparisons[0]["exact_register_matches"][name]
                    for name in comparisons[0]["entry_equal_registers"]
                },
                "relative_rsp": [row["relative_register_matches"]["rsp"] for row in comparisons],
            }
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
