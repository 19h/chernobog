"""Check an IDA shadow plan against ELF, runtime dump, Capstone and QEMU visits."""

import argparse
import copy
import hashlib
import json
from collections import Counter
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from verify_native_candidate_trace import elf64_load_segments, file_bytes

ROOT = 0x430000
SHADOW_SIZE = 65536


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fnv1a(data):
    value = 14695981039346656037
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return hex(value)


def mapped_bytes(image, segments, shadow, address, size):
    if ROOT <= address and address + size <= ROOT + len(shadow):
        return shadow[address - ROOT : address - ROOT + size]
    if address < ROOT + len(shadow) and address + size > ROOT:
        return None
    return file_bytes(image, segments, address, size)


def edge_rows(counter):
    return [
        {"source": source, "target": target, "count": count}
        for (source, target), count in sorted(counter.items())
    ]


def check_candidate(path, image, segments, shadow, decoder):
    report = json.loads(path.read_text())
    trace = report["shadow"]
    heads = {int(row["site"], 16): row for row in trace["heads"]}
    mismatches = {"head_bytes": [], "head_decode": [], "entered_bytes": [], "linear_successor": []}
    for address, row in heads.items():
        encoded = bytes.fromhex(row["bytes"])
        actual = mapped_bytes(image, segments, shadow, address, len(encoded))
        if encoded != actual or len(encoded) != int(row["size"]):
            mismatches["head_bytes"].append(hex(address))
        decoded = next(decoder.disasm(encoded, address), None)
        if decoded is None or decoded.size != len(encoded):
            mismatches["head_decode"].append(hex(address))
    visits = trace["execution"]
    for row in visits:
        address = int(row["site"], 16)
        size = int(row["size"])
        encoded = None if address not in heads else bytes.fromhex(heads[address]["bytes"])
        if encoded is None or encoded != mapped_bytes(image, segments, shadow, address, size):
            mismatches["entered_bytes"].append(hex(address))
    for left, right in zip(visits, visits[1:]):
        address = int(left["site"], 16)
        if int(heads[address]["flow"]) == 0 and int(right["site"], 16) != address + int(
            left["size"]
        ):
            mismatches["linear_successor"].append(hex(address))
    recorded_edges = Counter((row["source"], row["target"]) for row in trace["edges"])
    entered_edges = Counter(
        (left["site"], right["site"])
        for left, right in zip(visits, visits[1:])
        if int(right["site"], 16) != int(left["site"], 16) + int(left["size"])
    )
    checks = {
        "probe_checks": not report["errors"] and all(row["passed"] for row in report["checks"]),
        "snapshot_unchanged": report["inventory_before"] == report["inventory_after"],
        "candidate_available": trace["available"] and trace["runtime_shadow"],
        "supplied_shadow_hash": report["shadow_sha256"] == hashlib.sha256(shadow).hexdigest(),
        "synthetic_scope": trace["synthetic_entry"]
        and trace["scope"] == "native-candidate-region"
        and not trace["function_evidence_published"]
        and not trace["vm_identity_proved"],
        "shadow_size": trace["shadow_bytes"] == SHADOW_SIZE,
        "shadow_fingerprint": trace["shadow_fingerprint"] == fnv1a(shadow),
        "shadow_changed_bytes": trace["shadow_changed_bytes"]
        == sum(
            left != right
            for left, right in zip(shadow, file_bytes(image, segments, ROOT, len(shadow)))
        ),
        "all_head_bytes": not mismatches["head_bytes"],
        "all_head_decodes": not mismatches["head_decode"],
        "all_entered_bytes": not mismatches["entered_bytes"],
        "linear_successors": not mismatches["linear_successor"],
        "recorded_edges_match_execution": recorded_edges == entered_edges,
    }
    return {
        "report_sha256": digest(path),
        "planned_heads": len(heads),
        "entered_instructions": len(visits),
        "stop": trace["stop"],
        "stop_pc": trace["stop_pc"],
        "frontiers": len(trace["frontiers"]),
        "checks": checks,
        "mismatches": mismatches,
        "visits": visits,
        "heads": heads,
        "edges": trace["edges"],
        "inventory": report["inventory_before"],
    }


def check_runtime(path, candidate, image, segments, shadow, decoder, binary_hash, input_hash):
    report = json.loads(path.read_text())
    runtime = report["instructions"]
    visits = candidate["visits"]
    prefix = next(
        (
            index
            for index, (actual, planned) in enumerate(zip(runtime, visits))
            if actual["pc"] != planned["site"]
        ),
        min(len(runtime), len(visits)),
    )
    head_bytes = candidate["heads"]
    byte_mismatches = []
    runtime_byte_mismatches = []
    runtime_decode_mismatches = []
    runtime_sizes = []
    for index, row in enumerate(runtime):
        address = int(row["pc"], 16)
        actual = bytes.fromhex(row["bytes_16_hex"])
        decoded = next(decoder.disasm(actual, address), None)
        if decoded is None or decoded.size > len(actual):
            runtime_decode_mismatches.append(index)
            runtime_sizes.append(None)
            continue
        runtime_sizes.append(decoded.size)
        if actual[: decoded.size] != mapped_bytes(image, segments, shadow, address, decoded.size):
            runtime_byte_mismatches.append(index)
    for index in range(prefix):
        address = int(runtime[index]["pc"], 16)
        size = int(visits[index]["size"])
        encoded = bytes.fromhex(head_bytes[address]["bytes"])
        if bytes.fromhex(runtime[index]["bytes_16_hex"])[:size] != encoded:
            byte_mismatches.append(index)
    candidate_index = runtime_index = 0
    unobserved = []
    unobserved_indices = []
    while candidate_index < len(visits) and runtime_index < len(runtime):
        if visits[candidate_index]["site"] == runtime[runtime_index]["pc"]:
            candidate_index += 1
            runtime_index += 1
            continue
        if not candidate_index or candidate_index + 1 >= len(visits) or len(unobserved) >= 16:
            break
        omitted = visits[candidate_index]
        previous = visits[candidate_index - 1]
        omitted_address = int(omitted["site"], 16)
        previous_address = int(previous["site"], 16)
        omitted_bytes = bytes.fromhex(head_bytes[omitted_address]["bytes"])
        previous_window = bytes.fromhex(runtime[runtime_index - 1]["bytes_16_hex"])
        previous_size = int(previous["size"])
        if not (
            runtime[runtime_index]["pc"] == visits[candidate_index + 1]["site"]
            and int(head_bytes[omitted_address]["flow"]) == 0
            and previous_address + previous_size == omitted_address
            and omitted_address + int(omitted["size"]) == int(runtime[runtime_index]["pc"], 16)
            and previous_window[previous_size : previous_size + len(omitted_bytes)] == omitted_bytes
        ):
            break
        unobserved.append(omitted["site"])
        unobserved_indices.append(candidate_index)
        candidate_index += 1
    boundary_reached = (
        candidate_index == len(visits)
        and runtime_index < len(runtime)
        and runtime[runtime_index]["pc"] == candidate["stop_pc"]
    )
    observed_edges = Counter(
        (runtime[index]["pc"], runtime[index + 1]["pc"])
        for index in range(min(runtime_index, len(runtime) - 1))
        if runtime_sizes[index] is not None
        and int(runtime[index + 1]["pc"], 16)
        != int(runtime[index]["pc"], 16) + runtime_sizes[index]
    )
    omission_artifacts = Counter(
        (visits[index - 1]["site"], visits[index + 1]["site"]) for index in unobserved_indices
    )
    artifacts_observed = (observed_edges & omission_artifacts) == omission_artifacts
    adjusted_edges = observed_edges - omission_artifacts
    candidate_edges = Counter((row["source"], row["target"]) for row in candidate["edges"])
    missing_edges = candidate_edges - adjusted_edges
    extra_edges = adjusted_edges - candidate_edges
    checks = {
        "packed_entry": report["entry_registers"]["rip"] == hex(ROOT),
        "binary_hash": report["binary_sha256"] == binary_hash,
        "input_hash": report["input_sha256"] == input_hash,
        "mapped_dump": report["entry_packed_65536_sha256"] == hashlib.sha256(shadow).hexdigest(),
        "prefix_bytes": not byte_mismatches,
        "all_runtime_bytes": not runtime_byte_mismatches,
        "all_runtime_decodes": not runtime_decode_mismatches,
        "aligned_to_candidate_boundary": boundary_reached,
        "all_candidate_edges_observed": artifacts_observed
        and not missing_edges
        and not extra_edges,
        "bounded_runtime": report["stop"] == "instruction-limit" and len(runtime) <= 4096,
    }
    return {
        "report_sha256": digest(path),
        "instruction_entries": len(runtime),
        "matching_address_prefix": prefix,
        "first_runtime_divergence": None if prefix == len(runtime) else runtime[prefix]["pc"],
        "first_candidate_divergence": None if prefix == len(visits) else visits[prefix]["site"],
        "aligned_candidate_entries": candidate_index,
        "aligned_runtime_entries": runtime_index,
        "unobserved_gdb_entries": unobserved,
        "candidate_edge_count": sum(candidate_edges.values()),
        "runtime_nonfallthrough_count": sum(observed_edges.values()),
        "gdb_omission_edge_count": sum(omission_artifacts.values()),
        "missing_candidate_edges": edge_rows(missing_edges),
        "extra_runtime_edges": edge_rows(extra_edges),
        "candidate_boundary_reached": boundary_reached,
        "next_pc": report.get("next_pc"),
        "byte_mismatches_in_prefix": byte_mismatches,
        "runtime_byte_mismatches": runtime_byte_mismatches,
        "runtime_decode_mismatches": runtime_decode_mismatches,
        "checks": checks,
        "runtime": runtime,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--second-binary", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--shadow", type=Path, required=True)
    parser.add_argument("--second-shadow", type=Path, required=True)
    parser.add_argument("--first-ida", type=Path, required=True)
    parser.add_argument("--second-ida", type=Path, required=True)
    parser.add_argument("--first-runtime", type=Path, required=True)
    parser.add_argument("--second-runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    image = args.binary.read_bytes()
    second_image = args.second_binary.read_bytes()
    stdin = args.input.read_bytes()
    shadow = args.shadow.read_bytes()
    second_shadow = args.second_shadow.read_bytes()
    assert len(shadow) == SHADOW_SIZE
    segments = elf64_load_segments(image)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    candidates = [
        check_candidate(path, image, segments, shadow, decoder)
        for path in (args.first_ida, args.second_ida)
    ]
    runtime = [
        check_runtime(
            path,
            candidates[0],
            image,
            segments,
            shadow,
            decoder,
            digest(args.binary),
            digest(args.input),
        )
        for path in (args.first_runtime, args.second_runtime)
    ]
    candidate_visits_match = candidates[0]["visits"] == candidates[1]["visits"]
    runtime_visits_match = runtime[0]["runtime"] == runtime[1]["runtime"]
    mutated_shadow = bytearray(shadow)
    mutated_shadow[0] ^= 1
    shadow_rejected = check_candidate(args.first_ida, image, segments, mutated_shadow, decoder)
    negative_shadow_byte_mutation_rejected = (
        not shadow_rejected["checks"]["supplied_shadow_hash"]
        and not shadow_rejected["checks"]["all_head_bytes"]
    )
    mutated_candidate = copy.deepcopy(candidates[0])
    mutated_candidate["edges"][0]["target"] = "0xdeadbeef"
    edge_rejected = check_runtime(
        args.first_runtime,
        mutated_candidate,
        image,
        segments,
        shadow,
        decoder,
        digest(args.binary),
        digest(args.input),
    )
    negative_candidate_edge_mutation_rejected = (
        not edge_rejected["checks"]["all_candidate_edges_observed"]
        and sum(row["count"] for row in edge_rejected["missing_candidate_edges"]) == 1
        and sum(row["count"] for row in edge_rejected["extra_runtime_edges"]) == 1
    )
    for row in candidates:
        row.pop("visits")
        row.pop("heads")
        row.pop("edges")
    for row in runtime:
        row.pop("runtime")
    passed = (
        image == second_image
        and shadow == second_shadow
        and candidate_visits_match
        and runtime_visits_match
        and negative_shadow_byte_mutation_rejected
        and negative_candidate_edge_mutation_rejected
        and all(all(row["checks"].values()) for row in candidates + runtime)
        and runtime[0]["matching_address_prefix"] > 0
    )
    output = {
        "schema": 1,
        "source_sha256": digest(Path(__file__)),
        "binary_sha256": digest(args.binary),
        "second_binary_sha256": digest(args.second_binary),
        "input_sha256": digest(args.input),
        "shadow_sha256": digest(args.shadow),
        "second_shadow_sha256": digest(args.second_shadow),
        "capstone_version": __import__("capstone").__version__,
        "candidate_visits_match": candidate_visits_match,
        "runtime_visits_match": runtime_visits_match,
        "negative_shadow_byte_mutation_rejected": negative_shadow_byte_mutation_rejected,
        "negative_candidate_edge_mutation_rejected": negative_candidate_edge_mutation_rejected,
        "candidates": candidates,
        "runtime": runtime,
        "passed": passed,
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": passed,
                "planned_heads": candidates[0]["planned_heads"],
                "candidate_entries": candidates[0]["entered_instructions"],
                "matching_prefix": runtime[0]["matching_address_prefix"],
                "head_mismatches": [
                    {key: len(value) for key, value in row["mismatches"].items()}
                    for row in candidates
                ],
            }
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
