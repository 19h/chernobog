"""Compare QEMU/GDB process traces with the bounded synthetic IDA capture."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile

from verify_native_candidate_trace import elf64_load_segments, file_bytes


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_run(path, candidate, image, segments):
    trace = json.loads(path.read_text())
    visits = trace["instructions"]
    expected = candidate["execution"]
    heads = {row["site"]: row for row in candidate["heads"]}
    mismatches = {"address": [], "runtime_byte": [], "image_byte": []}
    for index, (actual, planned) in enumerate(zip(visits, expected)):
        address = int(actual["pc"], 16)
        size = int(planned["size"])
        encoded = bytes.fromhex(heads[planned["site"]]["bytes"])
        runtime = bytes.fromhex(actual["bytes_16_hex"])[:size]
        file_value = file_bytes(image, segments, address, size)
        if actual["pc"] != planned["site"]:
            mismatches["address"].append(index)
        if runtime != encoded:
            mismatches["runtime_byte"].append(index)
        if file_value != runtime:
            mismatches["image_byte"].append(index)
    for state_name in ("initial", "callback"):
        state = trace[state_name]
        for name, address, size in (
            ("root_4096", 0x418440, 4096),
            ("packed_65536", 0x430000, 65536),
        ):
            expected_hash = hashlib.sha256(file_bytes(image, segments, address, size)).hexdigest()
            if state[name + "_sha256"] != expected_hash:
                mismatches["image_byte"].append(state_name + ":" + name)
    return {
        "report_sha256": digest(path),
        "instruction_entries": len(visits),
        "stop": trace["stop"],
        "next_pc": trace.get("next_pc"),
        "initial_pc": trace["initial"]["registers"]["rip"],
        "callback_registers": trace["callback"]["registers"],
        "mismatches": mismatches,
        "address_sequence": [row["pc"] for row in visits],
        "byte_sequence": [row["bytes_16_hex"] for row in visits],
    }


def check_negative_controls(path, candidate, image, segments):
    original = json.loads(path.read_text())
    with tempfile.TemporaryDirectory() as directory:
        mutant_path = Path(directory) / "mutant.json"
        changed_address = copy.deepcopy(original)
        changed_address["instructions"][0]["pc"] = "0x418441"
        mutant_path.write_text(json.dumps(changed_address))
        address_result = check_run(mutant_path, candidate, image, segments)
        changed_byte = copy.deepcopy(original)
        encoded = changed_byte["instructions"][0]["bytes_16_hex"]
        changed_byte["instructions"][0]["bytes_16_hex"] = (
            "00" if encoded[:2] != "00" else "ff"
        ) + encoded[2:]
        mutant_path.write_text(json.dumps(changed_byte))
        byte_result = check_run(mutant_path, candidate, image, segments)
    return {
        "changed_address_rejected": 0 in address_result["mismatches"]["address"],
        "changed_byte_rejected": (
            0 in byte_result["mismatches"]["runtime_byte"]
            and 0 in byte_result["mismatches"]["image_byte"]
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--second-binary", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--first-runtime", type=Path, required=True)
    parser.add_argument("--second-runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    image = args.binary.read_bytes()
    second_image = args.second_binary.read_bytes()
    candidate = json.loads(args.candidate.read_text())["candidate"]
    assert candidate["scope"] == "native-candidate-region"
    assert candidate["synthetic_entry"] and candidate["candidate_decode"]
    segments = elf64_load_segments(image)
    runs = [
        check_run(path, candidate, image, segments)
        for path in (args.first_runtime, args.second_runtime)
    ]
    negative_controls = check_negative_controls(args.first_runtime, candidate, image, segments)
    same_addresses = runs[0]["address_sequence"] == runs[1]["address_sequence"]
    same_bytes = runs[0]["byte_sequence"] == runs[1]["byte_sequence"]
    for row in runs:
        row.pop("address_sequence")
        row.pop("byte_sequence")
    passed = (
        image == second_image
        and same_addresses
        and same_bytes
        and all(negative_controls.values())
        and all(
            row["instruction_entries"] == len(candidate["execution"])
            and row["stop"] == "instruction-limit"
            and row["next_pc"] == candidate["stop_pc"]
            and row["initial_pc"] == "0x40021b"
            and not any(row["mismatches"].values())
            for row in runs
        )
    )
    output = {
        "schema": 1,
        "binary_sha256": digest(args.binary),
        "second_binary_sha256": digest(args.second_binary),
        "candidate_sha256": digest(args.candidate),
        "probe_source_sha256": digest(Path(__file__).with_name("morok_qemu_runtime_trace.py")),
        "verifier_source_sha256": digest(Path(__file__)),
        "runtime_address_sequences_match": same_addresses,
        "runtime_byte_sequences_match": same_bytes,
        "negative_controls": negative_controls,
        "runs": runs,
        "passed": passed,
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": passed,
                "visits_per_run": [row["instruction_entries"] for row in runs],
                "mismatch_counts": [
                    {name: len(values) for name, values in row["mismatches"].items()}
                    for row in runs
                ],
            }
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
