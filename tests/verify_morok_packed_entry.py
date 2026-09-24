"""Verify the paired keygen's mapped packed-code transition and output oracle."""

import argparse
import hashlib
import json
from pathlib import Path

from verify_native_candidate_trace import elf64_load_segments, file_bytes

PACKED = 0x430000
PACKED_SIZE = 65536
CALLBACK = 0x418440
VALID_STDIN = b"1\n1234-56789-01234\n800001\n20270101\n"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check_capture(report_path, dump_path, binary_hash, input_hash, file_hash, root_hash):
    report = json.loads(report_path.read_text())
    dumped = dump_path.read_bytes()
    before = report["initial"]
    callback = report["callback"]
    entry = report["packed_entry"]
    checks = {
        "binary_hash": report["binary_sha256"] == binary_hash,
        "input_hash": report["input_sha256"] == input_hash,
        "entry_pc": before["registers"]["rip"] == "0x40021b",
        "callback_pc": callback["registers"]["rip"] == hex(CALLBACK),
        "packed_pc": entry["registers"]["rip"] == hex(PACKED),
        "packed_range": report["packed_region"] == [hex(PACKED), hex(PACKED + PACKED_SIZE)],
        "file_bytes_at_start": before["packed_65536_sha256"] == file_hash,
        "file_bytes_at_callback": callback["packed_65536_sha256"] == file_hash,
        "callback_bytes_stable": all(
            state["callback_4096_sha256"] == root_hash for state in (before, callback, entry)
        ),
        "dump_size": len(dumped) == PACKED_SIZE,
        "dump_hash": report["dump_sha256"] == digest(dumped)
        and entry["packed_65536_sha256"] == digest(dumped),
        "dump_prefix": entry["packed_first_32_hex"] == dumped[:32].hex(),
    }
    return {
        "report_sha256": digest(report_path.read_bytes()),
        "dump_sha256": digest(dumped),
        "checks": checks,
        "dump": dumped,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--first-binary", type=Path, required=True)
    parser.add_argument("--second-binary", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--first-report", type=Path, required=True)
    parser.add_argument("--second-report", type=Path, required=True)
    parser.add_argument("--first-dump", type=Path, required=True)
    parser.add_argument("--second-dump", type=Path, required=True)
    parser.add_argument("--original-stdout", type=Path, required=True)
    parser.add_argument("--protected-stdout", type=Path, required=True)
    parser.add_argument("--second-protected-stdout", type=Path, required=True)
    parser.add_argument("--original-stderr", type=Path, required=True)
    parser.add_argument("--protected-stderr", type=Path, required=True)
    parser.add_argument("--second-protected-stderr", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    original = args.original.read_bytes()
    first_binary = args.first_binary.read_bytes()
    second_binary = args.second_binary.read_bytes()
    stdin = args.input.read_bytes()
    segments = elf64_load_segments(first_binary)
    file_region = file_bytes(first_binary, segments, PACKED, PACKED_SIZE)
    callback_region = file_bytes(first_binary, segments, CALLBACK, 4096)
    assert file_region is not None and callback_region is not None
    file_hash = digest(file_region)
    binary_hash = digest(first_binary)
    runs = [
        check_capture(path, dump, binary_hash, digest(stdin), file_hash, digest(callback_region))
        for path, dump in (
            (args.first_report, args.first_dump),
            (args.second_report, args.second_dump),
        )
    ]
    first_dump, second_dump = (row.pop("dump") for row in runs)
    original_stdout = args.original_stdout.read_bytes()
    protected_stdout = args.protected_stdout.read_bytes()
    second_protected_stdout = args.second_protected_stdout.read_bytes()
    original_stderr = args.original_stderr.read_bytes()
    protected_stderr = args.protected_stderr.read_bytes()
    second_protected_stderr = args.second_protected_stderr.read_bytes()
    checks = {
        "fixed_seed_binaries_equal": first_binary == second_binary,
        "protected_differs_from_original": first_binary != original,
        "valid_input_exact": stdin == VALID_STDIN,
        "unpacked_dumps_equal": first_dump == second_dump,
        "mapped_bytes_changed": first_dump != file_region,
        "valid_stdout_equal": original_stdout == protected_stdout == second_protected_stdout
        and b"Password:" in original_stdout,
        "valid_stderr_equal": original_stderr == protected_stderr == second_protected_stderr == b"",
    }
    changed_bytes = sum(left != right for left, right in zip(first_dump, file_region))
    passed = all(checks.values()) and all(all(row["checks"].values()) for row in runs)
    output = {
        "schema": 1,
        "source_sha256": digest(Path(__file__).read_bytes()),
        "probe_source_sha256": digest(
            Path(__file__).with_name("morok_qemu_packed_entry.py").read_bytes()
        ),
        "original_sha256": digest(original),
        "protected_sha256": binary_hash,
        "input_sha256": digest(stdin),
        "file_region_sha256": file_hash,
        "mapped_region_sha256": digest(first_dump),
        "changed_byte_positions": changed_bytes,
        "valid_stdout_sha256": digest(original_stdout),
        "valid_stdout_bytes": len(original_stdout),
        "checks": checks,
        "runs": runs,
        "passed": passed,
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({"passed": passed, "changed_byte_positions": changed_bytes, "checks": checks}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
