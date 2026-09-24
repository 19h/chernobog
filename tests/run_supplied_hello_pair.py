#!/usr/bin/env python3
"""Measure a supplied original/protected macOS x86-64 pair with bounded runs."""

import argparse
import json
from pathlib import Path
import platform
import struct
import sys

sys.dont_write_bytecode = True
from run_vmp_corpus import digest, execute


def validate_macho_x64(path):
    header = path.read_bytes()[:32]
    if len(header) != 32:
        raise ValueError("truncated Mach-O header")
    magic, cpu_type, _, file_type, _, _, _, _ = struct.unpack("<IiiIIIII", header)
    if (magic, cpu_type, file_type) != (0xFEEDFACF, 0x01000007, 2):
        raise ValueError("expected thin x86-64 Mach-O executable")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--protected", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.runs <= 20:
        parser.error("--runs must be in [1, 20]")
    original, protected = args.original.resolve(), args.protected.resolve()
    for path in (original, protected):
        validate_macho_x64(path)
    if original == protected or digest(original) == digest(protected):
        parser.error("original and protected inputs must differ")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "schema": 1,
        "scope": "bounded macOS process exit and stdout/stderr comparison only",
        "runner_sha256": digest(Path(__file__)),
        "host_system": platform.system(),
        "host_machine": platform.machine(),
        "inputs": {
            "original": {"sha256": digest(original), "bytes": original.stat().st_size},
            "protected": {"sha256": digest(protected), "bytes": protected.stat().st_size},
        },
        "runs": [],
    }
    passed = True
    first_observation = {}
    for trial in range(args.runs):
        pair = {"trial": trial}
        outputs = {}
        for label, path in (("original", original), ("protected", protected)):
            measurement, stdout, stderr = execute([path], timeout=5)
            unchanged = digest(path) == report["inputs"][label]["sha256"]
            outputs[label] = (measurement["exit_code"], stdout, stderr)
            pair[label] = {
                **measurement,
                "binary_unchanged": unchanged,
                "stdout_bytes": len(stdout),
                "stderr_bytes": len(stderr),
                "stdout_hex": stdout.hex() if len(stdout) <= 64 else None,
                "repeat_equal": label not in first_observation
                or outputs[label] == first_observation[label],
            }
            first_observation.setdefault(label, outputs[label])
            passed &= (
                measurement["exit_code"] == 0
                and not measurement["timed_out"]
                and not measurement["output_exceeded"]
                and unchanged
                and pair[label]["repeat_equal"]
            )
        pair["behavior_equal"] = outputs["original"] == outputs["protected"]
        passed &= pair["behavior_equal"]
        report["runs"].append(pair)
    report["passed"] = bool(passed)
    (output / "paired_process.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS" if passed else "FAIL", "paired runs=%d" % args.runs)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
