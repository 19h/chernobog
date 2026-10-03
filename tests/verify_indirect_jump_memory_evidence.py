#!/usr/bin/env python3
"""Verify paired exact direct-memory indirect-jump facts on x86-64 and i386."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES = ("known_memory_jump", "dynamic_memory_jump")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def record(region, site):
    rows = [row for row in region["records"] if row["kind"] == "indirect-jump-target"]
    assert len(rows) == 1 and rows[0]["site"] == site
    assert rows[0]["publication"] == "none"
    return rows[0]


def verify_current(report):
    assert report["passed"] and not report["errors"]
    bits = report["address_bits"]
    assert bits in (32, 64) and set(report["cases"]) == set(CASES)
    assert len(report["checks"]) == (10 if bits == 64 else 8)
    assert all(check["passed"] for check in report["checks"])
    for name in CASES:
        case = report["cases"][name]
        region = case["region"]
        assert len(case["site_bytes"]) == 12 and case["site_bytes"].startswith("ff25")
        displacement = int.from_bytes(bytes.fromhex(case["site_bytes"][4:]), "little")
        address = (
            int(case["site"], 16)
            + 6
            + (displacement if displacement < 0x80000000 else displacement - 0x100000000)
            if bits == 64
            else displacement
        )
        address &= (1 << bits) - 1
        assert hex(address) == case["decoded_operand_address"] == report["mutable_pointer"]
        assert region["root"] == case["start"] and region["address_bits"] == bits
        assert region["available"] and region["converged"] and not region["truncated"]
        assert region["published"] is False and len(region["records"]) == 1
        expected_nodes = 2 if bits == 32 or name == "dynamic_memory_jump" else 3
        assert len(region["nodes"]) == len(region["edges"]) == expected_nodes
        assert all(edge["kind"] != "direct-jump" for edge in region["edges"])
        assert any(
            edge["kind"] == "frontier"
            and edge["reason"] == "indirect_target"
            and edge["source"] == case["site"]
            for edge in region["edges"]
        )
        row = record(region, case["site"])
        assert row["source_kind"] == "memory"
        assert row["admission"] == "exact-writable-memory-encoding"
        assert row["width_bits"] == str(bits)
        if name == "dynamic_memory_jump":
            assert row["status"] == "unresolved" and row["target"] == "unknown"
            assert row["target_proof"] == "unresolved"
        else:
            assert row["status"] == "proved"
            assert row["target"] == report["target_seven"]
            assert row["target_proof"] == "local-memory-word"
        direct = case["direct_entry"]
        assert direct["available"] and direct["converged"] and not direct["truncated"]
        assert direct["published"] is False and direct["root"] == case["site"]
        assert len(direct["nodes"]) == len(direct["edges"]) == 1
        direct_row = record(direct, case["site"])
        assert direct_row["admission"] == "exact-writable-memory-encoding"
        assert direct_row["status"] == "unresolved" and direct_row["target"] == "unknown"


def verify_pair(prior, current):
    verify_current(current)
    assert prior["passed"] and not prior["errors"]
    for field in ("address_bits", "target_seven", "target_eight", "mutable_pointer"):
        assert prior[field] == current[field]
    assert set(prior["cases"]) == set(current["cases"]) == set(CASES)
    for name in CASES:
        before, after = prior["cases"][name], current["cases"][name]
        for field in (
            "start",
            "site",
            "site_bytes",
            "decoded_operand_type",
            "decoded_operand_address",
            "inventory",
        ):
            assert before[field] == after[field]
        a, b = before["region"], after["region"]
        assert a["root"] == b["root"]
        assert a["nodes"] == b["nodes"] and a["edges"] == b["edges"]
        old = record(a, before["site"])
        assert old["source_kind"] == "other"
        assert old["admission"] == "unresolved-encoding"
        assert old["status"] == "unresolved" and old["target"] == "unknown"
        old_direct = record(before["direct_entry"], before["site"])
        assert old_direct["status"] == "unresolved" and old_direct["target"] == "unknown"


def verify_raw_pair(certificate, section, prior_dir, current_dir):
    expected = certificate[section]
    pairs = []
    for label, directory in (("prior", prior_dir), ("current", current_dir)):
        report_path = directory / "indirect_jump_memory.json"
        run_path = directory / "run.json"
        assert sha256(report_path) == expected[label + "_report_sha256"]
        assert sha256(run_path) == expected[label + "_run_sha256"]
        report, run = read(report_path), read(run_path)
        assert run["input_sha256"] == expected["binary_sha256"]
        assert run["source_script_sha256"] == expected["probe_sha256"]
        assert run["ida_sha256"] == certificate["ida_sha256"]
        assert run["plugin_sha256"] == certificate[label + "_plugin_sha256"]
        assert run["artifacts_unchanged"] and run["source_script_unchanged"]
        pairs.append((report, run))
    assert (
        pairs[0][1]["chernobog_environment_sha256"] == pairs[1][1]["chernobog_environment_sha256"]
    )
    verify_pair(pairs[0][0], pairs[1][0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--match-source", action="store_true")
    parser.add_argument("--x64-prior-dir", type=Path)
    parser.add_argument("--x64-current-dir", type=Path)
    parser.add_argument("--i386-prior-dir", type=Path)
    parser.add_argument("--i386-current-dir", type=Path)
    parser.add_argument("--current-only-dir", type=Path, action="append", default=[])
    args = parser.parse_args()
    certificate = read(args.certificate)
    assert certificate["schema"] == "chernobog.indirect-jump-memory-evidence.v1"
    checks = []
    if args.match_source:
        for name, expected in certificate["source_sha256"].items():
            assert sha256(ROOT / name) == expected, name
        checks.append("source hashes")
    for section, prior_dir, current_dir in (
        ("x64", args.x64_prior_dir, args.x64_current_dir),
        ("i386", args.i386_prior_dir, args.i386_current_dir),
    ):
        assert (prior_dir is None) == (current_dir is None)
        if prior_dir is not None:
            verify_raw_pair(certificate, section, prior_dir, current_dir)
            checks.append(section + " paired raw reports")
    for directory in args.current_only_dir:
        verify_current(read(directory / "indirect_jump_memory.json"))
        checks.append("current " + directory.name)
    print("indirect jump memory evidence PASS: " + (", ".join(checks) or "schema"))


if __name__ == "__main__":
    main()
