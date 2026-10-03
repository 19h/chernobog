#!/usr/bin/env python3
"""Verify the source-pinned XADD certificate and optional raw IDA pair."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def verify_raw(certificate, prior_dir, current_dir):
    prior = read(prior_dir / "xadd.json")
    current = read(current_dir / "xadd.json")
    prior_run = read(prior_dir / "run.json")
    current_run = read(current_dir / "run.json")
    assert sha256(prior_dir / "xadd.json") == certificate["prior_report_sha256"]
    assert sha256(current_dir / "xadd.json") == certificate["current_report_sha256"]
    assert sha256(prior_dir / "run.json") == certificate["prior_runner_sha256"]
    assert sha256(current_dir / "run.json") == certificate["current_runner_sha256"]
    assert prior["passed"] and prior["baseline"]
    assert current["passed"] and not current["baseline"]
    assert prior_run["input_sha256"] == current_run["input_sha256"]
    assert prior_run["input_sha256"] == certificate["binary_sha256"]
    assert prior_run["source_script_sha256"] == current_run["source_script_sha256"]
    assert prior_run["source_script_sha256"] == certificate["probe_sha256"]
    assert prior_run["ida_sha256"] == current_run["ida_sha256"]
    assert prior_run["ida_sha256"] == certificate["ida_sha256"]
    assert prior_run["plugin_sha256"] == certificate["prior_plugin_sha256"]
    assert current_run["plugin_sha256"] == certificate["current_plugin_sha256"]
    for run in (prior_run, current_run):
        assert run["artifacts_unchanged"] and run["source_script_unchanged"]

    assert list(prior["cases"]) == list(current["cases"])
    assert list(current["cases"]) == [case["name"] for case in certificate["cases"]]
    prior_proofs = current_proofs = 0
    for case in certificate["cases"]:
        name = case["name"]
        before, after = prior["cases"][name], current["cases"][name]
        assert before["decoded"] == after["decoded"]
        assert len(after["decoded"]) == 1
        decoded = after["decoded"][0]
        assert case["operand_types"] == [op["type"] for op in decoded["operands"]]
        assert case["operand_dtypes"] == [op["dtype"] for op in decoded["operands"]]
        assert case["auxpref"] == decoded["auxpref"]
        for row in before["proofs"] + after["proofs"]:
            assert row["truth"] == "native-proof" and row["fresh"] == "true"
        assert case["prior_values"] == [row["value"] for row in before["proofs"]]
        assert case["current_values"] == [row["value"] for row in after["proofs"]]
        prior_proofs += len(before["proofs"])
        current_proofs += len(after["proofs"])
    assert prior_proofs == certificate["prior_proofs"] == 0
    assert current_proofs == certificate["current_proofs"] == 16


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--match-source", action="store_true")
    parser.add_argument("--prior-dir", type=Path)
    parser.add_argument("--current-dir", type=Path)
    args = parser.parse_args()
    certificate = read(args.certificate)
    assert certificate["schema"] == "chernobog.xadd-garbage-evidence.v1"
    assert len(certificate["cases"]) == 18
    assert certificate["matched_input_probe_ida"] and certificate["artifacts_unchanged"]
    assert certificate["x86_execution_oracle"]["cases"] == 131456
    if args.match_source:
        for name, expected in certificate["source_sha256"].items():
            assert sha256(ROOT / name) == expected, name
    assert (args.prior_dir is None) == (args.current_dir is None)
    if args.prior_dir is not None:
        verify_raw(certificate, args.prior_dir, args.current_dir)
    print("XADD certificate PASS: 18 cases, 0 prior proofs, 16 current proofs")


if __name__ == "__main__":
    main()
