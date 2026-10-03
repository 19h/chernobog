#!/usr/bin/env python3
"""Verify the source-pinned BT-family certificate and optional raw IDA pair."""

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
    prior = read(prior_dir / "bit-test.json")
    current = read(current_dir / "bit-test.json")
    prior_run = read(prior_dir / "run.json")
    current_run = read(current_dir / "run.json")
    for run_dir, report_key, runner_key in (
        (prior_dir, "prior_report_sha256", "prior_runner_sha256"),
        (current_dir, "current_report_sha256", "current_runner_sha256"),
    ):
        assert sha256(run_dir / "bit-test.json") == certificate[report_key]
        assert sha256(run_dir / "run.json") == certificate[runner_key]
    assert prior["passed"] and prior["baseline"]
    assert current["passed"] and not current["baseline"]
    for key, certificate_key in (
        ("input_sha256", "binary_sha256"),
        ("source_script_sha256", "probe_sha256"),
        ("ida_sha256", "ida_sha256"),
    ):
        assert prior_run[key] == current_run[key] == certificate[certificate_key]
    assert prior_run["plugin_sha256"] == certificate["prior_plugin_sha256"]
    assert current_run["plugin_sha256"] == certificate["current_plugin_sha256"]
    for run in (prior_run, current_run):
        assert run["artifacts_unchanged"] and run["source_script_unchanged"]
    assert list(prior["cases"]) == list(current["cases"])
    assert list(current["cases"]) == list(certificate["expected_values"])
    prior_proofs = current_proofs = 0
    for name, values in certificate["expected_values"].items():
        before, after = prior["cases"][name], current["cases"][name]
        assert before["decoded"] == after["decoded"]
        assert len(after["decoded"]) == 1
        assert after["decoded"][0]["itype"] in (12, 13, 14, 15)
        assert not before["proofs"]
        assert [row["value"] for row in after["proofs"]] == values
        for row in after["proofs"]:
            assert row["truth"] == "native-proof" and row["fresh"] == "true"
        prior_proofs += len(before["proofs"])
        current_proofs += len(after["proofs"])
    assert prior_proofs == certificate["prior_proofs"] == 0
    assert current_proofs == certificate["current_proofs"] == 15


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--match-source", action="store_true")
    parser.add_argument("--prior-dir", type=Path)
    parser.add_argument("--current-dir", type=Path)
    args = parser.parse_args()
    certificate = read(args.certificate)
    assert certificate["schema"] == "chernobog.bit-test-garbage-evidence.v1"
    assert len(certificate["expected_values"]) == 19
    assert certificate["x86_execution_oracle"]["register_cases"] == 12288
    assert certificate["x86_execution_oracle"]["memory_cases"] == 6218
    if args.match_source:
        for name, expected in certificate["source_sha256"].items():
            assert sha256(ROOT / name) == expected, name
    assert (args.prior_dir is None) == (args.current_dir is None)
    if args.prior_dir is not None:
        verify_raw(certificate, args.prior_dir, args.current_dir)
    print("BT-family certificate PASS: 19 cases, 0 prior proofs, 15 current proofs")


if __name__ == "__main__":
    main()
