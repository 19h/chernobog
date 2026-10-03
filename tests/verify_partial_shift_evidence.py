#!/usr/bin/env python3
"""Verify a source-pinned partial-shift certificate and optional raw IDA pair."""

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
    prior = read(prior_dir / "partial-shift.json")
    current = read(current_dir / "partial-shift.json")
    prior_run = read(prior_dir / "run.json")
    current_run = read(current_dir / "run.json")
    for run_dir, report_key, runner_key in (
        (prior_dir, "prior_report_sha256", "prior_runner_sha256"),
        (current_dir, "current_report_sha256", "current_runner_sha256"),
    ):
        assert sha256(run_dir / "partial-shift.json") == certificate[report_key]
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
    assert list(current["cases"]) == list(certificate["expected_current_values"])
    assert list(prior["cases"]) == list(certificate["expected_prior_values"])
    before_count = after_count = 0
    for name in prior["cases"]:
        before, after = prior["cases"][name], current["cases"][name]
        assert before["decoded"] == after["decoded"]
        assert before["decoded"][0]["itype"] in (204, 227)
        assert any(row["itype"] in (163, 164, 165) for row in after["decoded"])
        if name == "shift_locked":
            assert any(row["itype"] == 165 and row["auxpref"] & 1 for row in after["decoded"])
        before_values = [row["value"] for row in before["proofs"]]
        after_values = [row["value"] for row in after["proofs"]]
        assert before_values == certificate["expected_prior_values"][name]
        assert after_values == certificate["expected_current_values"][name]
        for row in before["proofs"] + after["proofs"]:
            assert row["truth"] == "native-proof" and row["fresh"] == "true"
        before_count += len(before_values)
        after_count += len(after_values)
    assert before_count == certificate["prior_proofs"] == 1
    assert after_count == certificate["current_proofs"] == 7


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--match-source", action="store_true")
    parser.add_argument("--prior-dir", type=Path)
    parser.add_argument("--current-dir", type=Path)
    args = parser.parse_args()
    certificate = read(args.certificate)
    assert certificate["schema"] == "chernobog.partial-shift-evidence.v1"
    assert len(certificate["expected_current_values"]) == 11
    assert certificate["x86_execution_oracle"]["partial_shift_cases"] == 148104
    assert certificate["x86_execution_oracle"]["concrete_completion_cases"] == 14400
    if args.match_source:
        for name, expected in certificate["source_sha256"].items():
            assert sha256(ROOT / name) == expected, name
    assert (args.prior_dir is None) == (args.current_dir is None)
    if args.prior_dir is not None:
        verify_raw(certificate, args.prior_dir, args.current_dir)
    print("partial shift certificate PASS: 11 cases, 1 prior proof, 7 current proofs")


if __name__ == "__main__":
    main()
