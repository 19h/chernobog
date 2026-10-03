#!/usr/bin/env python3
"""Verify source-pinned partial BSWAP evidence and the optional raw IDA pair."""

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
    prior = read(prior_dir / "partial-bswap.json")
    current = read(current_dir / "partial-bswap.json")
    prior_run = read(prior_dir / "run.json")
    current_run = read(current_dir / "run.json")
    for run_dir, report_key, runner_key in (
        (prior_dir, "prior_report_sha256", "prior_runner_sha256"),
        (current_dir, "current_report_sha256", "current_runner_sha256"),
    ):
        assert sha256(run_dir / "partial-bswap.json") == certificate[report_key]
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
    assert list(prior["cases"]) == list(certificate["expected_prior_values"])
    assert list(current["cases"]) == list(certificate["expected_current_values"])
    prior_count = current_count = 0
    for name in prior["cases"]:
        before, after = prior["cases"][name], current["cases"][name]
        assert before["decoded"] == after["decoded"]
        swaps = [row for row in after["decoded"] if row["itype"] == 218]
        assert len(swaps) == 1
        if name == "bswap_locked":
            assert swaps[0]["auxpref"] & 1 and swaps[0]["size"] == 3
        else:
            assert not swaps[0]["auxpref"] & 1
        before_values = [row["value"] for row in before["proofs"]]
        after_values = [row["value"] for row in after["proofs"]]
        assert before_values == certificate["expected_prior_values"][name]
        assert after_values == certificate["expected_current_values"][name]
        for row in before["proofs"] + after["proofs"]:
            assert row["truth"] == "native-proof" and row["fresh"] == "true"
        prior_count += len(before_values)
        current_count += len(after_values)
    assert prior_count == certificate["prior_proofs"] == 3
    assert current_count == certificate["current_proofs"] == 5


def verify_raw32(certificate, prior_dir, current_dir):
    selected = certificate["i386"]
    prior = read(prior_dir / "partial-bswap32.json")
    current = read(current_dir / "partial-bswap32.json")
    prior_run = read(prior_dir / "run.json")
    current_run = read(current_dir / "run.json")
    for run_dir, report_key, runner_key in (
        (prior_dir, "prior_report_sha256", "prior_runner_sha256"),
        (current_dir, "current_report_sha256", "current_runner_sha256"),
    ):
        assert sha256(run_dir / "partial-bswap32.json") == selected[report_key]
        assert sha256(run_dir / "run.json") == selected[runner_key]
    assert prior["passed"] and prior["baseline"]
    assert current["passed"] and not current["baseline"]
    for key, expected in (
        ("input_sha256", selected["binary_sha256"]),
        ("source_script_sha256", selected["probe_sha256"]),
        ("ida_sha256", certificate["ida_sha256"]),
    ):
        assert prior_run[key] == current_run[key] == expected
    assert prior_run["plugin_sha256"] == selected["prior_plugin_sha256"]
    assert current_run["plugin_sha256"] == selected["current_plugin_sha256"]
    for run in (prior_run, current_run):
        assert run["artifacts_unchanged"] and run["source_script_unchanged"]
    assert list(prior["cases"]) == list(current["cases"])
    assert list(prior["cases"]) == list(selected["expected_prior_values"])
    assert list(current["cases"]) == list(selected["expected_current_values"])
    prior_count = current_count = 0
    for name in prior["cases"]:
        before, after = prior["cases"][name], current["cases"][name]
        assert before["decoded"] == after["decoded"]
        assert len([row for row in after["decoded"] if row["itype"] == 218]) == 1
        before_values = [row["value"] for row in before["proofs"]]
        after_values = [row["value"] for row in after["proofs"]]
        assert before_values == selected["expected_prior_values"][name]
        assert after_values == selected["expected_current_values"][name]
        for row in before["proofs"] + after["proofs"]:
            assert row["truth"] == "native-proof" and row["fresh"] == "true"
        prior_count += len(before_values)
        current_count += len(after_values)
    assert prior_count == selected["prior_proofs"] == 1
    assert current_count == selected["current_proofs"] == 3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--match-source", action="store_true")
    parser.add_argument("--prior-dir", type=Path)
    parser.add_argument("--current-dir", type=Path)
    parser.add_argument("--prior32-dir", type=Path)
    parser.add_argument("--current32-dir", type=Path)
    args = parser.parse_args()
    certificate = read(args.certificate)
    assert certificate["schema"] == "chernobog.partial-bswap-evidence.v1"
    assert len(certificate["expected_current_values"]) == 8
    assert certificate["x86_execution_oracle"]["portable_patterns"] == 48
    assert certificate["x86_execution_oracle"]["native_completions"] == 320
    assert len(certificate["i386"]["expected_current_values"]) == 4
    if args.match_source:
        for name, expected in certificate["source_sha256"].items():
            assert sha256(ROOT / name) == expected, name
    assert (args.prior_dir is None) == (args.current_dir is None)
    if args.prior_dir is not None:
        verify_raw(certificate, args.prior_dir, args.current_dir)
    assert (args.prior32_dir is None) == (args.current32_dir is None)
    if args.prior32_dir is not None:
        verify_raw32(certificate, args.prior32_dir, args.current32_dir)
    print("partial BSWAP certificate PASS: x64 8/3/5, i386 4/1/3 cases/prior/current proofs")


if __name__ == "__main__":
    main()
