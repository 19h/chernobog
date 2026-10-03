#!/usr/bin/env python3
"""Verify source-pinned paired REX-prefixed indirect-jump region facts."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = {
    "rexw_rax": ("48ffe0", "target_seven"),
    "rexw_r8": ("49ffe0", "target_eight"),
    "rexw_rx_r8": ("4fffe0", "target_seven"),
    "dynamic_rexw": ("48ffe7", None),
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def record(region, site):
    rows = [row for row in region["records"] if row["kind"] == "indirect-jump-target"]
    assert len(rows) == 1 and rows[0]["site"] == site
    assert rows[0]["publication"] == "none"
    assert rows[0]["source_kind"] == "register"
    return rows[0]


def verify_current(report):
    assert report["passed"] and not report["errors"]
    assert len(report["checks"]) == 19
    assert all(check["passed"] for check in report["checks"])
    assert set(report["cases"]) == set(EXPECTED)
    for name, (encoding, target_name) in EXPECTED.items():
        case = report["cases"][name]
        region = case["region"]
        assert case["site_bytes"] == encoding
        assert region["available"] and region["converged"] and not region["truncated"]
        assert region["root"] == case["start"] and region["address_bits"] == 64
        assert region["published"] is False
        assert len(region["nodes"]) == len(region["edges"]) == (1 if target_name is None else 2)
        assert len(region["records"]) == 1
        assert all(edge["kind"] != "direct-jump" for edge in region["edges"])
        assert any(
            edge["kind"] == "frontier"
            and edge["reason"] == "indirect_target"
            and edge["source"] == case["site"]
            for edge in region["edges"]
        )
        row = record(region, case["site"])
        assert row["admission"] == "exact-register-encoding"
        if target_name is None:
            assert row["status"] == "unresolved" and row["target"] == "unknown"
        else:
            assert row["status"] == "proved"
            assert row["target"] == report[target_name]
            assert row["target_proof"] == "register-definition"
        direct = case["direct_entry"]
        assert direct["available"] and direct["converged"] and not direct["truncated"]
        assert direct["published"] is False and direct["root"] == case["site"]
        assert len(direct["nodes"]) == len(direct["edges"]) == 1
        direct_row = record(direct, case["site"])
        assert direct_row["admission"] == "exact-register-encoding"
        assert direct_row["status"] == "unresolved" and direct_row["target"] == "unknown"


def verify_pair(prior, current):
    verify_current(current)
    assert prior["passed"] and not prior["errors"]
    assert prior["target_seven"] == current["target_seven"]
    assert prior["target_eight"] == current["target_eight"]
    assert set(prior["cases"]) == set(current["cases"]) == set(EXPECTED)
    for name in EXPECTED:
        before, after = prior["cases"][name], current["cases"][name]
        for field in ("start", "site", "site_bytes", "inventory"):
            assert before[field] == after[field]
        a, b = before["region"], after["region"]
        assert a["root"] == b["root"]
        assert a["nodes"] == b["nodes"] and a["edges"] == b["edges"]
        assert a["published"] is b["published"] is False
        old = record(a, before["site"])
        new = record(b, after["site"])
        assert old["admission"] == "unresolved-encoding"
        assert old["status"] == "unresolved" and old["target"] == "unknown"
        assert new["admission"] == "exact-register-encoding"
        old_direct = record(before["direct_entry"], before["site"])
        assert old_direct["status"] == "unresolved"
        assert old_direct["target"] == "unknown"


def verify_raw_pair(certificate, prior_dir, current_dir):
    pairs = []
    for label, directory in (("prior", prior_dir), ("current", current_dir)):
        report_path = directory / "indirect_jump_rexw.json"
        run_path = directory / "run.json"
        assert sha256(report_path) == certificate[label + "_report_sha256"]
        assert sha256(run_path) == certificate[label + "_run_sha256"]
        report, run = read(report_path), read(run_path)
        assert run["input_sha256"] == certificate["binary_sha256"]
        assert run["source_script_sha256"] == certificate["probe_sha256"]
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
    parser.add_argument("--prior-dir", type=Path)
    parser.add_argument("--current-dir", type=Path)
    parser.add_argument("--current-only-dir", type=Path)
    args = parser.parse_args()
    certificate = read(args.certificate)
    assert certificate["schema"] == "chernobog.indirect-jump-rexw-evidence.v1"
    checks = []
    if args.match_source:
        for name, expected in certificate["source_sha256"].items():
            assert sha256(ROOT / name) == expected, name
        checks.append("source hashes")
    assert (args.prior_dir is None) == (args.current_dir is None)
    if args.prior_dir is not None:
        verify_raw_pair(certificate, args.prior_dir, args.current_dir)
        checks.append("paired raw reports")
    if args.current_only_dir is not None:
        verify_current(read(args.current_only_dir / "indirect_jump_rexw.json"))
        checks.append("current semantics")
    print("indirect jump REX.W evidence PASS: " + (", ".join(checks) or "schema"))


if __name__ == "__main__":
    main()
