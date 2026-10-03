#!/usr/bin/env python3
"""Verify paired read-only near-indirect jump facts and protected abstention."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES = ("known_jump", "unknown_jump", "memory_jump")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def verify_pair(certificate, section, prior_dir, current_dir, report_name):
    expected = certificate[section]
    prior = read(prior_dir / report_name)
    current = read(current_dir / report_name)
    runs = [read(prior_dir / "run.json"), read(current_dir / "run.json")]
    for label, directory, report, run in zip(
        ("prior", "current"), (prior_dir, current_dir), (prior, current), runs
    ):
        assert sha256(directory / report_name) == expected[label + "_report_sha256"]
        assert sha256(directory / "run.json") == expected[label + "_run_sha256"]
        assert run["input_sha256"] == expected["binary_sha256"]
        assert run["source_script_sha256"] == expected["probe_sha256"]
        assert run["ida_sha256"] == certificate["ida_sha256"]
        assert run["plugin_sha256"] == certificate[label + "_plugin_sha256"]
        assert run["artifacts_unchanged"] and run["source_script_unchanged"]
        assert report["passed"] and not report["errors"]
    assert runs[0]["chernobog_environment_sha256"] == runs[1]["chernobog_environment_sha256"]
    return prior, current


def indirect_record(region, site):
    rows = [row for row in region["records"] if row["kind"] == "indirect-jump-target"]
    assert len(rows) == 1
    assert rows[0]["site"] == site
    assert rows[0]["publication"] == "none"
    assert rows[0]["source_kind"] == "register"
    assert rows[0]["admission"] == "exact-register-encoding"
    return rows[0]


def verify_fixture_current(report):
    assert report["passed"] and not report["errors"]
    assert set(report["cases"]) == set(CASES)
    for name in CASES:
        case = report["cases"][name]
        region = case["region"]
        assert region["address_bits"] in (32, 64)
        assert region["root"] == case["start"]
        assert region["available"] and region["converged"] and not region["truncated"]
        assert region["published"] is False
        expected_bytes = (
            "ffe7" if region["address_bits"] == 32 or name == "unknown_jump" else "41ffe2"
        )
        assert case["site_bytes"] == expected_bytes
        assert len(region["nodes"]) == len(region["edges"]) == (1 if name == "unknown_jump" else 2)
        assert len(region["records"]) == 1
        assert any(
            edge["kind"] == "frontier"
            and edge["reason"] == "indirect_target"
            and edge["source"] == case["site"]
            for edge in region["edges"]
        )
        row = indirect_record(region, case["site"])
        if name == "known_jump":
            assert row["status"] == "proved"
            assert row["target"] == report["target_seven"]
            assert row["target_proof"] == "register-definition"
        else:
            assert row["status"] == "unresolved"
            assert row["target"] == "unknown"
            assert row["target_proof"] == "unresolved"
    site_case = report["cases"]["known_jump"]
    site_entry = site_case["site_entry_region"]
    assert site_entry["root"] == site_case["site"]
    assert site_entry["available"] and site_entry["converged"]
    assert site_entry["published"] is False and not site_entry["truncated"]
    assert len(site_entry["nodes"]) == len(site_entry["edges"]) == 1
    row = indirect_record(site_entry, site_case["site"])
    assert row["status"] == "unresolved" and row["target"] == "unknown"


def verify_fixture_pair(prior, current):
    verify_fixture_current(current)
    assert prior["target_seven"] == current["target_seven"]
    assert prior["target_eight"] == current["target_eight"]
    assert prior["mutable_pointer"] == current["mutable_pointer"]
    assert set(prior["cases"]) == set(current["cases"]) == set(CASES)
    for name in CASES:
        before = prior["cases"][name]
        after = current["cases"][name]
        for field in ("start", "end", "site", "site_bytes", "before_owner", "prepared_inventory"):
            assert before[field] == after[field]
        a, b = before["region"], after["region"]
        assert a["root"] == b["root"]
        assert a["published"] is b["published"] is False
        assert a["converged"] and b["converged"]
        assert not a["truncated"] and not b["truncated"]
        assert a["records"] == []
        assert len(a["nodes"]) == len(b["nodes"])
        assert len(a["edges"]) == len(b["edges"])
        assert any(
            edge["kind"] == "frontier"
            and edge["reason"] == "unsupported_control"
            and edge["source"] == before["site"]
            for edge in a["edges"]
        )
    assert prior["cases"]["known_jump"]["site_entry_region"]["records"] == []


def verify_protected_current(report):
    assert report["passed"] and not report["errors"]
    assert report["inventory_before"] == report["inventory_after"]
    region = report["region"]
    assert region["root"] == "0x1002946b5"
    assert region["available"] and region["converged"] and not region["truncated"]
    assert region["published"] is False
    assert len(region["nodes"]) == 75 and len(region["edges"]) == 77
    assert len(region["records"]) == 4
    assert all(row["status"] == "unresolved" for row in region["records"])
    jump = indirect_record(region, "0x10024801a")
    assert jump["target"] == "unknown" and jump["target_proof"] == "unresolved"
    assert any(
        edge["kind"] == "frontier"
        and edge["reason"] == "indirect_target"
        and edge["source"] == "0x10024801a"
        for edge in region["edges"]
    )


def verify_protected_pair(prior, current):
    verify_protected_current(current)
    assert prior["inventory_before"] == prior["inventory_after"]
    assert prior["inventory_before"] == current["inventory_before"]
    a, b = prior["region"], current["region"]
    assert a["root"] == b["root"]
    assert len(a["nodes"]) == len(b["nodes"]) == 75
    assert len(a["edges"]) == len(b["edges"]) == 77
    assert len(a["records"]) == 3
    assert all(row["status"] == "unresolved" for row in a["records"])
    assert a["records"] == [row for row in b["records"] if row["kind"] != "indirect-jump-target"]
    assert any(
        edge["kind"] == "frontier"
        and edge["reason"] == "unsupported_control"
        and edge["source"] == "0x10024801a"
        for edge in a["edges"]
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--match-source", action="store_true")
    parser.add_argument("--fixture-prior-dir", type=Path)
    parser.add_argument("--fixture-current-dir", type=Path)
    parser.add_argument("--fixture32-prior-dir", type=Path)
    parser.add_argument("--fixture32-current-dir", type=Path)
    parser.add_argument("--protected-prior-dir", type=Path)
    parser.add_argument("--protected-current-dir", type=Path)
    parser.add_argument("--current-only-fixture-dir", type=Path)
    parser.add_argument("--current-only-protected-dir", type=Path)
    args = parser.parse_args()
    certificate = read(args.certificate)
    assert certificate["schema"] == "chernobog.indirect-jump-region-evidence.v1"
    checks = []
    if args.match_source:
        for name, expected in certificate["source_sha256"].items():
            assert sha256(ROOT / name) == expected, name
        checks.append("source hashes")
    directories = (
        args.fixture_prior_dir,
        args.fixture_current_dir,
        args.protected_prior_dir,
        args.protected_current_dir,
    )
    assert all(path is None for path in directories) or all(
        path is not None for path in directories
    )
    if directories[0] is not None:
        verify_fixture_pair(
            *verify_pair(
                certificate, "fixture", directories[0], directories[1], "indirect_jump_region.json"
            )
        )
        verify_protected_pair(
            *verify_pair(
                certificate,
                "protected",
                directories[2],
                directories[3],
                "indirect_jump_protected.json",
            )
        )
        checks.append("paired fixture/protected raw reports")
    assert (args.fixture32_prior_dir is None) == (args.fixture32_current_dir is None)
    if args.fixture32_prior_dir is not None:
        verify_fixture_pair(
            *verify_pair(
                certificate,
                "fixture32",
                args.fixture32_prior_dir,
                args.fixture32_current_dir,
                "indirect_jump_region.json",
            )
        )
        checks.append("paired i386 fixture raw reports")
    if args.current_only_fixture_dir is not None:
        verify_fixture_current(read(args.current_only_fixture_dir / "indirect_jump_region.json"))
        checks.append("current fixture semantics")
    if args.current_only_protected_dir is not None:
        verify_protected_current(
            read(args.current_only_protected_dir / "indirect_jump_protected.json")
        )
        checks.append("current protected abstention")
    print("indirect jump region evidence PASS: " + (", ".join(checks) or "certificate schema"))


if __name__ == "__main__":
    main()
