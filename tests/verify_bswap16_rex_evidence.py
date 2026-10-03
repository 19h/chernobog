#!/usr/bin/env python3
"""Verify source-pinned paired IDA observations of four-byte BSWAP16."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES = ("rex_bswap_cf", "rex_bswap_zf", "rex_bswap_unknown")


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


def verify_fixture(prior, current):
    assert set(prior["cases"]) == set(current["cases"]) == set(CASES)
    verify_fixture_current(current)
    for name in CASES:
        before = prior["cases"][name]
        after = current["cases"][name]
        assert before["start"] == after["start"]
        assert before["use"] == after["use"]
        assert before["instructions"] == after["instructions"]
        assert before["prepared_inventory"] == after["prepared_inventory"]
        assert before["swap"] == after["swap"]
        assert before["swap"]["bytes"] == "66410fc9"
        assert int(before["use"], 16) == int(before["swap"]["site"], 16) + 4
        a, b = before["region"], after["region"]
        assert a["root"] == b["root"] == before["start"]
        assert a["published"] is b["published"] is False
        assert a["converged"] and b["converged"]
        assert not a["truncated"] and not b["truncated"]
        assert len(a["records"]) == 0 and len(b["records"]) == 1
        assert any(
            edge["kind"] == "frontier" and edge["reason"] == "unsupported_bswap_width"
            for edge in a["edges"]
        )
        assert any(
            node["site"] == after["swap"]["site"]
            and node["bytes"] == "66410fc9"
            and node["abstract_effect"] == "undefined-register-result"
            for node in b["nodes"]
        )
        assert any(
            edge["kind"] == "fallthrough"
            and edge["source"] == after["swap"]["site"]
            and edge["target"] == after["use"]
            for edge in b["edges"]
        )


def verify_fixture_current(current):
    assert current["passed"] and not current["errors"]
    assert set(current["cases"]) == set(CASES)
    for name in CASES:
        case = current["cases"][name]
        assert case["swap"]["bytes"] == "66410fc9"
        assert int(case["use"], 16) == int(case["swap"]["site"], 16) + 4
        region = case["region"]
        assert region["root"] == case["start"]
        assert region["converged"] and not region["truncated"]
        assert region["published"] is False
        assert len(region["nodes"]) == len(region["edges"]) == 6
        assert len(region["records"]) == 1
        assert any(
            node["site"] == case["swap"]["site"]
            and node["bytes"] == "66410fc9"
            and node["abstract_effect"] == "undefined-register-result"
            for node in region["nodes"]
        )
        assert any(
            edge["kind"] == "fallthrough"
            and edge["source"] == case["swap"]["site"]
            and edge["target"] == case["use"]
            for edge in region["edges"]
        )
        record = region["records"][0]
        assert record["kind"] == "setcc-value"
        if name == "rex_bswap_unknown":
            assert record["status"] == "unresolved"
            assert record["value"] == "unknown"
        else:
            assert record["status"] == "proved"
            assert record["value"] == "0x1"


def verify_protected(prior, current):
    a, b = prior["region"], current["region"]
    assert a["root"] == b["root"] == "0x10007012e"
    assert a["published"] is b["published"] is False
    assert a["converged"] and b["converged"]
    assert not a["truncated"] and not b["truncated"]
    assert len(a["nodes"]) == len(a["edges"]) == 1
    assert a["records"] == []
    assert a["edges"][0]["reason"] == "unsupported_bswap_width"
    verify_protected_current(current)


def verify_protected_current(current):
    assert current["passed"] and not current["errors"]
    b = current["region"]
    assert b["root"] == "0x10007012e"
    assert b["published"] is False
    assert b["converged"] and not b["truncated"]
    assert len(b["nodes"]) == len(b["edges"]) == 104
    assert len(b["records"]) == 5
    assert all(record["status"] == "unresolved" for record in b["records"])
    assert any(
        node["site"] == b["root"]
        and node["bytes"] == "66410fc9"
        and node["abstract_effect"] == "undefined-register-result"
        for node in b["nodes"]
    )
    assert any(
        edge["kind"] == "fallthrough"
        and edge["source"] == b["root"]
        and edge["target"] == "0x100070132"
        for edge in b["edges"]
    )


def verify_owned_current(current):
    assert current["passed"] and not current["errors"]
    assert current["site"] == "0x10007012e"
    assert current["owner"] == "0x10007012c"
    assert current["bytes"] == "66410fc9"
    assert current["inventory_before"] == current["inventory_after"]
    assert current["inventory_before"]["heads"] == 25
    diagnostics = current["diagnostics"]
    assert diagnostics["available"] and not diagnostics["truncated"]
    assert diagnostics["function"] == current["owner"]
    assert diagnostics["heads_examined"] == 105
    assert diagnostics["condition_sites"] == 4
    assert len(diagnostics["records"]) == 4
    assert all(record["status"] == "unresolved" for record in diagnostics["records"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--match-source", action="store_true")
    parser.add_argument("--fixture-prior-dir", type=Path)
    parser.add_argument("--fixture-current-dir", type=Path)
    parser.add_argument("--protected-prior-dir", type=Path)
    parser.add_argument("--protected-current-dir", type=Path)
    parser.add_argument("--current-only-fixture-dir", type=Path)
    parser.add_argument("--current-only-protected-dir", type=Path)
    parser.add_argument("--current-only-owned-dir", type=Path)
    args = parser.parse_args()
    certificate = read(args.certificate)
    assert certificate["schema"] == "chernobog.bswap16-rex-evidence.v1"
    if args.match_source:
        for name, expected in certificate["source_sha256"].items():
            assert sha256(ROOT / name) == expected, name
    directories = (
        args.fixture_prior_dir,
        args.fixture_current_dir,
        args.protected_prior_dir,
        args.protected_current_dir,
    )
    assert all(directory is None for directory in directories) or all(
        directory is not None for directory in directories
    )
    checks = []
    if directories[0] is not None:
        verify_fixture(
            *verify_pair(
                certificate,
                "fixture",
                directories[0],
                directories[1],
                "bswap16_rex_fixture.json",
            )
        )
        verify_protected(
            *verify_pair(
                certificate,
                "protected_region",
                directories[2],
                directories[3],
                "bswap16_rex_region.json",
            )
        )
        checks.append("paired fixture/protected raw reports")
    if args.current_only_fixture_dir is not None:
        verify_fixture_current(read(args.current_only_fixture_dir / "bswap16_rex_fixture.json"))
        checks.append("current fixture semantics")
    if args.current_only_protected_dir is not None:
        verify_protected_current(read(args.current_only_protected_dir / "bswap16_rex_region.json"))
        checks.append("current protected topology and abstentions")
    if args.current_only_owned_dir is not None:
        verify_owned_current(read(args.current_only_owned_dir / "bswap16_rex.json"))
        checks.append("current owned diagnostic and abstentions")
    if args.match_source:
        checks.append("source hashes")
    print("BSWAP16 REX evidence PASS: " + (", ".join(checks) or "certificate schema"))


if __name__ == "__main__":
    main()
