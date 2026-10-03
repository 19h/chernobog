#!/usr/bin/env python3
"""Verify the scoped IDA code-head indirect-jump census of supplied x86 binaries."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KINDS = (
    "register",
    "rex-register",
    "stack-top",
    "rex-stack-top",
    "direct-memory",
    "other",
)
SECTIONS = ("foo_original", "foo_vmp", "morok_boo", "morok_keygen")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def classify(data):
    size = len(data)
    if size == 2 and data[0] == 0xFF and 0xE0 <= data[1] <= 0xE7:
        return "register"
    if size == 3 and 0x40 <= data[0] <= 0x4F and data[1] == 0xFF and 0xE0 <= data[2] <= 0xE7:
        return "rex-register"
    if data == bytes.fromhex("ff2424"):
        return "stack-top"
    if (
        size == 4
        and 0x40 <= data[0] <= 0x4F
        and (data[0] & 3) == 0
        and data[1:] == bytes.fromhex("ff2424")
    ):
        return "rex-stack-top"
    if size == 6 and data[:2] == bytes.fromhex("ff25"):
        return "direct-memory"
    return "other"


def segment(report, name):
    rows = [row for row in report["segments"] if row["name"] == name]
    assert len(rows) == 1
    return rows[0]


def verify_report(report, expected, section):
    assert report["schema"] == 1 and report["passed"] and not report["errors"]
    assert report["processor"] == "metapc" and report["address_bits"] == 64
    assert report["plugin_loaded"] is True
    assert len(report["checks"]) == 3 and all(check["passed"] for check in report["checks"])
    assert report["code_heads"] == expected["code_heads"]
    assert report["indirect_jumps"] == expected["indirect_jumps"]
    assert report["totals"] == expected["counts"]
    assert set(report["totals"]) == set(KINDS)
    assert sum(report["totals"].values()) == report["indirect_jumps"]
    assert sum(row["code_heads"] for row in report["segments"]) == report["code_heads"]
    assert sum(row["indirect_jumps"] for row in report["segments"]) == report["indirect_jumps"]
    for row in report["segments"]:
        assert set(row["counts"]) == set(row["examples"]) == set(KINDS)
        assert sum(row["counts"].values()) == row["indirect_jumps"]
        start, end = int(row["start"], 16), int(row["end"], 16)
        assert start < end and row["code_heads"] >= row["indirect_jumps"]
        for kind in KINDS:
            examples = row["examples"][kind]
            assert len(examples) == min(row["counts"][kind], 16)
            for example in examples:
                site = int(example["site"], 16)
                assert start <= site < end
                assert classify(bytes.fromhex(example["bytes"])) == kind
    if section == "foo_original":
        assert segment(report, "__stubs")["counts"]["direct-memory"] == 1
        assert segment(report, "__text")["indirect_jumps"] == 0
    elif section == "foo_vmp":
        assert segment(report, "__text")["code_heads"] == 0
        hidden = segment(report, ".dlC1_hidden")
        assert hidden["counts"]["register"] == hidden["counts"]["rex-register"] == 1
        assert hidden["examples"]["rex-register"][0]["site"] == "0x10024801a"
    elif section == "morok_boo":
        assert segment(report, ".morok_npack_rx")["indirect_jumps"] == 0
        assert segment(report, ".text")["indirect_jumps"] == 13
    else:
        assert section == "morok_keygen"
        assert segment(report, ".hdmoh1mxteam2f")["code_heads"] == 0
        assert segment(report, ".text")["indirect_jumps"] == 17


def verify_raw(certificate, section, directory):
    expected = certificate["cases"][section]
    report_path = directory / "protected_indirect_census.json"
    run_path = directory / "run.json"
    assert sha256(report_path) == expected["report_sha256"]
    assert sha256(run_path) == expected["run_sha256"]
    report, run = read(report_path), read(run_path)
    assert run["input_sha256"] == expected["input_sha256"]
    assert (
        run["source_script_sha256"]
        == certificate["source_sha256"]["tests/ida_protected_indirect_census.py"]
    )
    assert run["plugin_sha256"] == certificate["plugin_sha256"]
    assert run["ida_sha256"] == certificate["ida_sha256"]
    assert run["chernobog_environment_sha256"] == certificate["environment_sha256"]
    assert run["artifacts_unchanged"] and run["source_script_unchanged"]
    assert run["runner_return_code"] == run["process_return_code"] == 0
    verify_report(report, expected, section)


def verify_current_only(certificate, section, directory):
    expected = certificate["cases"][section]
    report = read(directory / "protected_indirect_census.json")
    run = read(directory / "run.json")
    assert run["input_sha256"] == expected["input_sha256"]
    assert (
        run["source_script_sha256"]
        == certificate["source_sha256"]["tests/ida_protected_indirect_census.py"]
    )
    assert run["ida_sha256"] == certificate["ida_sha256"]
    assert run["artifacts_unchanged"] and run["source_script_unchanged"]
    assert run["runner_return_code"] == run["process_return_code"] == 0
    verify_report(report, expected, section)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--match-source", action="store_true")
    for section in SECTIONS:
        parser.add_argument("--" + section.replace("_", "-") + "-dir", type=Path)
    parser.add_argument("--current-only-case", choices=SECTIONS)
    parser.add_argument("--current-only-dir", type=Path)
    args = parser.parse_args()
    certificate = read(args.certificate)
    assert certificate["schema"] == "chernobog.protected-indirect-census-evidence.v1"
    assert set(certificate["cases"]) == set(SECTIONS)
    checks = []
    if args.match_source:
        for name, expected in certificate["source_sha256"].items():
            assert sha256(ROOT / name) == expected, name
        checks.append("source hashes")
    directories = [getattr(args, section + "_dir") for section in SECTIONS]
    assert all(directory is None for directory in directories) or all(
        directory is not None for directory in directories
    )
    if directories[0] is not None:
        for section, directory in zip(SECTIONS, directories):
            verify_raw(certificate, section, directory)
            checks.append(section)
    assert (args.current_only_case is None) == (args.current_only_dir is None)
    if args.current_only_case is not None:
        verify_current_only(certificate, args.current_only_case, args.current_only_dir)
        checks.append("current " + args.current_only_case)
    print("protected indirect census PASS: " + (", ".join(checks) or "schema"))


if __name__ == "__main__":
    main()
