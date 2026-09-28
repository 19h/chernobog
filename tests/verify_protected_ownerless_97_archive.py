#!/usr/bin/env python3
"""Verify the pinned protected 97-head capture without IDA or its input binary."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    evidence = json.loads(args.evidence.read_text())
    compressed = args.archive.read_bytes()
    assert digest(compressed) == evidence["archive_sha256"]
    archive = json.loads(gzip.decompress(compressed))
    assert archive["schema"] == 1
    assert set(archive["files"]) == {
        "run.json",
        "protected_region.json",
        "independent_verify.json",
        "reference_75_run.json",
        "reference_75_protected_region.json",
    }
    for name, contents in archive["files"].items():
        assert "/Users/" not in contents and "/Applications/" not in contents
        assert digest(contents.encode()) == evidence["artifact_sha256"][name]
    run = json.loads(archive["files"]["run.json"])
    capture = json.loads(archive["files"]["protected_region.json"])
    verified = json.loads(archive["files"]["independent_verify.json"])
    reference_run = json.loads(archive["files"]["reference_75_run.json"])
    reference = json.loads(archive["files"]["reference_75_protected_region.json"])
    assert run["runner_return_code"] == run["process_return_code"] == 0
    assert run["artifacts_unchanged"] and run["source_script_unchanged"]
    assert run["input_sha256"] == evidence["input_sha256"]
    assert run["plugin_sha256"] == evidence["plugin_sha256"]
    assert run["ida_sha256"] == evidence["ida_sha256"]
    assert (
        run["source_script_sha256"]
        == evidence["source_sha256"]["tests/ida_protected_region_inspect.py"]
    )
    assert not capture["errors"] and all(row["passed"] for row in capture["checks"])
    assert capture["inventory_before"] == capture["inventory_after"]
    assert verified["passed"] and not verified["errors"]
    assert verified["input_sha256"] == evidence["input_sha256"]
    assert verified["inspection_sha256"] == evidence["artifact_sha256"]["protected_region.json"]
    assert verified["run_sha256"] == evidence["artifact_sha256"]["run.json"]
    assert (
        verified["verifier_sha256"]
        == evidence["source_sha256"]["tests/verify_protected_ownerless_97.py"]
    )
    assert (
        verified["decoder_sha256"]
        == evidence["source_sha256"]["tests/verify_vm_native_region_decode.py"]
    )
    assert verified["node_count"] == 97 and verified["direct_edge_count"] == 97
    assert verified["proved_condition_sites"] == 0 and verified["read_only_inventory"]
    assert reference_run["runner_return_code"] == 0 and reference_run["artifacts_unchanged"]
    assert reference_run["input_sha256"] == evidence["reference_input_sha256"]
    assert reference_run["plugin_sha256"] == evidence["plugin_sha256"]
    assert (
        reference_run["source_script_sha256"]
        == evidence["source_sha256"]["tests/ida_protected_region_inspect.py"]
    )
    assert reference["root"] == 0x1002946B5 and not reference["errors"]
    assert all(row["passed"] for row in reference["checks"])
    assert reference["inventory_before"] == reference["inventory_after"]
    assert len(reference["inspection"]["nodes"]) == 75
    assert len(reference["inspection"]["edges"]) == 77
    print("[chernobog][ownerless-97-archive] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
