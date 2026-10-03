"""Recheck the committed Morok post-syscall capture without ignored build files."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import tempfile

import capstone

from verify_native_candidate_trace import elf64_load_segments
from verify_native_post_syscall import ROOT, check_case, check_regression, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    evidence = json.loads(args.evidence.read_text())
    raw = args.archive.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == evidence["archive_sha256"]
    payload = json.loads(gzip.decompress(raw))
    assert payload["schema"] == evidence["schema"] == 1
    assert evidence["passed"] and len(payload["captures"]) == len(evidence["cases"]) == 2
    assert b"/Users/" not in gzip.decompress(raw)
    for name, expected in evidence["sources_sha256"].items():
        assert sha(ROOT / name) == expected
    assert capstone.__version__ == evidence["capstone_version"]
    assert sha(Path(capstone.__file__)) == evidence["capstone_binding_sha256"]
    assert sha(Path(capstone._cs._name)) == evidence["capstone_library_sha256"]
    binary = bytes.fromhex(payload["binary_hex"])
    assert (
        hashlib.sha256(binary).hexdigest() == payload["binary_sha256"] == evidence["binary_sha256"]
    )
    segments = elf64_load_segments(binary)
    with tempfile.TemporaryDirectory(prefix="chernobog-post-syscall-") as directory:
        root = Path(directory)
        binary_path = root / "protected-keygen"
        binary_path.write_bytes(binary)
        cases = []
        for row in payload["captures"]:
            label = row["variant"]
            assert label in ("first", "second")
            output = root / label
            output.mkdir()
            paths = {}
            for kind in ("input", "branch", "owned", "post", "shadow", "ida"):
                path = output / (kind + (".bin" if kind == "shadow" else ".json"))
                path.write_bytes(bytes.fromhex(row[kind + "_hex"]))
                paths[kind] = path
            (output / "run.json").write_bytes(bytes.fromhex(row["run_hex"]))
            case, _ = check_case(
                binary_path,
                segments,
                label,
                *[paths[kind] for kind in ("input", "branch", "owned", "post", "shadow", "ida")]
            )
            cases.append(case)
        assert cases == evidence["cases"]
        regression_dir = root / "regression"
        regression_dir.mkdir()
        regression_path = regression_dir / "owned_call_probe.json"
        regression_path.write_bytes(bytes.fromhex(payload["regression"]["ida_hex"]))
        (regression_dir / "run.json").write_bytes(bytes.fromhex(payload["regression"]["run_hex"]))
        regression, _ = check_regression(
            regression_path, evidence["binary_sha256"], evidence["plugin_sha256"]
        )
        assert regression == evidence["regression"]
    assert sum(case["entered"] for case in cases) == evidence["totals"]["entered"]
    assert sum(case["exact_gprs"] for case in cases) == evidence["totals"]["exact_gprs"]
    assert sum(case["exact_rip"] for case in cases) == evidence["totals"]["exact_rip"]
    assert (
        sum(case["exact_defined_flag_bits"] for case in cases)
        == evidence["totals"]["exact_defined_flag_bits"]
    )
    assert sum(case["boundary_bytes"] for case in cases) == evidence["totals"]["boundary_bytes"]
    print("Morok post-syscall archive verification: pass")


if __name__ == "__main__":
    main()
