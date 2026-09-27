"""Package exact source versions, paired binaries and undefined-result captures."""

import base64
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    root = Path(__file__).resolve().parent.parent
    files, binaries = {}, {}

    def add(name, data=None):
        data = (root / name).read_bytes() if data is None else data
        text = data.decode("utf-8")
        assert not re.search(r"/Users/[A-Za-z0-9_.-]+/", text), name
        files[name] = {"sha256": sha(data), "text": text}

    report_names = [
        "build/region-temporal-db33-fresh-v1/region_temporal_analysis.json",
        "build/undefined-final-trace/region_temporal_analysis.json",
        "build/undefined-final-strings/region_strings_analysis.json",
    ]
    reports = [json.loads((root / name).read_text()) for name in report_names]
    assert all(report["passed"] for report in reports)
    for name, report in zip(report_names, reports):
        add(name)
        for run in report["runs"]:
            for artifact, expected in run["artifact_sha256"].items():
                artifact_name = str(Path(name).parent / run["label"] / artifact)
                add(artifact_name)
                assert files[artifact_name]["sha256"] == expected
        for source, expected in report["source_sha256"].items():
            current = (root / source).read_bytes()
            if sha(current) == expected:
                add(source, current)
                continue
            frozen = root / "build/undefined-source-v4" / source
            previous = frozen.read_bytes() if frozen.is_file() else b""
            if sha(previous) != expected:
                previous = subprocess.check_output(
                    ["git", "show", "db33e00fcdd2:" + source], cwd=root
                )
            assert sha(previous) == expected, source
            add("revisions/" + expected[:12] + "/" + source, previous)
    source_names = [
        "src/vm/native_undefined.hpp",
        "src/vm/ida_native_trace.cpp",
        "src/hybrid/emu_driver.cpp",
        "src/hybrid/emu_driver.hpp",
        "tests/hybrid_tests.cpp",
        "tests/ida_region_temporal_probe.py",
        "tests/ida_region_strings_probe.py",
        "tests/run_vmp_region_temporal.py",
        "tests/verify_native_undefined_slices.py",
        "tests/package_native_undefined_evidence.py",
        "tests/verify_vm_native_region_decode.py",
        "tests/vmp_native/native_read_strings.S",
        "tests/run_vmp_strings.py",
        "docs/VMP_UNDEFINED_RESULTS.md",
    ]
    for name in source_names:
        add(name)
    for name in [
        "build/protected-strings-db33-v1/strings.json",
        "build/undefined-final-audit.json",
        "build/undefined-final-component.txt",
        "build/undefined-feature-ctest.txt",
    ]:
        add(name)
    corpus = json.loads(files["build/protected-strings-db33-v1/strings.json"]["text"])
    labels = {
        "original": corpus["original_sha256"],
        **{r["label"]: r["sha256"] for r in corpus["protection"]},
    }
    for label, expected in labels.items():
        name = "build/protected-strings-db33-v1/" + label
        data = (root / name).read_bytes()
        assert sha(data) == expected
        binaries[name] = {"sha256": expected, "base64": base64.b64encode(data).decode("ascii")}
    for record in corpus["negative_oracles"]:
        found = [
            p
            for p in (root / "build/protected-strings-db33-v1").iterdir()
            if p.is_file() and sha(p.read_bytes()) == record["sha256"]
        ]
        assert len(found) == 1
        name = str(found[0].relative_to(root))
        binaries[name] = {
            "sha256": record["sha256"],
            "base64": base64.b64encode(found[0].read_bytes()).decode("ascii"),
        }
    for name, path in [
        ("dependencies/ida-sdk/intel.hpp", root / "../ida-sdk/src/include/intel.hpp"),
        ("dependencies/rax/rax.h", root / "vendor/rax/capi/include/rax.h"),
    ]:
        add(name, path.read_bytes())
    archive = {"schema": 1, "files": files, "binary_files": binaries}
    canonical = (json.dumps(archive, sort_keys=True, separators=(",", ":")) + "\n").encode()
    compressed = gzip.compress(canonical, mtime=0)
    archive_name = "docs/VMP_UNDEFINED_RESULTS_CAPTURE.json.gz"
    (root / archive_name).write_bytes(compressed)
    audit = json.loads(files["build/undefined-final-audit.json"]["text"])
    evidence = {
        "schema": 1,
        "passed": True,
        "baseline_revision": "db33e00fcdd2c26e5e8e364345b46e2eeedeb0b1",
        "scope": "paired native-region observations under explicit ABI models and closed undefined-result dependence slices",
        "archive": {
            "path": archive_name,
            "sha256": sha(compressed),
            "canonical_sha256": sha(canonical),
            "compressed_bytes": len(compressed),
            "canonical_bytes": len(canonical),
            "text_files": len(files),
            "binary_files": len(binaries),
        },
        "sources": {name: sha((root / name).read_bytes()) for name in source_names},
        "reports": {name: sha((root / name).read_bytes()) for name in report_names},
        "corpus_report_sha256": sha(
            (root / "build/protected-strings-db33-v1/strings.json").read_bytes()
        ),
        "plugin_sha256": reports[1]["plugin_sha256"],
        "ida_sha256": reports[1]["ida_sha256"],
        "independent_audit": audit,
        "trace_checks": sum(r["checks"] for r in reports[1]["runs"]),
        "string_checks": sum(r["checks"] for r in reports[2]["runs"]),
        "baseline_completed_runs": sum(r["completed"] for r in reports[0]["runs"]),
        "candidate_completed_runs": sum(r["completed"] for r in reports[1]["runs"]),
        "completed_protected_value_instances": 6,
        "expected_protected_value_instances": 18,
        "assumptions": ["U1", "U2", "U3", "U4", "U5"],
        "review_complete": False,
    }
    (root / "docs/VMP_UNDEFINED_RESULTS_EVIDENCE.json").write_text(
        json.dumps(evidence, indent=2) + "\n"
    )
    print(json.dumps(evidence["archive"], sort_keys=True))


if __name__ == "__main__":
    main()
