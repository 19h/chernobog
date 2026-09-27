"""Package exact joined-quota captures and source versions without rewriting history."""

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
    root = Path(__file__).resolve().parents[1]
    files, binaries, external = {}, {}, {}

    def add(name, data=None):
        data = (root / name).read_bytes() if data is None else data
        text = data.decode()
        assert not re.search(r"/Users/[A-Za-z0-9_.-]+/", text), name
        files[name] = {"sha256": sha(data), "text": text}

    baseline = "7a7a0effc85721cce7689ecb8e90267417ba9595"
    reports = [
        "build/native-extension-prior-matrix/region_temporal_analysis.json",
        "build/native-extension-candidate-matrix/region_temporal_analysis.json",
    ]
    for name in reports:
        add(name)
        report = json.loads(files[name]["text"])
        assert report["passed"]
        for source, expected in report["source_sha256"].items():
            add(source)
            assert files[source]["sha256"] == expected
        for run in report["runs"]:
            for artifact, expected in run["artifact_sha256"].items():
                path = str(Path(name).parent / run["label"] / artifact)
                add(path)
                assert files[path]["sha256"] == expected
    production = {
        name for name in files if name.startswith("src/") or name.startswith("python/chernobog_")
    }
    baseline_sources = {}
    for name in sorted(production):
        data = subprocess.check_output(["git", "show", baseline + ":" + name], cwd=root)
        add("revisions/" + baseline[:12] + "/" + name, data)
        baseline_sources[name] = sha(data)
    assert baseline_sources["src/vm/native_region.cpp"] == sha(
        (root / "build/native-extension-prior-native_region.cpp").read_bytes()
    )
    extras = [
        "tests/vmp_native/native_extension_quota.c",
        "tests/ida_native_extension_quota_probe.py",
        "tests/verify_native_extension_quota.py",
        "tests/verify_native_undefined_slices.py",
        "tests/verify_vm_native_region_decode.py",
        "tests/package_native_extension_evidence.py",
        "docs/VMP_NATIVE_EXTENSION_QUOTA.md",
        "docs/VMP_IMPLEMENTATION.md",
        "build/native-extension-fixture-v3/corpus.json",
        "build/protected-strings-db33-v1/strings.json",
        "build/native-extension-component.txt",
        "build/native-extension-ctest.txt",
        "build/native-extension-independent.json",
        "build/native-extension-symbolic.json",
        "build/native-extension-comparison.json",
        "build/undefined-encoding-install-verification.json",
    ]
    for name in extras:
        add(name)
    independent = json.loads(files["build/native-extension-independent.json"]["text"])
    symbolic = json.loads(files["build/native-extension-symbolic.json"]["text"])
    comparison = json.loads(files["build/native-extension-comparison.json"]["text"])
    assert independent["passed"] and symbolic["passed"] and comparison["passed"]
    assert independent["source_sha256"] == files["tests/verify_native_extension_quota.py"]["sha256"]
    assert symbolic["source_sha256"] == files["tests/verify_native_undefined_slices.py"]["sha256"]
    for label in ("prior-exact", "candidate-exact", "prior-excess", "candidate-excess"):
        for artifact in ("run.json", "native_extension_quota.json"):
            add("build/native-extension-sdk-v3-" + label + "/" + artifact)
    for label in ("exact", "excess"):
        name = "build/native-extension-fixture-v3/" + label
        data = (root / name).read_bytes()
        assert not re.search(rb"/Users/[A-Za-z0-9_.-]+/", data), name
        binaries[name] = {"sha256": sha(data), "base64": base64.b64encode(data).decode()}
    historical_path = "docs/VMP_UNDEFINED_RESULTS_CAPTURE.json.gz"
    historical_data = (root / historical_path).read_bytes()
    previous = json.loads((root / "docs/VMP_UNDEFINED_RESULTS_EVIDENCE.json").read_text())
    assert sha(historical_data) == previous["archive"]["sha256"]
    historical = json.loads(gzip.decompress(historical_data))
    corpus = json.loads(files["build/protected-strings-db33-v1/strings.json"]["text"])
    expected_inputs = {
        "original": corpus["original_sha256"],
        **{row["label"]: row["sha256"] for row in corpus["protection"]},
    }
    for label, expected in expected_inputs.items():
        name = "build/protected-strings-db33-v1/" + label
        assert sha((root / name).read_bytes()) == expected
        assert historical["binary_files"][name]["sha256"] == expected
        external[name] = {
            "sha256": expected,
            "archive": historical_path,
            "archive_sha256": sha(historical_data),
            "entry": name,
        }
    canonical = (
        json.dumps(
            {
                "schema": 1,
                "files": files,
                "binary_files": binaries,
                "external_binary_files": external,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    compressed = gzip.compress(canonical, mtime=0)
    archive_name = "docs/VMP_NATIVE_EXTENSION_QUOTA_CAPTURE.json.gz"
    (root / archive_name).write_bytes(compressed)
    evidence = {
        "schema": 1,
        "passed": True,
        "baseline_revision": baseline,
        "scope": "joined native-target quota; exact snapshot admission; scoped predecessor/candidate observations",
        "archive": {
            "path": archive_name,
            "sha256": sha(compressed),
            "canonical_sha256": sha(canonical),
            "compressed_bytes": len(compressed),
            "canonical_bytes": len(canonical),
            "text_files": len(files),
            "binary_files": len(binaries),
            "external_binary_files": len(external),
        },
        "sources": {
            name: files[name]["sha256"]
            for name in files
            if name.startswith(("src/", "tests/", "python/", "docs/"))
        },
        "baseline_production_sources": baseline_sources,
        "reports": {name: files[name]["sha256"] for name in reports},
        "independent_audit": independent,
        "symbolic_audit": symbolic,
        "comparison": comparison,
        "assumptions": ["N1", "N2", "N3", "N4", "N5"],
        "review_complete": False,
    }
    (root / "docs/VMP_NATIVE_EXTENSION_QUOTA_EVIDENCE.json").write_text(
        json.dumps(evidence, indent=2) + "\n"
    )
    print(json.dumps(evidence["archive"], sort_keys=True))


if __name__ == "__main__":
    main()
