"""Audit actual IDA Qt temporal-VM captures and package durable evidence."""

import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent.parent
VARIANTS = {
    "checked": (
        "virtualization-0",
        "tests/ida_vm_temporal_gui_probe.py",
        "temporal_vm_gui.json",
        "temporal_vm_gui.png",
    ),
    "abstained": (
        "combined-12648430",
        "tests/ida_vm_temporal_gui_abstain_probe.py",
        "temporal_vm_abstain.json",
        "temporal_vm_abstain.png",
    ),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    return digest(Path(path).read_bytes())


def png_dimensions(data):
    assert data[:16] == b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    width, height = struct.unpack_from(">II", data, 16)
    assert 1000 <= width <= 8192 and 600 <= height <= 8192
    return [width, height]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in (
        "checked-dir",
        "abstained-dir",
        "corpus-report",
        "ida",
        "plugin",
        "output",
        "archive",
    ):
        parser.add_argument("--" + option, type=Path, required=True)
    args = parser.parse_args()
    corpus = json.loads(args.corpus_report.read_text())
    assert corpus["passed"] and corpus["architecture"] == "x86_64"
    binaries = {
        "original": corpus["original_sha256"],
        **{variant["label"]: variant["sha256"] for variant in corpus["protection"]},
    }
    plugin_hash, ida_hash = file_digest(args.plugin), file_digest(args.ida)
    source_names = (
        "python/chernobog_evidence.py",
        "tests/run_ida_smoke.py",
        "tests/ida_vm_temporal_gui_probe.py",
        "tests/ida_vm_temporal_gui_abstain_probe.py",
    )
    sources = {name: file_digest(ROOT / name) for name in source_names}
    archive = {"schema": 1, "artifacts": {}}
    outcomes = {}
    for kind, (label, script, report_name, screenshot_name) in VARIANTS.items():
        directory = getattr(args, kind.replace("-", "_") + "_dir")
        runner_bytes = (directory / "run.json").read_bytes()
        report_bytes = (directory / report_name).read_bytes()
        screenshot_bytes = (directory / screenshot_name).read_bytes()
        runner = json.loads(runner_bytes)
        report = json.loads(report_bytes)
        assert runner["runner_return_code"] == 0 and runner["artifacts_unchanged"]
        assert runner["input_sha256"] == binaries[label]
        assert file_digest(args.corpus_report.parent / label) == binaries[label]
        assert runner["plugin_sha256"] == plugin_hash
        assert runner["ida_sha256"] == ida_hash
        assert runner["enable_rax"] and runner["script_sha256"] == sources[script]
        assert report["view_sha256"] == sources["python/chernobog_evidence.py"]
        assert not report["errors"] and all(row["passed"] for row in report["checks"])
        assert report["checks"] and len({row["case"] for row in report["checks"]}) == len(
            report["checks"]
        )
        if kind == "checked":
            assert len(report["checks"]) == 13
            assert report["inventory_unchanged"]
            assert report["inventory_after_form_unchanged"]
            assert report["inventory_second_capture_unchanged"]
            assert report["candidate_support_unchanged"]
            assert report["summary"]["visits"] == 4
            assert report["summary"]["queries"] == 8
            assert report["summary"]["memory_rows"] == 5
        else:
            assert len(report["checks"]) == 5
            assert report["summary"] == {
                "syntax_candidates": 3,
                "candidate_visits": 0,
                "solver_queries": 0,
            }
        dimensions = png_dimensions(screenshot_bytes)
        outcomes[kind] = {
            "binary_label": label,
            "binary_sha256": binaries[label],
            "runner_sha256": digest(runner_bytes),
            "report_sha256": digest(report_bytes),
            "screenshot_sha256": digest(screenshot_bytes),
            "screenshot_dimensions_px": dimensions,
            "checks": len(report["checks"]),
            "summary": report["summary"],
        }
        archive["artifacts"][kind] = {
            "run.json": runner_bytes.decode(),
            "report.json": report_bytes.decode(),
            "screenshot.png": base64.b64encode(screenshot_bytes).decode(),
        }
    assert all(file_digest(ROOT / name) == value for name, value in sources.items())
    assert file_digest(args.plugin) == plugin_hash and file_digest(args.ida) == ida_hash
    encoded = json.dumps(archive, sort_keys=True, separators=(",", ":")).encode()
    assert b"/Users/" not in encoded and b"/Applications/" not in encoded
    args.archive.write_bytes(gzip.compress(encoded, mtime=0))
    evidence = {
        "schema": 1,
        "passed": True,
        "scope": "actual IDA Qt checked and abstained temporal VM captures",
        "corpus_report_sha256": file_digest(args.corpus_report),
        "plugin_sha256": plugin_hash,
        "ida_gui_sha256": ida_hash,
        "source_sha256": sources,
        "verifier_sha256": file_digest(ROOT / "tests/verify_vm_temporal_gui.py"),
        "archive_verifier_sha256": file_digest(ROOT / "tests/verify_vm_temporal_gui_archive.py"),
        "archive_sha256": file_digest(args.archive),
        "outcomes": outcomes,
    }
    args.output.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"passed": True, "checks": sum(v["checks"] for v in outcomes.values())}))


if __name__ == "__main__":
    main()
