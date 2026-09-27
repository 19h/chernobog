"""Recheck archived IDA Qt temporal-VM reports and screenshots offline."""

import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path
import struct


def digest(data):
    return hashlib.sha256(data).hexdigest()


def dimensions(data):
    assert data[:16] == b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    return list(struct.unpack_from(">II", data, 16))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    evidence = json.loads(args.evidence.read_text())
    assert evidence["passed"] and evidence["schema"] == 1
    assert digest(Path(__file__).read_bytes()) == evidence["archive_verifier_sha256"]
    assert digest(args.archive.read_bytes()) == evidence["archive_sha256"]
    archive = json.loads(gzip.decompress(args.archive.read_bytes()))
    assert archive["schema"] == 1
    assert set(archive["artifacts"]) == set(evidence["outcomes"]) == {"checked", "abstained"}
    total_checks = 0
    for kind, raw in archive["artifacts"].items():
        outcome = evidence["outcomes"][kind]
        runner_bytes = raw["run.json"].encode()
        report_bytes = raw["report.json"].encode()
        screenshot = base64.b64decode(raw["screenshot.png"], validate=True)
        assert digest(runner_bytes) == outcome["runner_sha256"]
        assert digest(report_bytes) == outcome["report_sha256"]
        assert digest(screenshot) == outcome["screenshot_sha256"]
        assert dimensions(screenshot) == outcome["screenshot_dimensions_px"]
        runner = json.loads(runner_bytes)
        report = json.loads(report_bytes)
        assert runner["runner_return_code"] == 0 and runner["artifacts_unchanged"]
        assert runner["input_sha256"] == outcome["binary_sha256"]
        assert runner["plugin_sha256"] == evidence["plugin_sha256"]
        assert runner["ida_sha256"] == evidence["ida_gui_sha256"]
        assert report["view_sha256"] == evidence["source_sha256"]["python/chernobog_evidence.py"]
        assert not report["errors"] and len(report["checks"]) == outcome["checks"]
        assert all(row["passed"] for row in report["checks"])
        assert report["summary"] == outcome["summary"]
        names = {row["case"] for row in report["checks"]}
        if kind == "checked":
            assert outcome["binary_label"] == "virtualization-0"
            assert outcome["checks"] == 13 and report["inventory_unchanged"]
            assert report["summary"]["visits"] == 4
            assert report["summary"]["queries"] == 8
            assert "changed source bytes disable navigation" in names
        else:
            assert outcome["binary_label"] == "combined-12648430"
            assert outcome["checks"] == 5
            assert report["summary"] == {
                "syntax_candidates": 3,
                "candidate_visits": 0,
                "solver_queries": 0,
            }
            assert "selected scaffold is explicitly syntax-only" in names
        total_checks += outcome["checks"]
    assert total_checks == 18
    print(json.dumps({"passed": True, "checks": total_checks}))


if __name__ == "__main__":
    main()
