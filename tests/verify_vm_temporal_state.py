"""Audit the paired native-state transition matrix and create durable evidence."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_IDA = "613d9ff7cda10686fefde8fee90ec5cbd0d2dc656bb8eaf737cbd5f9b3021ffd"
EXPECTED_COUNTS = {
    "original": (0, 0),
    "mutation-0": (0, 0),
    "mutation-1": (0, 0),
    "mutation-12648430": (0, 0),
    "virtualization-0": (4, 4),
    "virtualization-1": (4, 7),
    "virtualization-12648430": (0, 0),
    "combined-0": (5, 10),
    "combined-1": (4, 8),
    "combined-12648430": (3, 0),
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def audit(matrix, corpus_path, plugin, ida):
    report = json.loads(Path(matrix).read_text())
    corpus = json.loads(Path(corpus_path).read_text())
    assert report["passed"] and len(report["runs"]) == 10
    assert corpus["passed"] and corpus["architecture"] == "x86_64"
    assert report["baseline_commit"] == "6cbfd62cc8c0639b0264de866023f2ded62af10b"
    assert report["corpus_report_sha256"] == digest(corpus_path)
    assert report["plugin_sha256"] == digest(plugin)
    assert report["ida_sha256"] == digest(ida) == EXPECTED_IDA
    assert all(digest(ROOT / name) == value for name, value in report["source_sha256"].items())
    binaries = {
        "original": corpus["original_sha256"],
        **{variant["label"]: variant["sha256"] for variant in corpus["protection"]},
    }
    assert set(binaries) == set(EXPECTED_COUNTS)

    totals = {
        "runs": 0,
        "candidate_rows": 0,
        "candidate_visits": 0,
        "corroborated": 0,
        "solver_queries": 0,
        "partial_instruction_samples": 0,
        "abstained_runs": 0,
    }
    outcomes = {}
    target_rows = []
    for item in report["runs"]:
        label = item["label"]
        assert label not in outcomes and digest(Path(corpus_path).parent / label) == binaries[label]
        assert item["input_sha256"] == binaries[label]
        directory = Path(matrix).parent / label
        artifact = directory / "vm_temporal_state.json"
        assert digest(artifact) == item["artifact_sha256"]["vm_temporal_state.json"]
        assert digest(directory / "run.json") == item["artifact_sha256"]["run.json"]
        runner = json.loads((directory / "run.json").read_text())
        assert runner["runner_return_code"] == 0 and runner["artifacts_unchanged"]
        assert runner["input_sha256"] == binaries[label]
        assert runner["plugin_sha256"] == digest(plugin) and runner["ida_sha256"] == EXPECTED_IDA
        assert (
            runner["script_sha256"]
            == report["source_sha256"]["tests/ida_vm_temporal_state_probe.py"]
        )
        captured = json.loads(artifact.read_text())
        assert captured["passed"] and not captured["errors"] and len(captured["runs"]) == 4
        expected_rows, expected_visits = EXPECTED_COUNTS[label]
        for index, run in enumerate(captured["runs"]):
            assert run["available"] and run["ran"] and run["sample_requested"]
            assert set(run["comparison"]) == {
                "execution",
                "heads",
                "edges",
                "data",
                "candidates",
            }
            assert all(run["comparison"].values())
            assert run["sample_count"] == run["execution_count"]
            assert run["candidate_count"] == expected_rows
            assert run["candidate_visits"] == expected_visits
            assert run["transition_attempts"] == expected_visits
            assert run["queries"] == 2 * expected_visits
            assert len(run["verdicts"]) == expected_visits
            assert not run["function_published"] and not run["vm_identity_proved"]
            assert not run["candidate_limited"] and not run["path_limited"]
            assert not run["sample_complete"] or run["partial_samples"] == 0
            assert run["seed"] == ("0x0", "0x1", "0x11", "0xc0ffee")[index]
            if label.startswith(("original", "mutation")):
                assert run["temporal_complete"] and run["view_available"]
            else:
                assert not run["temporal_complete"]
            if label == "combined-12648430":
                assert not run["prefix_complete"] and not run["sample_complete"]
                assert not run["view_available"]
                assert (
                    run["view_reason"]
                    == "complete native instruction-entry or temporal event prefix required"
                )
                totals["abstained_runs"] += 1
            else:
                assert run["view_available"]
            for row in run["verdicts"]:
                assert row["semantic_validation"] == "corroborated for captured transition"
                assert row["transition_queries"] == "2"
                assert row["path"] == "complete captured native path"
                assert row["internal_transfers"] == "exact captured witnesses"
                assert row["transition_reason"].startswith("SAT inputs then UNSAT mismatch:")
                assert 0 <= int(row["accesses_captured"]) <= 64
                totals["corroborated"] += 1
                if label == "virtualization-0" and row["site"] == "0x1000d64db":
                    assert row["read"] == "0x1000d64ea"
                    assert row["dispatch"] == "0x10008ef17"
                    assert row["target"] == "0x100007031"
                    assert row["accesses_captured"] == "5"
                    assert int(row["entry_vip"], 16) - int(row["output_vip"], 16) == 4
                    target_rows.append({"seed": run["seed"], **row})
            totals["runs"] += 1
            totals["candidate_rows"] += run["candidate_count"]
            totals["candidate_visits"] += run["candidate_visits"]
            totals["solver_queries"] += run["queries"]
            totals["partial_instruction_samples"] += run["partial_samples"]
        assert item["candidate_counts"] == [r["candidate_count"] for r in captured["runs"]]
        assert item["candidate_visits"] == [r["candidate_visits"] for r in captured["runs"]]
        assert item["queries"] == [r["queries"] for r in captured["runs"]]
        outcomes[label] = {
            "binary_sha256": binaries[label],
            "capture_sha256": digest(artifact),
            "candidate_rows": sum(item["candidate_counts"]),
            "candidate_visits": sum(item["candidate_visits"]),
            "corroborated": sum(item["corroborated_counts"]),
            "solver_queries": sum(item["queries"]),
            "partial_instruction_samples": sum(item["partial_samples"]),
            "sample_complete": item["sample_complete"],
            "temporal_complete": item["temporal_complete"],
        }
    assert len(outcomes) == 10 and len(target_rows) == 4
    assert totals == {
        "runs": 40,
        "candidate_rows": 80,
        "candidate_visits": 116,
        "corroborated": 116,
        "solver_queries": 232,
        "partial_instruction_samples": 1676,
        "abstained_runs": 4,
    }
    return {
        "schema": 1,
        "passed": True,
        "baseline_commit": report["baseline_commit"],
        "scope": report["scope"],
        "matrix_sha256": digest(matrix),
        "corpus_report_sha256": digest(corpus_path),
        "plugin_sha256": digest(plugin),
        "ida_sha256": digest(ida),
        "source_sha256": report["source_sha256"],
        "verifier_sha256": digest(ROOT / "tests/verify_vm_temporal_state.py"),
        "archive_verifier_sha256": digest(ROOT / "tests/verify_vm_temporal_state_archive.py"),
        "totals": totals,
        "outcomes": outcomes,
        "target_rows": target_rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("matrix", "corpus-report", "plugin", "ida", "output", "archive"):
        parser.add_argument("--" + option, type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.matrix, args.corpus_report, args.plugin, args.ida)
    archive = {
        "schema": 1,
        "matrix": args.matrix.read_text(),
        "artifacts": {
            label: {
                "run.json": (args.matrix.parent / label / "run.json").read_text(),
                "vm_temporal_state.json": (
                    args.matrix.parent / label / "vm_temporal_state.json"
                ).read_text(),
            }
            for label in result["outcomes"]
        },
    }
    encoded = json.dumps(archive, sort_keys=True, separators=(",", ":")).encode()
    assert b"/Users/" not in encoded and b"/Applications/" not in encoded
    args.archive.write_bytes(gzip.compress(encoded, mtime=0))
    restored = json.loads(gzip.decompress(args.archive.read_bytes()))
    assert hashlib.sha256(restored["matrix"].encode()).hexdigest() == result["matrix_sha256"]
    for label, item in result["outcomes"].items():
        assert (
            hashlib.sha256(
                restored["artifacts"][label]["vm_temporal_state.json"].encode()
            ).hexdigest()
            == item["capture_sha256"]
        )
    result["archive_sha256"] = digest(args.archive)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"passed": True, **result["totals"]}))


if __name__ == "__main__":
    main()
