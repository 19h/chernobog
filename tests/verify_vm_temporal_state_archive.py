"""Recheck archived temporal-state captures without an installed IDA plugin."""

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
    assert evidence["passed"] and digest(args.archive.read_bytes()) == evidence["archive_sha256"]
    assert digest(Path(__file__).read_bytes()) == evidence["archive_verifier_sha256"]
    archive = json.loads(gzip.decompress(args.archive.read_bytes()))
    assert archive["schema"] == 1
    assert digest(archive["matrix"].encode()) == evidence["matrix_sha256"]
    matrix = json.loads(archive["matrix"])
    assert matrix["passed"] and len(matrix["runs"]) == 10
    assert matrix["source_sha256"] == evidence["source_sha256"]
    assert matrix["plugin_sha256"] == evidence["plugin_sha256"]
    assert matrix["ida_sha256"] == evidence["ida_sha256"]
    assert matrix["corpus_report_sha256"] == evidence["corpus_report_sha256"]
    assert set(archive["artifacts"]) == set(evidence["outcomes"])
    totals = {key: 0 for key in evidence["totals"]}
    for item in matrix["runs"]:
        label = item["label"]
        raw = archive["artifacts"][label]
        assert digest(raw["run.json"].encode()) == item["artifact_sha256"]["run.json"]
        assert (
            digest(raw["vm_temporal_state.json"].encode())
            == item["artifact_sha256"]["vm_temporal_state.json"]
        )
        assert (
            digest(raw["vm_temporal_state.json"].encode())
            == evidence["outcomes"][label]["capture_sha256"]
        )
        runner = json.loads(raw["run.json"])
        assert runner["runner_return_code"] == 0 and runner["artifacts_unchanged"]
        assert runner["input_sha256"] == evidence["outcomes"][label]["binary_sha256"]
        assert runner["plugin_sha256"] == evidence["plugin_sha256"]
        assert runner["ida_sha256"] == evidence["ida_sha256"]
        assert (
            runner["script_sha256"]
            == matrix["source_sha256"]["tests/ida_vm_temporal_state_probe.py"]
        )
        capture = json.loads(raw["vm_temporal_state.json"])
        assert capture["passed"] and len(capture["runs"]) == 4
        for run in capture["runs"]:
            assert set(run["comparison"]) == {
                "execution",
                "heads",
                "edges",
                "data",
                "candidates",
            }
            assert all(run["comparison"].values())
            totals["runs"] += 1
            totals["candidate_rows"] += run["candidate_count"]
            totals["candidate_visits"] += run["candidate_visits"]
            totals["solver_queries"] += run["queries"]
            totals["partial_instruction_samples"] += run["partial_samples"]
            totals["abstained_runs"] += not run["view_available"]
            for row in run["verdicts"]:
                assert row["semantic_validation"] == "corroborated for captured transition"
                assert row["transition_queries"] == "2"
                totals["corroborated"] += 1
    assert totals == evidence["totals"]
    print(json.dumps({"passed": True, **totals}))


if __name__ == "__main__":
    main()
