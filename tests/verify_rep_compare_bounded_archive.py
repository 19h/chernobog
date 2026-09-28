"""Package and recheck bounded comparison edge, IDA delta and protected evidence."""

import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NEW = {
    "df_repe_cmps_three_exhaust_target",
    "df_repne_cmps_three_second_target",
    "df_repe_scas_three_second_target",
    "df_repe_scas_reverse_second_target",
}
CONTROLS = {"df_repne_cmps_two_count_target", "df_repe_scas_two_count_target"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def relative(path):
    return str(path.resolve().relative_to(ROOT))


def files(args):
    owned, ownerless = args.owned_dir, args.ownerless_dir
    paths = {
        "score": args.score,
        "owned_report": owned / "dataflow_analysis.json",
        "ownerless_report": ownerless / "ownerless_dataflow_analysis.json",
        "delta_prior_run": args.prior_dir / "run.json",
        "delta_prior_report": args.prior_dir / "rep_compare_bounded.json",
        "delta_current_run": args.current_dir / "run.json",
        "delta_current_report": args.current_dir / "rep_compare_bounded.json",
        "protected_prior_run": args.protected_prior_dir / "run.json",
        "protected_prior_report": args.protected_prior_dir / "protected_region.json",
        "protected_current_run": args.protected_current_dir / "run.json",
        "protected_current_report": args.protected_current_dir / "protected_region.json",
    }
    for arch in ("x86_64", "i386"):
        paths["owned_" + arch + "_binary"] = owned / arch / "dataflow"
        paths["owned_" + arch + "_run"] = owned / arch / "inspection/run.json"
        paths["owned_" + arch + "_inspection"] = owned / arch / "inspection/dataflow.json"
        paths["ownerless_" + arch + "_binary"] = ownerless / arch / "ownerless"
        paths["ownerless_" + arch + "_run"] = ownerless / arch / "inspection/run.json"
        paths["ownerless_" + arch + "_inspection"] = (
            ownerless / arch / "inspection/ownerless_dataflow.json"
        )
    return paths


def validate(raw, evidence):
    data = {name: base64.b64decode(item["base64"], validate=True) for name, item in raw.items()}
    assert set(data) == set(evidence["artifacts"])
    for name, item in raw.items():
        meta = evidence["artifacts"][name]
        assert item["path"] == meta["path"] and item["path"].startswith("build/")
        assert len(data[name]) == meta["bytes"] and digest(data[name]) == meta["sha256"]
    document = lambda name: json.loads(data[name])
    score = document("score")
    assert score["passed"] and score["schema"] == 1 and len(score["runs"]) == 4
    assert score["oracle_delta_sha256"] == evidence["oracle_delta_sha256"]
    assert score["plugin_sha256"] == evidence["plugin_sha256"]
    assert score["ida_sha256"] == evidence["ida_sha256"]
    assert len(score["attribution_controls"]) == 7
    assert {tuple((r["architecture"], r["analysis"])) for r in score["runs"]} == {
        (arch, path) for arch in ("x86_64", "i386") for path in ("owned", "ownerless")
    }
    for row in score["runs"]:
        arch, path = row["architecture"], row["analysis"]
        counts = row["counts"]
        assert len(row["cases"]) == 68
        assert counts["eligible_sites"] == 53 and counts["oracle_edges"] == 56
        assert counts["false_edges"] == 0 and counts["unsound_covers"] == 0
        assert counts["correct_edges"] == (50 if arch == "x86_64" else 33)
        assert counts["exact_covers"] == (53 if arch == "x86_64" else 36)
        selected = {case["name"]: case for case in row["cases"] if case["name"] in NEW}
        assert set(selected) == NEW
        assert all(
            case["edge_outcome"] == ("correct" if arch == "x86_64" else "unresolved")
            for case in selected.values()
        )
        assert all(
            case["cover_outcome"] == ("exact" if arch == "x86_64" else "incomplete")
            for case in selected.values()
        )
        report = document(path + "_report")
        assert report["passed"] and report["plugin_sha256"] == evidence["plugin_sha256"]
        assert report["ida_sha256"] == evidence["ida_sha256"]
        inspected = document(path + "_" + arch + "_inspection")
        runner = document(path + "_" + arch + "_run")
        assert runner["runner_return_code"] == 0 and runner["artifacts_unchanged"]
        assert runner["source_script_unchanged"]
        assert runner["plugin_sha256"] == evidence["plugin_sha256"]
        assert runner["ida_sha256"] == evidence["ida_sha256"]
        assert runner["input_sha256"] == digest(data[path + "_" + arch + "_binary"])
        assert not inspected["errors"]
        assert score["artifact_sha256"][raw[path + "_" + arch + "_inspection"]["path"]] == digest(
            data[path + "_" + arch + "_inspection"]
        )
    before_run, after_run = document("delta_prior_run"), document("delta_current_run")
    before, after = document("delta_prior_report"), document("delta_current_report")
    assert before["passed"] and after["passed"] and not before["errors"] and not after["errors"]
    assert before_run["runner_return_code"] == after_run["runner_return_code"] == 0
    assert before_run["artifacts_unchanged"] and after_run["artifacts_unchanged"]
    assert before_run["source_script_unchanged"] and after_run["source_script_unchanged"]
    assert before_run["input_sha256"] == after_run["input_sha256"]
    assert before_run["ida_sha256"] == after_run["ida_sha256"] == evidence["ida_sha256"]
    assert before_run["script_sha256"] == after_run["script_sha256"] == evidence["probe_sha256"]
    assert before_run["plugin_sha256"] == evidence["prior_plugin_sha256"]
    assert after_run["plugin_sha256"] == evidence["plugin_sha256"]
    assert set(before["sites"]) == set(after["sites"]) == NEW | CONTROLS
    for name in NEW | CONTROLS:
        old, new = before["sites"][name], after["sites"][name]
        for field in ("root", "site", "source", "expected_target", "source_bytes", "source_flags"):
            assert old[field] == new[field]
        assert new["target"] == new["expected_target"]
        if name in NEW:
            assert (old["truth"], old["edge"], old["target"], old["user_edges"]) == (
                "candidate",
                "false",
                "unknown",
                [],
            )
        else:
            assert old == new
        assert new["truth"] == "native-proof" and new["edge"] == "true"
        assert new["user_edges"] == [new["expected_target"]]
    protected = [document("protected_" + stage + "_report") for stage in ("prior", "current")]
    protected_runs = [document("protected_" + stage + "_run") for stage in ("prior", "current")]
    for stage, run, report in zip(("prior", "current"), protected_runs, protected):
        assert run["runner_return_code"] == 0 and run["artifacts_unchanged"]
        assert (
            run["plugin_sha256"]
            == evidence["prior_plugin_sha256" if stage == "prior" else "plugin_sha256"]
        )
        assert run["ida_sha256"] == evidence["ida_sha256"]
        assert run["input_sha256"] == (
            "c61935fe4f8a66a6d36e8c0027341a55b816833005dc0006dc0fdbdb342938a5"
        )
        assert not report["errors"] and len(report["checks"]) == 8
        assert all(check["passed"] for check in report["checks"])
        assert report["inventory_before"] == report["inventory_after"]
    assert protected_runs[0]["script_sha256"] == protected_runs[1]["script_sha256"]
    assert protected[0]["inventory_before"] == protected[1]["inventory_before"]
    assert protected[0]["inspection"] == protected[1]["inspection"]
    inspected = protected[1]["inspection"]
    assert inspected["available"] and inspected["converged"] and not inspected["truncated"]
    assert len(inspected["nodes"]) == 75 and len(inspected["edges"]) == 77
    assert len(inspected["records"]) == 3
    assert all(row["status"] == "unresolved" for row in inspected["records"])
    return score


def package(args):
    paths = files(args)
    archive = {"schema": 1, "artifacts": {}}
    metadata = {}
    for name, path in paths.items():
        content = path.read_bytes()
        metadata[name] = {"path": relative(path), "sha256": digest(content), "bytes": len(content)}
        archive["artifacts"][name] = {
            "path": relative(path),
            "base64": base64.b64encode(content).decode(),
        }
    encoded = json.dumps(archive, sort_keys=True, separators=(",", ":")).encode()
    assert b"/Users/" not in encoded and b"/Applications/" not in encoded
    args.archive.write_bytes(gzip.compress(encoded, mtime=0))
    score = json.loads(args.score.read_text())
    prior = json.loads((args.prior_dir / "run.json").read_text())
    evidence = {
        "schema": 1,
        "passed": True,
        "scope": "matched x86-64/i386 owned and ownerless bounded repeated-comparison oracle",
        "artifacts": metadata,
        "archive_sha256": digest(args.archive.read_bytes()),
        "oracle_delta_sha256": digest(
            (ROOT / "tests/vmp_native/edge_oracle_bounded_compare.json").read_bytes()
        ),
        "verifier_sha256": digest(Path(__file__).read_bytes()),
        "scorer_sha256": digest((ROOT / "tests/score_rep_compare_bounded.py").read_bytes()),
        "probe_sha256": digest((ROOT / "tests/ida_rep_compare_bounded_probe.py").read_bytes()),
        "prior_plugin_sha256": prior["plugin_sha256"],
        "plugin_sha256": score["plugin_sha256"],
        "ida_sha256": score["ida_sha256"],
    }
    args.evidence.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")


def verify(args):
    evidence = json.loads(args.evidence.read_text())
    assert evidence["passed"] and evidence["schema"] == 1
    assert digest(Path(__file__).read_bytes()) == evidence["verifier_sha256"]
    assert digest(args.archive.read_bytes()) == evidence["archive_sha256"]
    assert (
        digest((ROOT / "tests/score_rep_compare_bounded.py").read_bytes())
        == evidence["scorer_sha256"]
    )
    assert (
        digest((ROOT / "tests/ida_rep_compare_bounded_probe.py").read_bytes())
        == evidence["probe_sha256"]
    )
    assert (
        digest((ROOT / "tests/vmp_native/edge_oracle_bounded_compare.json").read_bytes())
        == evidence["oracle_delta_sha256"]
    )
    archive = json.loads(gzip.decompress(args.archive.read_bytes()))
    assert archive["schema"] == 1
    validate(archive["artifacts"], evidence)
    print(json.dumps({"passed": True, "cases": 4 * 68, "delta_sites": 6}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "score",
        "owned-dir",
        "ownerless-dir",
        "prior-dir",
        "current-dir",
        "protected-prior-dir",
        "protected-current-dir",
        "archive",
        "evidence",
    ):
        parser.add_argument("--" + name, type=Path, required=name in ("archive", "evidence"))
    args = parser.parse_args()
    if args.score:
        package(args)
    verify(args)


if __name__ == "__main__":
    main()
