"""Run separate-process condition persistence, relocation and undo IR audits."""

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from run_relational_conditions import verify_ir
from run_vmp_corpus import digest, execute


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-report", type=Path, required=True)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixture = json.loads(args.fixture_report.read_text())
    assert fixture["passed"] and not fixture["baseline"]
    assert {row["architecture"] for row in fixture["runs"]} == {"x86_64", "i386"}
    for name in (
        "tests/vmp_native/relational_conditions.c",
        "tests/vmp_native/relational_conditions_main.c",
    ):
        assert digest(root / name) == fixture["source_sha256"][name]
    sources = [
        "src/ida_analysis/x86_analysis.cpp",
        "src/ida_analysis/x86_analysis.hpp",
        "src/ida_analysis/native_engine.cpp",
        "src/ida_analysis/early_hexrays.cpp",
        "src/ida_analysis/proof_receipt.hpp",
        "src/common/x86_abstract.h",
        "src/common/bounded_dataflow.h",
        "python/chernobog_evidence.py",
        "tests/ida_condition_lifecycle_probe.py",
        "tests/run_condition_lifecycle.py",
        "tests/ida_relational_conditions_probe.py",
        "tests/run_relational_conditions.py",
        "tests/verify_conditions_microcode.py",
        "tests/run_ida_smoke.py",
        "tests/run_vmp_corpus.py",
        "tests/vmp_native/relational_conditions.c",
        "tests/vmp_native/relational_conditions_main.c",
    ]
    report = {
        "passed": False,
        "source_sha256": {name: digest(root / name) for name in sources},
        "fixture_report": str(args.fixture_report.resolve().relative_to(root)),
        "fixture_report_sha256": digest(args.fixture_report),
        "plugin_sha256": digest(args.plugin),
        "ida_sha256": digest(args.ida),
        "runs": [],
    }
    try:
        for row in fixture["runs"]:
            architecture = row["architecture"]
            binary = args.fixture_report.resolve().parent / architecture / "relation"
            assert digest(binary) == row["binary_sha256"]
            assert row["native_result"] == {"passed": True, "checks": 41476}
            base = output / architecture
            base.mkdir()
            stages = [
                ("write", "write", binary),
                ("read", "read", base / "write/condition_lifecycle.i64"),
                ("rebase", "rebase", base / "write/condition_lifecycle.i64"),
                ("read_rebased", "read_rebased", base / "rebase/condition_rebased.i64"),
                ("rebase_nodes", "rebase_nodes", base / "write/condition_lifecycle.i64"),
                (
                    "read_rebased_nodes",
                    "read_rebased",
                    base / "rebase_nodes/condition_rebased.i64",
                ),
                ("undo", "undo", base / "write/condition_lifecycle.i64"),
            ]
            for label, stage, input_path in stages:
                directory = base / label
                measurement, _, _ = execute(
                    [
                        sys.executable,
                        "-B",
                        root / "tests/run_ida_smoke.py",
                        input_path,
                        root / "tests/ida_condition_lifecycle_probe.py",
                        "--ida",
                        args.ida.resolve(),
                        "--plugin",
                        args.plugin.resolve(),
                        "--output-dir",
                        directory,
                        "--set",
                        "CHERNOBOG_IDA_REGISTER_SCAN_DEPTH=64",
                        "--set",
                        "CHERNOBOG_IDA_FLAG_SCAN_DEPTH=64",
                        "--set",
                        "CHERNOBOG_CONDITION_CONTRACT="
                        + str(root / "tests/ida_relational_conditions_probe.py"),
                        "--set",
                        "CHERNOBOG_VIEW_MODULE=" + str(root / "python/chernobog_evidence.py"),
                        "--set",
                        "CHERNOBOG_CONDITION_STAGE=" + stage,
                        *(["--allow-database"] if stage != "write" else []),
                    ],
                    timeout=120,
                )
                result = {"architecture": architecture, "stage": label, "measurement": measurement}
                report["runs"].append(result)
                capture = json.loads((directory / "condition_lifecycle.json").read_text())
                result["errors"] = capture["errors"]
                assert (
                    measurement["exit_code"] == 0
                    and not measurement["timed_out"]
                    and not measurement["output_exceeded"]
                )
                assert not capture["errors"] and all(check["passed"] for check in capture["checks"])
                result["checks"] = len(capture["checks"])
                result["effect_checks"] = {}
                for name, snapshot in capture["snapshots"].items():
                    members, effects = (24, 112) if snapshot["patched"] else (30, 140)
                    result["effect_checks"][name] = verify_ir(snapshot, False, members, effects)
                manifest = json.loads((directory / "run.json").read_text())
                assert manifest["artifacts_unchanged"] and manifest["source_script_unchanged"]
                assert (
                    manifest["plugin_sha256"] == report["plugin_sha256"]
                    and manifest["ida_sha256"] == report["ida_sha256"]
                )
                assert (
                    manifest["input_sha256"] == digest(input_path)
                    and manifest["runner_return_code"] == 0
                )
                result["input_sha256"] = digest(input_path)
                result["artifact_sha256"] = {
                    name: digest(directory / name)
                    for name in ("condition_lifecycle.json", "run.json")
                }
                if stage in ("write", "rebase", "rebase_nodes"):
                    checkpoint = (
                        "condition_lifecycle.i64" if stage == "write" else "condition_rebased.i64"
                    )
                    result["checkpoint_sha256"] = digest(directory / checkpoint)
                print(
                    json.dumps(
                        {
                            "architecture": architecture,
                            "stage": label,
                            "checks": result["checks"],
                            "effect_checks": result["effect_checks"],
                        }
                    ),
                    flush=True,
                )
        assert all(digest(root / name) == h for name, h in report["source_sha256"].items())
        assert (
            digest(args.plugin) == report["plugin_sha256"]
            and digest(args.ida) == report["ida_sha256"]
        )
        assert digest(args.fixture_report) == report["fixture_report_sha256"]
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    (output / "condition_lifecycle_analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "runs": len(report["runs"]),
                "failure": report.get("failure"),
            }
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
