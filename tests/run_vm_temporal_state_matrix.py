"""Run the opt-in native state/transition probe on the paired strings corpus."""

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from run_vmp_corpus import digest, execute


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("corpus-report", "ida", "plugin", "output-dir"):
        parser.add_argument("--" + option, type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    corpus_path = args.corpus_report.resolve()
    corpus = json.loads(corpus_path.read_text())
    assert corpus["passed"] and corpus["architecture"] == "x86_64"
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source_files = (
        "tests/run_vm_temporal_state_matrix.py",
        "tests/ida_vm_temporal_state_probe.py",
        "tests/run_ida_smoke.py",
        "tests/run_vmp_corpus.py",
        "src/hybrid/emu_driver.cpp",
        "src/hybrid/emu_driver.hpp",
        "src/vm/ida_native_trace.cpp",
        "src/vm/ida_native_trace.hpp",
        "src/vm/native_observations.cpp",
        "src/plugin/idc_api.cpp",
        "tests/vm_native_observation_tests.cpp",
    )
    sources = {name: digest(root / name) for name in source_files}
    plugin_hash, ida_hash = digest(args.plugin), digest(args.ida)
    binaries = {
        "original": corpus["original_sha256"],
        **{variant["label"]: variant["sha256"] for variant in corpus["protection"]},
    }
    report = {
        "schema": 1,
        "passed": False,
        "baseline_commit": "6cbfd62cc8c0639b0264de866023f2ded62af10b",
        "source_sha256": sources,
        "plugin_sha256": plugin_hash,
        "ida_sha256": ida_hash,
        "corpus_report_sha256": digest(corpus_path),
        "scope": "sampled explicit native temporal prefixes; local fixed-input transition checks only",
        "runs": [],
    }
    try:
        for label, expected in binaries.items():
            binary = corpus_path.parent / label
            run_dir = output / label
            assert digest(binary) == expected
            measurement, _, _ = execute(
                [
                    sys.executable,
                    "-B",
                    root / "tests/run_ida_smoke.py",
                    binary,
                    root / "tests/ida_vm_temporal_state_probe.py",
                    "--ida",
                    args.ida.resolve(),
                    "--plugin",
                    args.plugin.resolve(),
                    "--output-dir",
                    run_dir,
                    "--enable-rax",
                    "--set",
                    "CHERNOBOG_STRING_ENTRY=" + corpus["selected_entry"],
                    "--set",
                    "CHERNOBOG_VARIANT_LABEL=" + label,
                ],
                timeout=120,
            )
            item = {"label": label, "input_sha256": expected, "measurement": measurement}
            report["runs"].append(item)
            assert measurement["exit_code"] == 0 and not measurement["timed_out"]
            assert not measurement["output_exceeded"]
            capture_path = run_dir / "vm_temporal_state.json"
            capture = json.loads(capture_path.read_text())
            runner = json.loads((run_dir / "run.json").read_text())
            assert capture["passed"] and not capture["errors"] and len(capture["runs"]) == 4
            assert runner["runner_return_code"] == 0 and runner["artifacts_unchanged"]
            assert runner["input_sha256"] == expected
            assert runner["plugin_sha256"] == plugin_hash and runner["ida_sha256"] == ida_hash
            assert runner["script_sha256"] == sources["tests/ida_vm_temporal_state_probe.py"]
            item["candidate_counts"] = [r["candidate_count"] for r in capture["runs"]]
            item["candidate_visits"] = [r["candidate_visits"] for r in capture["runs"]]
            item["corroborated_counts"] = [
                sum(
                    row["semantic_validation"] == "corroborated for captured transition"
                    for row in r["verdicts"]
                )
                for r in capture["runs"]
            ]
            item["partial_samples"] = [r["partial_samples"] for r in capture["runs"]]
            item["queries"] = [r["queries"] for r in capture["runs"]]
            item["sample_complete"] = [r["sample_complete"] for r in capture["runs"]]
            item["temporal_complete"] = [r["temporal_complete"] for r in capture["runs"]]
            item["artifact_sha256"] = {
                "run.json": digest(run_dir / "run.json"),
                "vm_temporal_state.json": digest(capture_path),
            }
            print(
                json.dumps(
                    {
                        "label": label,
                        "candidates": item["candidate_counts"],
                        "corroborated": item["corroborated_counts"],
                        "queries": item["queries"],
                    }
                ),
                flush=True,
            )
        assert all(digest(root / name) == hash_value for name, hash_value in sources.items())
        assert digest(args.plugin) == plugin_hash and digest(args.ida) == ida_hash
        assert digest(corpus_path) == report["corpus_report_sha256"]
        assert all(digest(corpus_path.parent / label) == value for label, value in binaries.items())
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__
    finally:
        (output / "vm_temporal_state_matrix.json").write_text(json.dumps(report, indent=2) + "\n")
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
    sys.exit(main())
