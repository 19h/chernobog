"""Measure explicit temporal-region execution on the paired string corpus."""

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from run_vmp_corpus import digest, execute


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-report", type=Path, required=True)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--strings", action="store_true", help="Measure scoped string consensus and freshness"
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    corpus_path = args.corpus_report.resolve()
    corpus = json.loads(corpus_path.read_text())
    assert corpus["passed"] and corpus["architecture"] == "x86_64"
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    probe_name = "ida_region_strings_probe.py" if args.strings else "ida_region_temporal_probe.py"
    artifact = "region_strings.json" if args.strings else "region_temporal.json"
    files = (
        "tests/run_vmp_region_temporal.py",
        "tests/" + probe_name,
        "tests/run_ida_smoke.py",
        "tests/run_vmp_corpus.py",
        "src/vm/native_region.hpp",
        "src/vm/native_region.cpp",
        "src/vm/ida_native_trace.hpp",
        "src/vm/ida_native_trace.cpp",
        "src/hybrid/emu_driver.hpp",
        "src/hybrid/emu_driver.cpp",
        "src/hybrid/temporal_memory.hpp",
        "src/hybrid/call_summary_policy.cpp",
        "src/plugin/idc_api.cpp",
        "src/plugin/deobf_plugin.cpp",
        "tests/hybrid_tests.cpp",
        "src/hybrid/evidence.hpp",
        "src/hybrid/evidence.cpp",
        "src/hybrid/native_read_strings.cpp",
        "python/chernobog_temporal_strings.py",
    )
    sources = {name: digest(root / name) for name in files}
    plugin_hash, ida_hash = digest(args.plugin), digest(args.ida)
    binaries = {
        "original": corpus["original_sha256"],
        **{p["label"]: p["sha256"] for p in corpus["protection"]},
    }
    report = {
        "schema": 1,
        "passed": False,
        "source_sha256": sources,
        "plugin_sha256": plugin_hash,
        "ida_sha256": ida_hash,
        "corpus_report_sha256": digest(corpus_path),
        "runs": [],
        "strings": args.strings,
        "scope": "explicit modeled native-region observations; ordinary publication and VM identity excluded",
    }
    try:
        for label, expected in binaries.items():
            binary, run_dir = corpus_path.parent / label, output / label
            assert digest(binary) == expected
            expected_return = label in ("original", "mutation-0", "mutation-12648430")
            measurement, _, _ = execute(
                [
                    sys.executable,
                    "-B",
                    root / "tests/run_ida_smoke.py",
                    binary,
                    root / "tests" / probe_name,
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
                    "CHERNOBOG_EXPECT_RETURN=" + str(int(expected_return)),
                ],
                timeout=120,
            )
            item = {"label": label, "input_sha256": expected, "measurement": measurement}
            report["runs"].append(item)
            assert (
                measurement["exit_code"] == 0
                and not measurement["timed_out"]
                and not measurement["output_exceeded"]
            )
            capture = json.loads((run_dir / artifact).read_text())
            run = json.loads((run_dir / "run.json").read_text())
            assert (
                run["runner_return_code"] == 0
                and run["artifacts_unchanged"]
                and run["source_script_unchanged"]
            )
            assert (
                run["input_sha256"] == expected
                and run["plugin_sha256"] == plugin_hash
                and run["ida_sha256"] == ida_hash
            )
            assert run["script_sha256"] == sources["tests/" + probe_name]
            assert not capture["errors"] and all(r["passed"] for r in capture["records"])
            item["checks"] = len(capture["records"])
            if args.strings:
                snapshot = capture["snapshot"]
                assert len(snapshot["runs"]) == 4
                item["completed"] = sum(t["complete"] == "true" for t in snapshot["runs"])
                item["instructions"] = [int(t["instructions"]) for t in snapshot["runs"]]
                item["strings"] = [row["value"] for row in snapshot["observations"]]
                item["witnesses"] = len(snapshot["witnesses"])
            else:
                assert len(capture["traces"]) == 4
                item["completed"] = sum(t["native_temporal_complete"] for t in capture["traces"])
                item["instructions"] = [t["instruction_count"] for t in capture["traces"]]
            item["artifact_sha256"] = {
                name: digest(run_dir / name) for name in ("run.json", artifact)
            }
            print(
                json.dumps({k: item[k] for k in ("label", "checks", "completed", "instructions")}),
                flush=True,
            )
        assert all(digest(root / name) == h for name, h in sources.items())
        assert digest(args.plugin) == plugin_hash and digest(args.ida) == ida_hash
        assert digest(corpus_path) == report["corpus_report_sha256"]
        assert all(digest(corpus_path.parent / name) == h for name, h in binaries.items())
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__
    finally:
        (
            output
            / ("region_strings_analysis.json" if args.strings else "region_temporal_analysis.json")
        ).write_text(json.dumps(report, indent=2) + "\n")
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
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"passed": False, "failure": type(error).__name__}))
        sys.exit(1)
