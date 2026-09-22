"""Compare direct-jump decoding on/off on an already validated paired corpus.

All other Chernobog options are identical. RAX execution is disabled. Code-xref
inventories do not substitute for an independent complete protected-edge oracle.
"""
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
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    corpus_path = args.corpus_report.resolve()
    corpus = json.loads(corpus_path.read_text())
    assert corpus["passed"] and not corpus["smoke"]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sources = {name: digest(root / name) for name in ("tests/run_vmp_analysis.py", "tests/ida_vmp_corpus_probe.py",
                "tests/run_ida_smoke.py", "tests/run_vmp_corpus.py")}
    plugin_hash, ida_hash, corpus_hash = digest(args.plugin), digest(args.ida), digest(corpus_path)
    report = {"schema": 1, "passed": False, "smoke": args.smoke, "source_sha256": sources,
              "plugin_sha256": plugin_hash, "ida_sha256": ida_hash, "corpus_report_sha256": corpus_hash,
              "profile_difference": "CHERNOBOG_IDA_DIRECT_JUMP_DECODE=0 versus 1; RAX disabled in both",
              "runs": [], "scope": "selected-entry code and xref inventories; complete oracle edge rates unknown"}
    binaries = {"original": corpus["original_sha256"], **{p["label"]: p["sha256"] for p in corpus["protection"]}}
    if args.smoke:
        binaries = {name: binaries[name] for name in ("original", "mutation-0")}
    try:
        for label, expected_hash in binaries.items():
            binary = corpus_path.parent / label
            assert digest(binary) == expected_hash
            for enabled in (False, True):
                run_name = label + ("-enabled" if enabled else "-disabled")
                run_dir = output / run_name
                command = [sys.executable, "-B", root / "tests/run_ida_smoke.py", binary,
                           root / "tests/ida_vmp_corpus_probe.py", "--ida", args.ida.resolve(),
                           "--plugin", args.plugin.resolve(), "--output-dir", run_dir,
                           "--set", "CHERNOBOG_IDA_DIRECT_JUMP_DECODE=" + str(int(enabled)),
                           "--set", "CHERNOBOG_CORPUS_ENTRIES=" + json.dumps(corpus["selected_functions"])]
                measurement, _, _ = execute(command, timeout=120)
                item = {"label": label, "enabled": enabled, "directory": run_name,
                        "input_sha256": expected_hash, "runner_measurement": measurement}
                report["runs"].append(item)
                assert measurement["exit_code"] == 0 and not measurement["timed_out"] and not measurement["output_exceeded"]
                run = json.loads((run_dir / "run.json").read_text())
                inspection = json.loads((run_dir / "corpus_inspection.json").read_text())
                assert run["runner_return_code"] == 0 and run["artifacts_unchanged"] and run["source_script_unchanged"]
                assert run["input_sha256"] == expected_hash and run["plugin_sha256"] == plugin_hash and run["ida_sha256"] == ida_hash
                assert run["script_sha256"] == sources["tests/ida_vmp_corpus_probe.py"]
                assert inspection["passed"] and "materialization_experiment" not in inspection
                item["native_stats"] = inspection["native_stats"]
                item["entries"] = {name: {"reachable_heads": len(entry["instructions"]),
                    "undefined_heads": sum(not i["is_code"] for i in entry["instructions"]),
                    "truncated": entry["traversal_truncated"], "owners_omitted": entry["owners_omitted"],
                    "native_records": sum(len(i["native"].get("records", [])) for i in entry["inspections"]),
                    "vm_candidates": sum(len(i["vm"].get("records", [])) for i in entry["inspections"]),
                    "solver_records": sum(len(i["solver"].get("records", [])) for i in entry["inspections"]),
                    "inspection_preserved_code_and_xrefs": entry["inspection_preserved_code_and_xrefs"]}
                    for name, entry in inspection["entries"].items()}
                item["artifact_sha256"] = {name: digest(run_dir / name) for name in ("run.json", "corpus_inspection.json")}
                print(json.dumps({"run": run_name, "passed": True, "entries": item["entries"]}), flush=True)
        assert all(digest(root / name) == h for name, h in sources.items())
        assert digest(args.plugin) == plugin_hash and digest(args.ida) == ida_hash and digest(corpus_path) == corpus_hash
        assert all(digest(corpus_path.parent / name) == h for name, h in binaries.items())
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__
    finally:
        (output / "analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "runs": len(report["runs"]), "failure": report.get("failure")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(type(error).__name__, file=sys.stderr)
        sys.exit(1)
