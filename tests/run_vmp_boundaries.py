"""Measure bounded native region frontiers on an existing paired VMP corpus."""
import argparse
from collections import Counter
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
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    corpus_path = args.corpus_report.resolve()
    corpus = json.loads(corpus_path.read_text())
    assert corpus["passed"] and not corpus["smoke"]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    files = ["tests/run_vmp_boundaries.py", "tests/ida_vm_boundary_probe.py", "tests/run_ida_smoke.py",
             "tests/run_vmp_corpus.py", "src/vm/boundary.hpp", "src/vm/boundary.cpp",
             "src/vm/ida_regions.cpp", "tests/vm_boundary_tests.cpp", "CMakeLists.txt"]
    sources = {name: digest(root / name) for name in files}
    plugin_hash, ida_hash, corpus_hash = digest(args.plugin), digest(args.ida), digest(corpus_path)
    binaries = {"original": corpus["original_sha256"], **{p["label"]: p["sha256"] for p in corpus["protection"]}}
    report = {"schema": 1, "passed": False, "source_sha256": sources, "plugin_sha256": plugin_hash,
              "ida_sha256": ida_hash, "corpus_report_sha256": corpus_hash, "runs": [],
              "scope": "decoded native topology stops at unmodeled transfers; no VM execution ownership",
              "profile": "normal native analysis; RAX disabled; disposable boundary controls on original only"}
    try:
        for label, expected in binaries.items():
            binary, run_dir = corpus_path.parent / label, output / label
            assert digest(binary) == expected
            command = [sys.executable, "-B", root / "tests/run_ida_smoke.py", binary,
                       root / "tests/ida_vm_boundary_probe.py", "--ida", args.ida.resolve(),
                       "--plugin", args.plugin.resolve(), "--output-dir", run_dir,
                       "--set", "CHERNOBOG_CORPUS_ENTRIES=" + json.dumps(corpus["selected_functions"]),
                       "--set", "CHERNOBOG_BOUNDARY_CONTROLS=" + str(int(label == "original"))]
            measurement, _, _ = execute(command, timeout=180)
            item = {"label": label, "input_sha256": expected, "runner_measurement": measurement}
            report["runs"].append(item)
            assert measurement["exit_code"] == 0 and not measurement["timed_out"] and not measurement["output_exceeded"]
            run = json.loads((run_dir / "run.json").read_text())
            capture = json.loads((run_dir / "vm_boundaries.json").read_text())
            assert run["runner_return_code"] == 0 and run["artifacts_unchanged"] and run["source_script_unchanged"]
            assert run["input_sha256"] == expected and run["plugin_sha256"] == plugin_hash and run["ida_sha256"] == ida_hash
            assert run["script_sha256"] == sources["tests/ida_vm_boundary_probe.py"]
            assert capture["passed"] and not capture["errors"] and all(c["passed"] for c in capture["checks"])
            item["checks"] = len(capture["checks"])
            item["entries"] = {}
            for name in corpus["selected_functions"]:
                audit = capture["captures"][name]
                assert audit["execution_admitted"] is False
                item["entries"][name] = {key: audit[key] for key in ("available", "decoded_heads", "ownerless_heads",
                    "incoming_examined", "head_limit", "incoming_limit")}
                item["entries"][name]["frontiers"] = dict(Counter(f["reason"] for f in audit["frontiers"]))
                item["entries"][name]["edges"] = len(audit["edges"])
            item["artifact_sha256"] = {name: digest(run_dir / name) for name in ("run.json", "vm_boundaries.json")}
            print(json.dumps({"label": label, "checks": item["checks"], "entries": item["entries"]}), flush=True)
        assert all(digest(root / name) == value for name, value in sources.items())
        assert digest(args.plugin) == plugin_hash and digest(args.ida) == ida_hash and digest(corpus_path) == corpus_hash
        assert all(digest(corpus_path.parent / name) == value for name, value in binaries.items())
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__
    finally:
        (output / "boundaries_analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "runs": len(report["runs"]), "failure": report.get("failure")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(type(error).__name__, file=sys.stderr)
        sys.exit(1)
