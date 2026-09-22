#!/usr/bin/env python3
"""Matched condition-consumer measurements on the validated protected corpus.

A completed measurement is not a successful recovery. Decompiler failures,
ownerless sites and exhausted budgets remain explicit observations.
"""
import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from run_vmp_corpus import base_environment, digest, execute


SOURCES = ("tests/run_vmp_conditions.py", "tests/ida_vmp_conditions_probe.py", "tests/run_ida_smoke.py",
           "tests/run_vmp_corpus.py", "src/ida_analysis/early_hexrays.cpp", "src/ida_analysis/early_hexrays.hpp",
           "src/ida_analysis/analysis_config.cpp", "src/ida_analysis/analysis_config.hpp",
           "src/ida_analysis/x86_analysis.cpp", "src/ida_analysis/x86_analysis.hpp", "src/common/x86_abstract.h")


def summarize(inspection):
    reachable = {row["ea"]: row for entry in inspection["entries"].values()
                 for row in entry["instructions"] if row["kind"]}
    owners = inspection["owners"]
    deltas = {key: sum(owner.get("generated", {}).get("codegen_delta", {}).get(key, 0) for owner in owners)
              for key in ("codegen_setcc", "codegen_cmov", "codegen_cmov_memory")}
    return {"reachable_condition_sites": len(reachable),
            "ownerless_condition_sites": sum(row["owner"] is None for row in reachable.values()),
            "owned_function_condition_sites": sum(len(owner.get("conditions", [])) for owner in owners),
            "owners_inspected": len(owners), "owners_omitted": inspection["owners_omitted"],
            "native_budget_skips": sum(owner["status"] == "native_budget" for owner in owners),
            "generated_successes": sum(owner.get("generated", {}).get("status") == "captured" for owner in owners),
            "decompiled_successes": sum(owner.get("decompiled", {}).get("status") == "success" for owner in owners),
            "generated_failures": [{"entry": owner["entry"], "failure_code": owner["generated"].get("failure_code"),
                                    "exception_type": owner["generated"].get("exception_type")}
                                   for owner in owners if "generated" in owner and owner["generated"]["status"] != "captured"],
            "decompiled_failures": [{"entry": owner["entry"], "failure_code": owner["decompiled"].get("failure_code"),
                                     "exception_type": owner["decompiled"].get("exception_type")}
                                    for owner in owners if "decompiled" in owner and owner["decompiled"]["status"] != "success"],
            "codegen_events": deltas,
            "traversal_truncated": any(entry["truncated"] for entry in inspection["entries"].values()),
            "microcode_truncated": any(owner.get("generated", {}).get("capture_truncated", False) for owner in owners),
            "reachability_preserved": inspection["reachability_preserved"],
            "native_inventories_preserved": all(owner.get("native_preserved", True) for owner in owners)}


def compare(off, on):
    assert off["entries"] == on["entries"], "different input reachability"
    left, right = ({row["entry"]: row for row in report["owners"]} for report in (off, on))
    assert left.keys() == right.keys(), "different owner scope"
    result = {"owners": []}
    for entry, before in left.items():
        after = right[entry]
        for key in ("status", "native_head_count", "native_truncated", "native_sha256", "conditions", "flags_before"):
            assert before.get(key) == after.get(key), "different native owner input"
        a, b = before.get("generated", {}), after.get("generated", {})
        assert not any(a.get("codegen_delta", {}).values()), "disabled condition consumer emitted code"
        comparable = a.get("status") == b.get("status") == "captured" and not (a["capture_truncated"] or b["capture_truncated"])
        changed = []
        if comparable:
            assert a["conditions"].keys() == b["conditions"].keys()
            changed = [int(ea) for ea in a["conditions"] if a["conditions"][ea] != b["conditions"][ea]]
        result["owners"].append({"entry": entry, "generated_comparable": comparable,
            "generated_status_off": a.get("status"), "generated_status_on": b.get("status"),
            "generated_changed": a["microcode_sha256"] != b["microcode_sha256"] if comparable else None,
            "changed_condition_sites": changed,
            "decompiled_status_off": before.get("decompiled", {}).get("status"),
            "decompiled_status_on": after.get("decompiled", {}).get("status"),
            "decompiled_text_changed": (before["decompiled"]["sha256"] != after["decompiled"]["sha256"])
                if before.get("decompiled", {}).get("status") == after.get("decompiled", {}).get("status") == "success" else None})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-report", required=True, type=Path)
    parser.add_argument("--ida", required=True, type=Path)
    parser.add_argument("--plugin", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--label", action="append", help="selected corpus labels; omit for all ten")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    corpus_path = args.corpus_report.resolve()
    corpus = json.loads(corpus_path.read_text())
    assert corpus["passed"] and not corpus["smoke"]
    binaries = {"original": corpus["original_sha256"], **{row["label"]: row["sha256"] for row in corpus["protection"]}}
    if args.label:
        assert len(set(args.label)) == len(args.label) and set(args.label) <= binaries.keys()
        binaries = {label: binaries[label] for label in args.label}
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": 1, "passed": False, "partial_labels": bool(args.label),
              "source_sha256": {name: digest(root / name) for name in SOURCES},
              "plugin_sha256": digest(args.plugin), "ida_sha256": digest(args.ida),
              "corpus_report_sha256": digest(corpus_path), "runs": [], "comparisons": {},
              "profile_difference": "CHERNOBOG_IDA_CONDITION_CODEGEN=0 versus 1; RAX disabled; all other controls identical",
              "scope": "existing selected-entry reachability and function owners; no native execution or complete protected-edge oracle"}
    try:
        for label, expected in binaries.items():
            binary = corpus_path.parent / label
            assert digest(binary) == expected
            captures = {}
            for enabled in (False, True):
                name = label + ("-on" if enabled else "-off")
                directory = output / name
                command = [sys.executable, "-B", root / "tests/run_ida_smoke.py", binary,
                    root / "tests/ida_vmp_conditions_probe.py", "--ida", args.ida.resolve(), "--plugin", args.plugin.resolve(),
                    "--output-dir", directory, "--set", "CHERNOBOG_IDA_CONDITION_CODEGEN=" + str(int(enabled)),
                    "--set", "CHERNOBOG_CORPUS_ENTRIES=" + json.dumps(corpus["selected_functions"])]
                measurement, _, _ = execute(command, cwd=root, env=base_environment(), timeout=180)
                item = {"label": label, "enabled": enabled, "directory": name, "input_sha256": expected,
                        "runner_measurement": measurement}
                report["runs"].append(item)
                assert measurement["exit_code"] == 0 and not measurement["timed_out"] and not measurement["output_exceeded"]
                run = json.loads((directory / "run.json").read_text())
                inspection = json.loads((directory / "conditions_corpus.json").read_text())
                assert run["artifacts_unchanged"] and run["source_script_unchanged"] and run["runner_return_code"] == 0
                assert run["input_sha256"] == expected and run["plugin_sha256"] == report["plugin_sha256"]
                assert run["ida_sha256"] == report["ida_sha256"]
                assert run["script_sha256"] == report["source_sha256"]["tests/ida_vmp_conditions_probe.py"]
                assert inspection["passed"] and not inspection["errors"] and inspection["condition_codegen"] == enabled
                captures[enabled] = inspection
                item["summary"] = summarize(inspection)
                item["artifact_sha256"] = {p: digest(directory / p) for p in ("run.json", "conditions_corpus.json")}
                print(json.dumps({"run": name, "summary": item["summary"]}), flush=True)
            report["comparisons"][label] = compare(captures[False], captures[True])
        assert all(digest(root / p) == sha for p, sha in report["source_sha256"].items())
        assert digest(args.plugin) == report["plugin_sha256"] and digest(args.ida) == report["ida_sha256"]
        assert digest(corpus_path) == report["corpus_report_sha256"]
        assert all(digest(corpus_path.parent / label) == sha for label, sha in binaries.items())
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__
    finally:
        (output / "conditions_analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "runs": len(report["runs"]), "failure": report.get("failure")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
