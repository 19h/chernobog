"""Check protected MBA reports before and after strict AST-cache reuse."""

import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path

from mba_match_replay import capture, catalog
from verify_mba_address_matrix_delta import (
    EXPECTED,
    canonical,
    check_manifest,
    checked_artifacts,
    digest,
    require,
    without_duration,
)


def check_inputs(report, totals):
    rules = report["rule_catalog"]
    require(rules["registered"] == 108 and rules["rejected"] == 0, "catalog size")
    require(
        rules["verified"] == (0 if report["transformations_disabled"] else 108),
        "catalog certification",
    )
    model, _ = catalog(
        report["matcher_catalog"],
        rules["names"],
        report["transformations_disabled"],
    )
    for entry in report["entries"]:
        for row in (entry, entry.get("body")):
            if row is None:
                continue
            for stage in row["stages"]:
                inputs = stage["statistics"]["matching_inputs"]
                require(inputs["schema"] == 2 and inputs["sample_limit"] == 1024, "capture profile")
                totals["events"] += inputs["events"]
                totals["unrecorded"] += inputs["unrecorded"]
                for sample in inputs["samples"]:
                    require(
                        sample["capture_status"] == "complete" and sample["input"] is not None,
                        "capture completeness",
                    )
                    require(sample["input"].get("schema") == 2, "input schema")
                    capture(sample["input"], model)
                    totals["retained_samples"] += 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prior_path, current_path = args.prior.resolve(), args.current.resolve()
    prior_bytes, current_bytes = prior_path.read_bytes(), current_path.read_bytes()
    prior, current = json.loads(prior_bytes), json.loads(current_bytes)
    for aggregate in (prior, current):
        require(aggregate["schema"] == 1 and aggregate["passed"], "matrix status")
        require(len(aggregate["runs"]) == 40, "matrix population")
        require(
            aggregate["native_analysis_disabled"] is False
            and aggregate["matcher_inputs"] is True
            and aggregate["input_limit"] == 1024
            and aggregate["matching_diagnostics"] is True,
            "matrix profile",
        )
    require(prior["plugin_sha256"] != current["plugin_sha256"], "plugin transition")
    require(prior["ida_sha256"] == current["ida_sha256"], "IDA transition")
    require(prior["ida_components_sha256"] == current["ida_components_sha256"], "IDA components")
    require(prior["paired"] == current["paired"], "paired result transition")
    old_runs = {(r["architecture"], r["label"], r["disabled"]): r for r in prior["runs"]}
    new_runs = {(r["architecture"], r["label"], r["disabled"]): r for r in current["runs"]}
    require(set(old_runs) == set(new_runs) == EXPECTED, "matrix identities")
    totals = Counter()
    normalized_hash = hashlib.sha256()
    first_report = None
    for key in sorted(EXPECTED):
        before, after = old_runs[key], new_runs[key]
        require(before["binary_sha256"] == after["binary_sha256"], "binary transition")
        require(before["counts"] == after["counts"], "SDK count transition")
        old_run, old_probe = checked_artifacts(before, prior_path.parent)
        new_run, new_probe = checked_artifacts(after, current_path.parent)
        check_manifest(before, prior, old_run)
        check_manifest(after, current, new_run)
        for field in (
            "input_sha256",
            "source_input_sha256",
            "script_sha256",
            "source_script_sha256",
            "ida_sha256",
            "chernobog_environment_sha256",
        ):
            require(old_run[field] == new_run[field], "SDK run transition: " + field)
        require(old_probe["passed"] and new_probe["passed"], "SDK report status")
        require(not old_probe["errors"] and not new_probe["errors"], "SDK report errors")
        older, newer = without_duration(old_probe), without_duration(new_probe)
        require(older == newer, "SDK report transition")
        check_inputs(new_probe, totals)
        totals["successful_matches"] += after["counts"]["successful_matches"]
        normalized_hash.update(canonical(key) + b"\0" + canonical(newer) + b"\0")
        if first_report is None:
            first_report = older
    require(
        totals
        == {"events": 14047, "unrecorded": 0, "retained_samples": 9729, "successful_matches": 5},
        "matrix totals",
    )
    altered = copy.deepcopy(first_report)
    altered["entries"][0]["stages"][0]["statistics"]["matching_inputs"]["events"] += 1
    require(altered != first_report, "report mutation accepted")
    result = {
        "schema": 1,
        "passed": True,
        "scope": "40 matched x86-64/i386 SDK profiles; exact schema-2 report equality excluding stage elapsed time",
        "prior_matrix_sha256": digest(prior_bytes),
        "current_matrix_sha256": digest(current_bytes),
        "prior_plugin_sha256": prior["plugin_sha256"],
        "current_plugin_sha256": current["plugin_sha256"],
        "ida_sha256": current["ida_sha256"],
        "normalized_reports_sha256": normalized_hash.hexdigest(),
        "counts": dict(totals),
        "report_count_mutation_rejected": True,
    }
    if args.evidence is not None:
        evidence = json.loads(args.evidence.read_text())
        source = Path(__file__)
        dependency = source.with_name("verify_mba_address_matrix_delta.py")
        require(evidence["verifier_sha256"] == digest(source.read_bytes()), "verifier pin")
        require(evidence["dependency_sha256"] == digest(dependency.read_bytes()), "dependency pin")
        require(evidence["result"] == result, "recorded result")
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print("MBA strict cache gate matrix: pass")


if __name__ == "__main__":
    main()
