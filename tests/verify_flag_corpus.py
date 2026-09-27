"""Audit flag admissions and unchanged SDK trees in the protected matrix."""

import argparse
from collections import Counter
import json
from pathlib import Path

from mba_match_replay import catalog, validate_inputs
from run_protected_mba_corpus import ROOT, check_probe
from run_vmp_corpus import digest
from verify_mba_matching_capture import diagnostic, profiles, require, rows, tree


def audit(current_path, baseline_path):
    current, baseline = [json.loads(p.read_text()) for p in (current_path, baseline_path)]
    require(
        all(digest(ROOT / p) == h for p, h in current["source_sha256"].items()),
        "current source changed",
    )
    for field in (
        "ida_sha256",
        "ida_components_sha256",
        "native_analysis_disabled",
        "matcher_inputs",
    ):
        require(current[field] == baseline[field], "paired SDK profile: " + field)
    now, prior = profiles(current), profiles(baseline)
    require(set(now) == set(prior), "paired profile population")
    old_runs = {(r["architecture"], r["label"], r["disabled"]): r for r in baseline["runs"]}
    new_runs = {(r["architecture"], r["label"], r["disabled"]): r for r in current["runs"]}
    counts, before_outcomes, after_outcomes, inputs = [Counter() for _ in range(4)]
    admissions = []
    for key, capture in now.items():
        require(
            old_runs[key]["binary_sha256"] == new_runs[key]["binary_sha256"],
            "native binary changed",
        )
        entries = {r["name"]: hex(r["entry"]) for r in capture["entries"]}
        check_probe(capture, entries, key[2], False, False, True)
        model, patterns = catalog(
            capture["matcher_catalog"], capture["rule_catalog"]["names"], key[2]
        )
        left, right = list(rows(prior[key])), list(rows(capture))
        require(len(left) == len(right), "native row population changed")
        per_profile = 0
        for old, new in zip(left, right):
            counts["native_rows"] += 1
            for field in (
                "entry",
                "owner",
                "status",
                "native_chunks",
                "native_bytes_unchanged",
                "chunks_after",
                "entry_bytes",
                "direct_target",
            ):
                require(old.get(field) == new.get(field), "native ownership or bytes changed")
            require(len(old["stages"]) == len(new["stages"]), "SDK stage population changed")
            for a, b in zip(old["stages"], new["stages"]):
                counts["stages"] += 1
                for field in ("maturity", "status", "error_code", "error_ea", "blocks"):
                    require(
                        tree(a.get(field)) == tree(b.get(field)),
                        "SDK outcome or typed tree changed",
                    )
                counts["captured"] += b["status"] == "captured"
                for field in (
                    "successful_matches",
                    "instance_disproved",
                    "instance_unsupported",
                    "instance_unknown",
                    "rejection_reasons",
                    "unrecorded_rejections",
                ):
                    require(
                        a["statistics"][field] == b["statistics"][field],
                        "verifier rejection or catalog application changed",
                    )
                delta = b["statistics"]["instance_verified"] - a["statistics"]["instance_verified"]
                require(delta >= 0 and (not key[2] or delta == 0), "invalid flag admission delta")
                per_profile += delta
                before_outcomes.update(diagnostic(a, old, key[2])["counts"])
                after_outcomes.update(diagnostic(b, new, key[2])["counts"])
                stats = b["statistics"]
                inventory = stats["matching_inputs"]
                samples = validate_inputs(
                    inventory, stats, new["entry"], b["maturity"], key[2], model, patterns
                )
                inputs["events"] += inventory["events"]
                inputs["unrecorded"] += inventory["unrecorded"]
                for sample in samples:
                    inputs["keys"] += 1
                    inputs["retained_events"] += sample["count"]
                    if sample["capture_status"] == "complete":
                        require(
                            type(sample["input"].get("root_iprops")) is int,
                            "missing original instruction metadata",
                        )
        if per_profile:
            admissions.append(
                {
                    "architecture": key[0],
                    "label": key[1],
                    "additional_verified_instances": per_profile,
                }
            )
            counts["additional_verified_instances"] += per_profile
    deltas = {k: after_outcomes[k] - before_outcomes[k] for k in before_outcomes | after_outcomes}
    require(
        deltas.get("no_indexed_pattern") == -counts["additional_verified_instances"],
        "flag/catalog attempt accounting",
    )
    require(
        all(v == 0 for k, v in deltas.items() if k != "no_indexed_pattern"),
        "unrelated matcher outcomes changed",
    )
    return {
        "passed": True,
        "counts": dict(counts),
        "inputs": dict(inputs),
        "before_outcomes": dict(before_outcomes),
        "after_outcomes": dict(after_outcomes),
        "outcome_deltas": deltas,
        "admissions": admissions,
        "current_report_sha256": digest(current_path),
        "baseline_report_sha256": digest(baseline_path),
        "scope": "matched selected native rows and captured typed trees remain equal; extra transient verified flag admissions reduce catalog attempts; no protected recovery or whole-program semantic gain established",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("current", "baseline", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.current, args.baseline)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
