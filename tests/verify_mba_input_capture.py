"""Audit transient matcher input replay, retention and local definition facts."""

import argparse
from collections import Counter
import copy
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from mba_match_replay import catalog, capture, local_constants, match, replay, validate_inputs
from run_protected_mba_corpus import ROOT, check_probe
from run_vmp_corpus import digest
from verify_mba_matching_capture import compare, diagnostic, local, profiles, require, rows


def corruptions(sample, model, patterns):
    rejected = []

    def trial(label, edit):
        wrong = copy.deepcopy(sample)
        edit(wrong)
        try:
            capture(wrong["input"], model)
            replay(wrong, patterns, model)
        except (ValueError, KeyError, IndexError):
            rejected.append(label)
        else:
            raise ValueError("corrupted match input accepted: " + label)

    trial("changed root opcode", lambda s: s["input"]["root"].__setitem__(3, model["ops"]["nop"]))
    trial("changed root width", lambda s: s["input"]["root"].__setitem__(1, 16))
    trial("changed opcode bucket", lambda s: s.update(indexed_patterns=s["indexed_patterns"] + 1))
    trial("changed structural count", lambda s: s.update(structural_matches=1))
    trial("changed failed rule", lambda s: s.update(rule="absent"))
    trial(
        "changed actual prefix count",
        lambda s: s.update(
            reason=(
                s["reason"].replace("nodes=2", "nodes=3")
                if "nodes=2" in s["reason"]
                else "match_failed;kind=node_required;p=R;c=R;nodes=999;cut=0"
            )
        ),
    )
    trial("invented pointer field", lambda s: s["input"].update(host_pointer=1))
    trial("false prefix frontier", lambda s: s["input"].update(prefix_status="unrestricted"))
    trial(
        "prefix head overflow", lambda s: s["input"].update(prefix=[s["input"]["enclosing"]] * 65)
    )
    return rejected


def audit(current_path, prior_path):
    current, prior = [json.loads(p.read_text()) for p in (current_path, prior_path)]
    require(
        current["matcher_inputs"] and current["matching_diagnostics"],
        "missing matcher input attribution",
    )
    require(
        all(digest(ROOT / p) == sha for p, sha in current["source_sha256"].items()),
        "current capture source changed",
    )
    now, old = profiles(current), profiles(prior)
    require(set(now) == set(old), "profile population changed")
    counts, statuses, frontiers, outcomes, resolutions = [Counter() for _ in range(5)]
    findings, first = [], None
    for key, probe in now.items():
        check_probe(
            probe,
            {r["name"]: hex(r["entry"]) for r in probe["entries"]},
            key[2],
            False,
            False,
            True,
        )
        counts.update(compare(old[key], probe))
        model, patterns = catalog(probe["matcher_catalog"], probe["rule_catalog"]["names"], key[2])
        for before, row in zip(rows(old[key]), rows(probe)):
            for prior_stage, stage in zip(before["stages"], row["stages"]):
                stats = stage["statistics"]
                require(
                    diagnostic(prior_stage, before, key[2]) == diagnostic(stage, row, key[2]),
                    "historical diagnostics changed",
                )
                outcomes.update(stats["matching"]["counts"])
                inputs = stats["matching_inputs"]
                samples = validate_inputs(
                    inputs, stats, row["entry"], stage["maturity"], key[2], model, patterns
                )
                statuses.update(inputs["counts"])
                counts["events"] += inputs["events"]
                counts["input_unrecorded"] += inputs["unrecorded"]
                for sample in samples:
                    counts["input_keys"] += 1
                    counts["retained_events"] += sample["count"]
                    if sample["capture_status"] != "complete":
                        continue
                    counts["replayed_keys"] += 1
                    counts["replayed_events"] += sample["count"]
                    value = sample["input"]
                    frontiers[value["prefix_status"]] += sample["count"]
                    if sample["outcome"] != "structural_mismatch":
                        continue
                    if first is None:
                        first = sample, model, patterns
                    transformed, facts = local_constants(value, model)
                    if not facts:
                        continue
                    hits = [
                        name
                        for name, pattern in patterns
                        if pattern[1] == transformed[3] and match(pattern, transformed, model)[0]
                    ]
                    resolutions["keys_with_local_constants"] += 1
                    resolutions["events_with_local_constants"] += sample["count"]
                    resolutions["keys_with_counterfactual_structural_match"] += bool(hits)
                    resolutions["events_with_counterfactual_structural_match"] += (
                        sample["count"] if hits else 0
                    )
                    findings.append(
                        {
                            "architecture": key[0],
                            "label": key[1],
                            "entry": row["entry"],
                            "requested_maturity": stage["maturity"],
                            "sample": sample,
                            "local_byte_facts": facts,
                            "counterfactual_structural_rules": hits,
                        }
                    )
    require(first is not None, "no replayed structural failures")
    require(
        counts["retained_events"] + counts["input_unrecorded"] == counts["events"],
        "bounded input accounting",
    )
    measured = [r["measurement"] for r in current["runs"]]
    return {
        "passed": True,
        "counts": dict(counts),
        "capture_statuses": dict(statuses),
        "prefix_frontiers": dict(frontiers),
        "outcomes": dict(outcomes),
        "local_definition_results": dict(resolutions),
        "local_definition_findings": findings,
        "corruption_controls": corruptions(*first),
        "max_process_elapsed_ns": max(m["elapsed_ns"] for m in measured),
        "max_process_peak_resident_bytes": max(m["peak_resident_bytes"] for m in measured),
        "current_report_sha256": digest(current_path),
        "prior_report_sha256": digest(prior_path),
        "scope": "actual retained match-time inputs and independent structural replay; rule-specific predicates/typed replacement proofs are not independently replayed; conservative consecutive local byte definitions under normal completion and a pure enclosing expression; counterfactual structure is not a demonstrated simplification, absent identity, full reaching-definition/alias proof or protected recovery gain",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--prior", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {"passed": False}
    try:
        paths = [
            local(p)
            for p in (args.current, args.prior, Path(__file__), Path("tests/mba_match_replay.py"))
        ]
        pins = {p: digest(p) for p in paths}
        result = audit(paths[0], paths[1])
        require(all(digest(p) == sha for p, sha in pins.items()), "audit input changed")
    except Exception as error:
        result["failure"] = type(error).__name__ + ": " + str(error)
    result["verifier_sha256"] = digest(Path(__file__))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "local_definition_findings"}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
