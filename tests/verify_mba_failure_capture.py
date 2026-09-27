"""Audit actual failed-branch witnesses and unchanged protected SDK outcomes."""

import argparse
from collections import Counter
import copy
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from mba_matching_diagnostics import parse_match_failure
from run_protected_mba_corpus import ROOT, check_probe
from run_vmp_corpus import digest
from verify_mba_matching_capture import compare, diagnostic, local, profiles, require, rows


def witness(sample, names):
    if sample["outcome"] == "no_indexed_pattern":
        require(
            sample["reason"] == "root_opcode_unindexed;opcode=" + str(sample["opcode"])
            and not sample["rule"],
            "unindexed root witness",
        )
        return {"kind": "root_opcode_unindexed"}
    require(sample["outcome"] == "structural_mismatch", "failed branch outcome")
    require(sample["rule"] in names, "failed pattern outside actual certified catalog")
    return parse_match_failure(sample["reason"])


def corruptions(sample, names):
    rejected = []

    def trial(label, edit):
        wrong = copy.deepcopy(sample)
        edit(wrong)
        try:
            witness(wrong, names)
        except (ValueError, KeyError):
            rejected.append(label)
            return
        raise ValueError("corrupted witness accepted: " + label)

    def reason(text):
        return lambda value: value.update(reason=text)

    trial("lost failed rule", lambda s: s.update(rule=""))
    trial("unknown failed rule", lambda s: s.update(rule="absent_from_catalog"))
    trial("unknown cause", reason("match_failed;kind=alias_proven;p=R;c=R;nodes=1;cut=0"))
    trial("wrong path alphabet", reason("match_failed;kind=node_required;p=X;c=R;nodes=1;cut=0"))
    trial(
        "path quota",
        reason("match_failed;kind=node_required;p=" + "L" * 65 + ";c=R;nodes=65;cut=1"),
    )
    trial("path depth mismatch", reason("match_failed;kind=node_required;p=LR;c=R;nodes=2;cut=0"))
    trial("prefix before path", reason("match_failed;kind=node_required;p=LR;c=RR;nodes=1;cut=0"))
    trial("false truncation", reason("match_failed;kind=node_required;p=R;c=R;nodes=1;cut=1"))
    trial("missing numeric fields", reason("match_failed;kind=opcode;p=R;c=R;nodes=1;cut=0"))
    trial(
        "invented frame pointers",
        reason("match_failed;kind=frame_owner;p=R;c=R;nodes=1;e=0x1;a=0x2;cut=0"),
    )
    trial(
        "equal differing fields",
        reason("match_failed;kind=opcode;p=R;c=R;nodes=1;e=0x1;a=0x1;cut=0"),
    )
    trial(
        "noncanonical integer",
        reason("match_failed;kind=opcode;p=R;c=R;nodes=1;e=0x01;a=0x2;cut=0"),
    )
    trial(
        "prefix overflow",
        reason("match_failed;kind=node_required;p=R;c=R;nodes=18446744073709551616;cut=0"),
    )
    wrong = {
        "outcome": "no_indexed_pattern",
        "opcode": 9,
        "rule": "",
        "reason": "root_opcode_unindexed;opcode=8",
    }
    try:
        witness(wrong, names)
    except ValueError:
        rejected.append("false unindexed opcode")
    else:
        raise ValueError("corrupted unindexed opcode accepted")
    return rejected


def audit(current_path, baseline_path):
    current, baseline = [json.loads(path.read_text()) for path in (current_path, baseline_path)]
    require(current["matching_diagnostics"], "missing matching diagnostics")
    require(
        all(digest(ROOT / name) == sha for name, sha in current["source_sha256"].items()),
        "current capture source changed",
    )
    now, old = profiles(current), profiles(baseline)
    require(set(now) == set(old), "changed profile population")
    counts, outcomes, kinds, rules, opcodes = [Counter() for _ in range(5)]
    attributed, first, catalog = [], None, None
    for key, capture in now.items():
        entries = {row["name"]: hex(row["entry"]) for row in capture["entries"]}
        check_probe(capture, entries, key[2], False, False, True)
        counts.update(compare(old[key], capture))
        inventory = capture["rule_catalog"]
        names = set(inventory["names"])
        require(
            inventory["registered"] == len(names)
            and inventory["verified"] == (0 if key[2] else len(names))
            and inventory["rejected"] == 0,
            "enabled catalog not wholly certified or disabled catalog initialized",
        )
        if catalog is None:
            catalog = sorted(names)
        require(sorted(names) == catalog, "changed catalog population")
        for before, row in zip(rows(old[key]), rows(capture)):
            for previous, stage in zip(before["stages"], row["stages"]):
                value = diagnostic(stage, row, key[2])
                prior = diagnostic(previous, before, key[2])
                require(
                    value["counts"] == prior["counts"] and value["events"] == prior["events"],
                    "changed terminal catalog outcomes",
                )
                outcomes.update(value["counts"])
                counts["events"] += value["events"]
                counts["unrecorded"] += value["unrecorded"]
                counts["retained_events"] += sum(s["count"] for s in value["samples"])
                for sample in value["samples"]:
                    if sample["outcome"] not in ("no_indexed_pattern", "structural_mismatch"):
                        continue
                    detail = witness(sample, names)
                    kinds[detail["kind"]] += sample["count"]
                    counts["witness_keys"] += 1
                    counts["witness_events"] += sample["count"]
                    if sample["outcome"] == "structural_mismatch":
                        rules[sample["rule"]] += sample["count"]
                        counts["commuted_witness_keys"] += (
                            detail["pattern_path"] != detail["candidate_path"]
                        )
                        counts["truncated_witness_keys"] += detail["path_truncated"]
                        if first is None:
                            first = sample, names
                    else:
                        opcodes[str(sample["opcode"])] += sample["count"]
                    attributed.append(
                        {
                            "architecture": key[0],
                            "label": key[1],
                            "entry": row["entry"],
                            "requested_maturity": stage["maturity"],
                            "sample": sample,
                            "parsed_witness": detail,
                        }
                    )
    require(first is not None, "no actual structural witnesses")
    require(
        counts["retained_events"] + counts["unrecorded"] == counts["events"], "retention accounting"
    )
    measures = [run["measurement"] for run in current["runs"]]
    return {
        "passed": True,
        "counts": dict(counts),
        "outcomes": dict(outcomes),
        "retained_witness_kinds": dict(kinds),
        "retained_failed_rules": dict(rules),
        "retained_unindexed_opcodes": dict(opcodes),
        "catalog_names": catalog,
        "max_process_elapsed_ns": max(m["elapsed_ns"] for m in measures),
        "max_process_peak_resident_bytes": max(m["peak_resident_bytes"] for m in measures),
        "witnesses": attributed,
        "corruption_controls": corruptions(*first),
        "current_report_sha256": digest(current_path),
        "baseline_report_sha256": digest(baseline_path),
        "scope": "one actual longest-prefix failed matcher branch per retained structural event, plus unindexed roots; unchanged recorded native owners/bytes, CFG/typed values and terminal outcomes; final SDK trees do not reconstruct transient matcher inputs; no complete causal, reaching-definition, alias relation, missing-identity or protected recovery claim",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {"passed": False}
    try:
        inputs = [
            local(p)
            for p in (
                args.current,
                args.baseline,
                Path(__file__),
                Path("tests/mba_matching_diagnostics.py"),
            )
        ]
        pins = {p: digest(p) for p in inputs}
        result = audit(inputs[0], inputs[1])
        require(all(digest(p) == sha for p, sha in pins.items()), "audit input changed")
    except Exception as error:
        result["failure"] = type(error).__name__ + ": " + str(error)
    result["verifier_sha256"] = digest(Path(__file__))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ("witnesses", "catalog_names")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
