"""Audit actual catalog outcomes, native source ranges and capture preservation."""

import argparse
from collections import Counter
import copy
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from mba_matching_diagnostics import validate_matching
from run_protected_mba_corpus import ROOT, check_probe
from run_vmp_corpus import digest


def require(value, reason):
    if not value:
        raise ValueError(reason)


def local(path):
    path = path.resolve()
    require(path.is_relative_to(ROOT), "audit artifact outside repository")
    return path


def tree(value):
    if isinstance(value, dict):
        return {k: tree(v) for k, v in value.items() if k not in ("text", "text_truncated")}
    if isinstance(value, list):
        return [tree(v) for v in value]
    return value


def rows(capture):
    for outer in capture["entries"]:
        yield outer
        if outer["body"] is not None:
            yield outer["body"]


def diagnostic(stage, row, disabled):
    stats = stage["statistics"]
    value = stats["matching"]
    validate_matching(value, stats, row["entry"], stage["maturity"], disabled)
    for sample in value["samples"]:
        require(
            sample["source"] == 2**64 - 1
            or any(c["start"] <= sample["source"] < c["end"] for c in row["native_chunks"]),
            "matching source outside selected native chunks",
        )
    return value


def profiles(report):
    require(report["passed"] and len(report["runs"]) == 40, "matrix population")
    result = {}
    for run in report["runs"]:
        key = run["architecture"], run["label"], run["disabled"]
        require(key not in result, "duplicate matrix profile")
        for name, sha in run["artifact_sha256"].items():
            require(digest(local(ROOT / name)) == sha, "changed matrix capture")
        path = next(n for n in run["artifact_sha256"] if n.endswith("/protected_mba.json"))
        result[key] = json.loads((ROOT / path).read_text())
    return result


def compare(before, after):
    counts = Counter()
    a, b = list(rows(before)), list(rows(after))
    require(len(a) == len(b), "changed native row population")
    for left, right in zip(a, b):
        counts["native_rows"] += 1
        for key in ("entry", "owner", "status", "native_chunks", "native_bytes_unchanged"):
            require(left.get(key) == right.get(key), "changed native ownership or bytes")
        require(len(left["stages"]) == len(right["stages"]), "changed SDK stage population")
        for old, new in zip(left["stages"], right["stages"]):
            counts["stages"] += 1
            for key in ("maturity", "status", "error_code", "error_ea", "blocks"):
                require(
                    tree(old.get(key)) == tree(new.get(key)), "changed SDK outcome or typed tree"
                )
            counts["captured"] += new["status"] == "captured"
            for key in (
                "total_matches",
                "successful_matches",
                "instance_verified",
                "instance_disproved",
                "instance_unsupported",
                "instance_unknown",
                "rejection_reasons",
                "unrecorded_rejections",
            ):
                require(
                    old["statistics"][key] == new["statistics"][key], "changed verifier outcome"
                )
    return counts


def corruptions(stage, row):
    rejected = []

    def trial(name, edit):
        wrong = copy.deepcopy(stage)
        edit(wrong["statistics"]["matching"])
        try:
            diagnostic(wrong, row, False)
        except (ValueError, KeyError):
            rejected.append(name)
            return
        raise ValueError("corrupted matching diagnostic accepted: " + name)

    trial("lost event", lambda d: d.update(events=d["events"] + 1))
    trial("false native owner", lambda d: d["samples"][0].update(entry=0))
    trial("false native source", lambda d: d["samples"][0].update(source=0))
    trial("false maturity", lambda d: d["samples"][0].update(maturity=1000))
    trial("false width", lambda d: d["samples"][0].update(width_bytes=16))
    trial("false phase count", lambda d: d["samples"][0].update(structural_matches=10**9))
    trial("false retained count", lambda d: d["samples"][0].update(count=0))
    trial("false text quota", lambda d: d["samples"][0].update(reason="x" * 257))
    trial("duplicate sample", lambda d: d["samples"].append(copy.deepcopy(d["samples"][0])))
    return rejected


def audit(current_path, baseline_path):
    current, baseline = [json.loads(p.read_text()) for p in (current_path, baseline_path)]
    require(current["matching_diagnostics"], "matching API not attributed")
    require(
        all(digest(ROOT / name) == sha for name, sha in current["source_sha256"].items()),
        "current source changed",
    )
    enabled, old = profiles(current), profiles(baseline)
    require(set(enabled) == set(old), "changed matrix profile population")
    counts, outcomes, measurements = Counter(), Counter(), []
    sample_stage = None
    for key, capture in enabled.items():
        entries = {row["name"]: hex(row["entry"]) for row in capture["entries"]}
        check_probe(capture, entries, key[2], False, False, True)
        counts.update(compare(old[key], capture))
        per_run = Counter()
        for row in rows(capture):
            for stage in row["stages"]:
                value = diagnostic(stage, row, key[2])
                outcomes.update(value["counts"])
                per_run.update(value["counts"])
                counts["matching_events"] += value["events"]
                counts["unrecorded_events"] += value["unrecorded"]
                counts["sample_keys"] += len(value["samples"])
                counts["retained_events"] += sum(s["count"] for s in value["samples"])
                if value["samples"] and sample_stage is None:
                    sample_stage = stage, row
        measurements.append(
            {"architecture": key[0], "label": key[1], "disabled": key[2], "counts": dict(per_run)}
        )
    require(sample_stage is not None, "no actual matching samples")
    require(
        counts["retained_events"] + counts["unrecorded_events"] == counts["matching_events"],
        "aggregate retention accounting",
    )
    return {
        "passed": True,
        "counts": dict(counts),
        "outcomes": dict(outcomes),
        "profiles": measurements,
        "corruption_controls": corruptions(*sample_stage),
        "current_report_sha256": digest(current_path),
        "baseline_report_sha256": digest(baseline_path),
        "scope": "actual catalog-attempt outcomes and native source-range attribution; preserved recorded CFG/typed values and verifier outcomes; no missing-identity, reaching-definition, alias, full-body or ISA-equivalence claim",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {"passed": False}
    try:
        inputs = [local(p) for p in (args.current, args.baseline, Path(__file__))]
        pins = {p: digest(p) for p in inputs}
        result = audit(inputs[0], inputs[1])
        require(all(digest(p) == sha for p, sha in pins.items()), "audit input changed")
    except Exception as error:
        result["failure"] = type(error).__name__ + ": " + str(error)
    result["verifier_sha256"] = digest(Path(__file__))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "profiles"}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
