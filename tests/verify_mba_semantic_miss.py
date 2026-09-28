"""Check actual rejected primitive reductions using typed SMT and integer witnesses."""

import argparse
from collections import Counter
import copy
import gzip
import hashlib
import json
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
from mba_match_replay import catalog, validate_inputs
from mba_matching_diagnostics import require
from mba_semantic_miss import (
    CONTRACTS,
    Unsupported,
    constraint_reduction,
    engine_provenance,
    primitive_reductions,
    verify_primitive_witness,
    verify_constraint_witness,
)
from run_vmp_corpus import digest
from verify_mba_matching_capture import local, profiles, rows

SOURCES = (
    "tests/mba_semantic_miss.py",
    "tests/verify_mba_semantic_miss.py",
    "tests/mba_match_replay.py",
    "tests/mba_matching_diagnostics.py",
    "tests/verify_mba_matching_capture.py",
    "src/deobf/rules/rules_sub.h",
    "src/deobf/rules/rules_and.h",
    "src/deobf/rules/rules_misc.h",
    "src/deobf/rules/pattern_rule.cpp",
    "src/deobf/rules/rule_verifier.cpp",
)


def controls(root, model, proof, root_iprops=None):
    query = next(
        q for q in proof["queries"] if q["state"] == "sat" and q["target"] != "any_constant"
    )
    rejected = []
    for name, edit in (
        (
            "changed computed result",
            lambda q: q["counterexample"].update(result=q["counterexample"]["result"] ^ 1),
        ),
        (
            "changed proposed result",
            lambda q: q["counterexample"].update(proposed=q["counterexample"]["proposed"] ^ 1),
        ),
        (
            "lost snapshot byte",
            lambda q: q["counterexample"]["bytes"].pop(next(iter(q["counterexample"]["bytes"]))),
        ),
        (
            "out-of-domain byte",
            lambda q: q["counterexample"]["bytes"].update(
                {next(iter(q["counterexample"]["bytes"])): 256}
            ),
        ),
        ("invented operand", lambda q: q["counterexample"]["operands"].update(host_pointer=0)),
        ("false solver state", lambda q: q.update(state="unknown")),
    ):
        wrong = copy.deepcopy(query)
        edit(wrong)
        try:
            verify_primitive_witness(root, model, wrong, root_iprops)
        except (ValueError, KeyError):
            rejected.append(name)
        else:
            raise ValueError("corrupted integer witness accepted: " + name)
    return rejected


def audit(report_path, timeout_ms, resource_limit, archive_path=None):
    report = json.loads(report_path.read_text())
    require(report["passed"] and report["matcher_inputs"], "complete actual input matrix required")
    root_dir = Path(__file__).resolve().parent.parent
    if archive_path is None:
        require(
            all(digest(root_dir / p) == h for p, h in report["source_sha256"].items()),
            "captured matcher source changed",
        )
    else:
        with gzip.open(archive_path, "rt") as stream:
            archive = json.load(stream)
        captured = archive["files"]
        report_key = str(report_path.relative_to(root_dir))
        require(
            hashlib.sha256(captured[report_key]["text"].encode()).hexdigest()
            == digest(report_path),
            "captured report differs from source archive",
        )
        require(
            all(
                hashlib.sha256(captured[p]["text"].encode()).hexdigest() == h
                for p, h in report["source_sha256"].items()
            ),
            "captured matcher source differs from source archive",
        )
    counts, classifications, gates, unsupported, solver_states = [Counter() for _ in range(5)]
    findings, proofs, proof_keys = [], [], {}
    first = None
    sdk_models = []
    for key, probe in profiles(report).items():
        require(key[0] in ("x86_64", "i386"), "byte-order domain")
        model, patterns = catalog(probe["matcher_catalog"], probe["rule_catalog"]["names"], key[2])
        if model not in sdk_models:
            sdk_models.append(model)
        for row in rows(probe):
            for stage in row["stages"]:
                stats = stage["statistics"]
                inventory = stats["matching_inputs"]
                samples = validate_inputs(
                    inventory, stats, row["entry"], stage["maturity"], key[2], model, patterns
                )
                counts["events"] += inventory["events"]
                counts["unrecorded"] += inventory["unrecorded"]
                for sample in samples:
                    counts["keys"] += 1
                    counts["retained_events"] += sample["count"]
                    gates[sample["outcome"]] += sample["count"]
                    if sample["capture_status"] != "complete":
                        classifications["capture_unavailable"] += sample["count"]
                        continue
                    if sample["outcome"] not in (
                        "structural_mismatch",
                        "no_indexed_pattern",
                        "constant_constraint",
                    ):
                        classifications["existing_terminal_outcome"] += sample["count"]
                        continue
                    root = sample["input"]["root"]
                    root_iprops = sample["input"].get("root_iprops")
                    # Cache only the semantic root inputs and exact SDK tags.
                    cache_key = json.dumps(
                        [
                            model,
                            root,
                            root_iprops,
                            sample["outcome"],
                            sample["rule"],
                            sample["reason"],
                        ],
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    if cache_key not in proof_keys:
                        value = primitive_reductions(
                            root, model, timeout_ms, resource_limit, root_iprops
                        )
                        if (
                            sample["outcome"] == "constant_constraint"
                            and sample["rule"] in CONTRACTS
                        ):
                            operation = CONTRACTS[sample["rule"]][0]
                            template = next(p for name, p in patterns if name == sample["rule"])
                            require(
                                template
                                == [
                                    "n",
                                    model["ops"][operation],
                                    ["v", "x_0"],
                                    ["k", 0, "c_minus_1"],
                                ],
                                "actual rule family template changed",
                            )
                            try:
                                value["rejected_rule_instance"] = constraint_reduction(
                                    sample, model, timeout_ms, resource_limit
                                )
                            except Unsupported as error:
                                value["rejected_rule_instance"] = {
                                    "status": "unsupported",
                                    "reason": str(error),
                                }
                        proof_keys[cache_key] = len(proofs)
                        proofs.append(value)
                    proof_id = proof_keys[cache_key]
                    proof = proofs[proof_id]
                    classifications[proof["status"]] += sample["count"]
                    if proof["status"] == "unsupported":
                        unsupported[proof["reason"]] += sample["count"]
                    else:
                        for query in proof["queries"]:
                            solver_states[query["state"]] += sample["count"]
                            if query["state"] == "sat":
                                verify_primitive_witness(root, model, query, root_iprops)
                                counts["integer_witness_replays"] += sample["count"]
                        if (
                            first is None
                            and proof["status"] == "primitive_reduction_refuted"
                            and any(
                                q["state"] == "sat" and q["target"] != "any_constant"
                                for q in proof["queries"]
                            )
                        ):
                            first = root, model, proof, root_iprops
                    instance = proof.get("rejected_rule_instance")
                    if instance is not None:
                        counts["constraint_instance_" + instance["status"]] += sample["count"]
                        if instance["status"] == "sat":
                            verify_constraint_witness(sample, model, instance)
                            counts["constraint_integer_witness_replays"] += sample["count"]
                    findings.append(
                        {
                            "architecture": key[0],
                            "label": key[1],
                            "entry": row["entry"],
                            "requested_maturity": stage["maturity"],
                            "sample": sample,
                            "proof": proof_id,
                        }
                    )
    require(
        sum(classifications.values()) == counts["retained_events"]
        and counts["retained_events"] + counts["unrecorded"] == counts["events"],
        "semantic inventory accounting",
    )
    require(first is not None, "no actual primitive counterexamples")
    return {
        "passed": True,
        "counts": dict(counts),
        "retained_outcomes": dict(gates),
        "classifications": dict(classifications),
        "unsupported_reasons": dict(unsupported),
        "weighted_solver_states": dict(solver_states),
        "sdk_models": sdk_models,
        "proofs": proofs,
        "findings": findings,
        "corruption_controls": controls(*first),
        "scope": "actual retained typed scalar value snapshots with at most one arithmetic child: refute reduction to any constant or current operand and check three captured rejected-rule instances; values may be unreachable in the native program; different storage classes have no inferred alias relation; no full-state/CFG, fault, side-effect, missing-identity completeness, live rewrite or protected recovery claim",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--timeout-ms", type=int, default=250)
    parser.add_argument("--resource-limit", type=int, default=100000)
    args = parser.parse_args()
    result = {"passed": False}
    start = time.monotonic_ns()
    try:
        report_path = local(args.report)
        archive_path = local(args.archive) if args.archive is not None else None
        pins = {p: digest(p) for p in (*SOURCES, str(report_path))}
        if archive_path is not None:
            pins[str(archive_path)] = digest(archive_path)
        engine = engine_provenance()
        result = audit(report_path, args.timeout_ms, args.resource_limit, archive_path)
        require(all(digest(p) == h for p, h in pins.items()), "semantic audit inputs changed")
        require(engine == engine_provenance(), "semantic engine changed")
        result.update(
            engine=engine,
            source_sha256={p: pins[p] for p in SOURCES},
            report_sha256=pins[str(report_path)],
            report=str(report_path.relative_to(Path(__file__).resolve().parent.parent)),
        )
        if archive_path is not None:
            result["capture_archive"] = str(
                archive_path.relative_to(Path(__file__).resolve().parent.parent)
            )
            result["capture_archive_sha256"] = pins[str(archive_path)]
    except Exception as error:
        result["failure"] = type(error).__name__ + ": " + str(error)
    result.update(
        elapsed_ns=time.monotonic_ns() - start,
        timeout_ms=args.timeout_ms,
        resource_limit=args.resource_limit,
    )
    local(args.output).write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                k: v
                for k, v in result.items()
                if k not in ("proofs", "findings", "sdk_models", "source_sha256")
            }
        )
    )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
