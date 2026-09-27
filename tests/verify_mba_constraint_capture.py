"""Recheck recorded all-ones constraints and give independent rule-family counterexamples."""

import argparse
from collections import Counter
import copy
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from mba_matching_diagnostics import parse_constant_failure
from run_protected_mba_corpus import ROOT
from run_vmp_corpus import digest
from verify_mba_matching_capture import compare, diagnostic, local, profiles, require, rows

# Primary contracts: rules_sub.h, rules_and.h, rules_misc.h; SDK opcode enum.
# These predicates evaluate the rule family with an unconstrained x. They do
# not assert that the concrete program's x has every possible value.
CONTRACTS = {"Sub1_FactorRule_2": (12, "add"), "And_Rule_3": (20, "and"), "Mul_Rule_4": (14, "mul")}


def witness(sample):
    require(sample["outcome"] == "constant_constraint", "constant outcome")
    require(sample["rule"] in CONTRACTS, "unsupported failed-rule contract")
    opcode, operation = CONTRACTS[sample["rule"]]
    require(sample["opcode"] == opcode, "failed rule root opcode")
    bindings, omitted = parse_constant_failure(sample["reason"])
    require(omitted == 0, "incomplete numeric binding capture")
    selected = [b for b in bindings if b["name"] == "c_minus_1"]
    require(len(selected) == 1, "all-ones binding identity")
    value = selected[0]
    require(value["width_bytes"] in (1, 2, 4, 8), "unsupported constant width")
    bits = 8 * value["width_bytes"]
    mask = (1 << bits) - 1
    constant = value["value"] & mask
    require(constant != mask, "recorded constant satisfies the rejected constraint")
    if operation == "and":
        x = mask ^ constant
        original, proposed = x & constant, x
    elif operation == "add":
        x = 0
        original, proposed = constant, mask
    else:
        x = 1
        original, proposed = constant, mask
    require(original != proposed, "vacuous rule-family counterexample")
    return {
        "bits": bits,
        "constant": hex(constant),
        "x": hex(x),
        "original": hex(original),
        "proposed": hex(proposed),
        "scope": "unconstrained-x rule family; not the concrete microcode instance",
    }


def controls(sample):
    rejected = []

    def trial(name, edit):
        wrong = copy.deepcopy(sample)
        edit(wrong)
        try:
            witness(wrong)
        except (ValueError, KeyError):
            rejected.append(name)
            return
        raise ValueError("corrupted constraint accepted: " + name)

    bindings, _ = parse_constant_failure(sample["reason"])
    selected = next(b for b in bindings if b["name"] == "c_minus_1")
    width = selected["width_bytes"]
    trial("lost rule", lambda s: s.update(rule=""))
    trial("unknown rule", lambda s: s.update(rule="invented_identity"))
    trial("wrong opcode", lambda s: s.update(opcode=0))
    trial("lost binding", lambda s: s.update(reason="constant_check_failed;numeric=;omitted=0"))
    trial(
        "incomplete bindings", lambda s: s.update(reason="constant_check_failed;numeric=;omitted=1")
    )
    trial(
        "unknown width",
        lambda s: s.update(reason="constant_check_failed;numeric=c_minus_1:16:0x0;omitted=0"),
    )
    trial(
        "constraint actually satisfied",
        lambda s: s.update(
            reason=f"constant_check_failed;numeric=c_minus_1:{width}:0x{(1 << (width * 8)) - 1:x};omitted=0"
        ),
    )
    if width < 8:
        trial(
            "constraint satisfied after width truncation",
            lambda s: s.update(
                reason=f"constant_check_failed;numeric=c_minus_1:{width}:0x{(1 << 63) | ((1 << (width * 8)) - 1):x};omitted=0"
            ),
        )
    trial(
        "noncanonical value",
        lambda s: s.update(reason="constant_check_failed;numeric=c_minus_1:4:0x00;omitted=0"),
    )
    trial(
        "duplicate binding",
        lambda s: s.update(
            reason="constant_check_failed;numeric=c_minus_1:4:0x0,c_minus_1:4:0x0;omitted=0"
        ),
    )
    trial(
        "oversized name",
        lambda s: s.update(
            reason="constant_check_failed;numeric=c_minus_1_oversized_identifier:4:0x0;omitted=0"
        ),
    )
    return rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    current, baseline = local(args.current), local(args.baseline)
    a, b = profiles(json.loads(baseline.read_text())), profiles(json.loads(current.read_text()))
    require(a.keys() == b.keys(), "matrix profile population")
    preservation, attributed, sampled = Counter(), Counter(), Counter()
    witnesses = []
    omitted_events = events = constant_events = 0
    for key in sorted(a):
        preservation.update(compare(a[key], b[key]))
        architecture, label, disabled = key
        for row in rows(b[key]):
            for stage in row["stages"]:
                value = diagnostic(stage, row, disabled)
                events += value["events"]
                omitted_events += value["unrecorded"]
                constant_events += value["counts"]["constant_constraint"]
                for sample in value["samples"]:
                    if sample["outcome"] != "constant_constraint":
                        continue
                    result = witness(sample)
                    attributed[sample["rule"]] += sample["count"]
                    sampled[sample["rule"]] += 1
                    witnesses.append(
                        {
                            "architecture": architecture,
                            "label": label,
                            "sample": sample,
                            "witness": result,
                        }
                    )
    require(witnesses and set(attributed) == set(CONTRACTS), "measured constraint population")
    require(sum(attributed.values()) <= constant_events, "retained constraint accounting")
    rejected = controls(witnesses[0]["sample"])
    # Evaluate all 8-bit x/c combinations for the three family formulas.
    finite = 0
    for operation in ("add", "and", "mul"):
        for c in range(256):
            equivalent = True
            for x in range(256):
                old = (
                    (x + c) & 255
                    if operation == "add"
                    else x & c if operation == "and" else x * c & 255
                )
                new = (x - 1) & 255 if operation == "add" else x if operation == "and" else -x & 255
                equivalent &= old == new
                finite += 1
            require(equivalent == (c == 255), "independent finite all-ones requirement")
    source = [
        "tests/verify_mba_constraint_capture.py",
        "tests/mba_matching_diagnostics.py",
        "tests/verify_mba_matching_capture.py",
        "src/deobf/rules/rules_sub.h",
        "src/deobf/rules/rules_and.h",
        "src/deobf/rules/rules_misc.h",
        "../ida-sdk/src/include/hexrays.hpp",
    ]
    result = {
        "passed": True,
        "preservation": dict(preservation),
        "events": events,
        "constant_events": constant_events,
        "unrecorded_events": omitted_events,
        "attributed_events": dict(attributed),
        "sample_keys": dict(sampled),
        "unattributed_constant_events": constant_events - sum(attributed.values()),
        "rule_family_comparisons": finite,
        "corruptions_rejected": rejected,
        "scope": "final failed rule at the furthest gate; numeric contract and family counterexamples; no concrete-instance counterexample or complete causal classification",
        "source_sha256": {p: digest(ROOT / p) for p in source},
        "report_sha256": {str(p.relative_to(ROOT)): digest(p) for p in (current, baseline)},
        "witnesses": witnesses,
    }
    output = local(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                k: v
                for k, v in result.items()
                if k not in ("witnesses", "source_sha256", "report_sha256")
            }
        )
    )


if __name__ == "__main__":
    main()
