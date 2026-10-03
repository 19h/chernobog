"""Check the protected MBA audit delta against its retained predecessor."""

import argparse
from collections import Counter
import copy
import gzip
import hashlib
import json
from pathlib import Path
import tarfile

from mba_matching_diagnostics import require
from mba_semantic_miss import primitive_reductions

EXPECTED_TRANSITIONS = {
    (
        "unsupported nested value or explicit-load contract",
        "primitive_reduction_refuted",
        None,
    ): 231,
    ("nested arithmetic instruction contract", "primitive_reduction_refuted", None): 93,
    (
        "nested arithmetic instruction contract",
        "unsupported",
        "unsupported nested value or explicit-load contract",
    ): 23,
    ("nested arithmetic instruction contract", "unsupported", "nested arithmetic depth budget"): 1,
}
EXPECTED_STACK_ROOTS = {"xor": 124, "setz": 28, "setp": 28, "sets": 28}
EXPECTED_COMPUTED_OFFSET_ROOTS = {
    "xor": 14,
    "setz": 2,
    "setp": 2,
    "sets": 2,
    "add": 1,
    "or": 1,
    "bnot": 1,
}
EXPECTED_UNSUPPORTED = {
    "embedded_call_result": 133,
    "reserved_microregister": 117,
    "address_of_operand": 48,
    "combined_xdu": 26,
    "depth_budget": 1,
}
PRIOR_SHA256 = "1e898cdad7b4fa7876f24d9bd695a48da2010865e6b44713776d86d8872f318e"
REPORT_MEMBER = "build/mba-expanded-matrix-v2/protected_mba_analysis.json"
REPORT_SHA256 = "b2a56f35acaf3983203b993fb33a1eab858167163b77d4e3dc94554677412cba"
SOURCE_REVISION = "5756071e69c4626db2419bc0e45531bf21f5f2a2"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unsupported_taxonomy(current, model):
    tags, ops = model["mops"], model["ops"]
    counts = Counter()

    def values(node):
        if node is None:
            return
        if node[0] == "n":
            yield from values(node[4])
            yield from values(node[5])
        elif node[0] == "v":
            yield node[2]

    for finding in current["findings"]:
        proof = current["proofs"][finding["proof"]]
        if proof["status"] != "unsupported":
            continue
        sample = finding["sample"]
        root = sample["input"]["root"]
        reason = proof["reason"]
        captured = list(values(root))
        embedded = [value[4] for value in captured if value[0] == tags["d"]]
        if reason == "unsupported nested value or explicit-load contract":
            if any(ins[0] == 0x38 for ins in embedded):
                family = "embedded_call_result"
            else:
                raise ValueError("unclassified nested value")
        elif reason == "reserved or condition microregister needs a state contract":
            require(
                any(value[0] == tags["r"] and value[4] < 8 for value in captured),
                "reserved microregister descriptor",
            )
            family = "reserved_microregister"
        elif reason == "unsupported operand effect or storage":
            require(any(value[0] == tags["a"] for value in captured), "address-of descriptor")
            family = "address_of_operand"
        elif reason == "root instruction properties":
            require(
                sample["input"]["root_iprops"] == 0x800 and root[3] == ops["xdu"],
                "combined xdu descriptor",
            )
            family = "combined_xdu"
        elif reason == "nested arithmetic depth budget":
            family = "depth_budget"
        else:
            raise ValueError("unclassified unsupported reason")
        counts[family] += sample["count"]
    require(dict(counts) == EXPECTED_UNSUPPORTED, "unsupported descriptor inventory")
    return dict(sorted(counts.items()))


def reserved_counterfactual(current):
    model = current["sdk_models"][0]
    register_tag = model["mops"]["r"]
    checked = 0

    def rename(node):
        if not isinstance(node, list):
            return
        if len(node) == 5 and node[0] == register_tag and type(node[4]) is int and node[4] < 8:
            node[4] += 1 << 60
        for part in node:
            rename(part)

    for finding in current["findings"]:
        proof = current["proofs"][finding["proof"]]
        if proof.get("reason") != "reserved or condition microregister needs a state contract":
            continue
        require(proof["status"] == "unsupported", "reserved source was admitted")
        root = copy.deepcopy(finding["sample"]["input"]["root"])
        rename(root)
        replacement = primitive_reductions(
            root,
            model,
            root_iprops=finding["sample"]["input"].get("root_iprops"),
        )
        require(
            replacement["status"] == "primitive_reduction_refuted"
            and all(query["state"] == "sat" for query in replacement["queries"]),
            "unconstrained reserved-register counterfactual",
        )
        checked += finding["sample"]["count"]
    require(checked == 117, "reserved-register counterfactual inventory")
    return checked


def address_of_counterfactual(current):
    model = current["sdk_models"][0]
    tags = model["mops"]
    checked = 0

    for finding in current["findings"]:
        proof = current["proofs"][finding["proof"]]
        if proof.get("reason") != "unsupported operand effect or storage":
            continue
        require(proof["status"] == "unsupported", "address-of source was admitted")
        root = copy.deepcopy(finding["sample"]["input"]["root"])
        addresses = []

        def rename(node):
            if not isinstance(node, list):
                return
            if len(node) == 5 and node[0] == tags["a"]:
                addresses.append(copy.deepcopy(node))
                node[:] = [tags["r"], node[1], node[2], 0, 1 << 61]
                return
            for part in node:
                rename(part)

        rename(root)
        require(
            bool(addresses)
            and all(
                address[1] == 4
                and address[3] == 0
                and address[4][0] == tags["S"]
                and address[4][1] == -1
                and address[4][3] == 0
                and address[4][4] == [1, 140]
                for address in addresses
            ),
            "captured address-of stack descriptor",
        )
        replacement = primitive_reductions(
            root,
            model,
            root_iprops=finding["sample"]["input"].get("root_iprops"),
        )
        require(
            replacement["status"] == "primitive_reduction_refuted"
            and all(query["state"] == "sat" for query in replacement["queries"]),
            "unconstrained address-of counterfactual",
        )
        checked += finding["sample"]["count"]
    require(checked == 48, "address-of counterfactual inventory")
    return checked


def compare(prior, current):
    require(prior["passed"] and current["passed"], "both audits must pass")
    require(
        prior["report_sha256"] == current["report_sha256"] == REPORT_SHA256
        and prior["counts"]["events"] == current["counts"]["events"] == 14047
        and prior["counts"]["unrecorded"] == current["counts"]["unrecorded"] == 0,
        "captured matrix identity",
    )
    require(
        prior["classifications"]
        == {
            "primitive_reduction_refuted": 13393,
            "unsupported": 649,
            "existing_terminal_outcome": 5,
        }
        and current["classifications"]
        == {
            "primitive_reduction_refuted": 13717,
            "unsupported": 325,
            "existing_terminal_outcome": 5,
        },
        "classification totals",
    )
    require(
        len(prior["findings"]) == len(current["findings"]) == 9724
        and len(prior["proofs"]) == len(current["proofs"]) == 1229,
        "candidate/proof inventory",
    )
    require(
        prior["sdk_models"] == current["sdk_models"]
        and prior["engine"] == current["engine"]
        and current["capture_source_revision"] == SOURCE_REVISION,
        "SDK, solver or source revision changed",
    )
    model = current["sdk_models"][0]
    names = {code: name for name, code in model["ops"].items()}
    transitions, stack_roots, computed_offset_roots = Counter(), Counter(), Counter()
    first_change = None
    for index, (old_finding, new_finding) in enumerate(zip(prior["findings"], current["findings"])):
        require(old_finding == {**new_finding, "proof": old_finding["proof"]}, "finding identity")
        count = old_finding["sample"]["count"]
        require(type(count) is int and 1 <= count <= 1024, "retained event weight")
        old = prior["proofs"][old_finding["proof"]]
        new = current["proofs"][new_finding["proof"]]
        if (old["status"], old.get("reason")) == (new["status"], new.get("reason")):
            continue
        if first_change is None:
            first_change = index
        key = (old.get("reason"), new["status"], new.get("reason"))
        transitions[key] += count
        if new["status"] == "primitive_reduction_refuted":
            require(
                new["queries"] and all(query["state"] == "sat" for query in new["queries"]),
                "refutation lacks SAT witnesses",
            )
        if key[0] == "unsupported nested value or explicit-load contract":
            offset_tags = {
                read["instruction"][4][0]
                for read in new["explicit_reads"]
                if read["instruction"][0] == model["ops"]["ldx"]
            }
            root_name = names[old_finding["sample"]["input"]["root"][3]]
            if model["mops"]["S"] in offset_tags:
                stack_roots[root_name] += count
            elif model["mops"]["d"] in offset_tags:
                computed_offset_roots[root_name] += count
            else:
                raise ValueError("new refutation lacks checked load offset")
    require(dict(transitions) == EXPECTED_TRANSITIONS, "weighted transition inventory")
    require(dict(stack_roots) == EXPECTED_STACK_ROOTS, "stack-offset root inventory")
    require(
        dict(computed_offset_roots) == EXPECTED_COMPUTED_OFFSET_ROOTS,
        "computed-offset root inventory",
    )
    require(first_change is not None, "no changed finding for mutation control")
    return {
        "old_refuted": 13393,
        "new_refuted": 13717,
        "newly_refuted": 324,
        "old_unsupported": 649,
        "new_unsupported": 325,
        "changed_events": sum(transitions.values()),
        "transitions": [
            {"prior_reason": old, "new_status": status, "new_reason": reason, "events": count}
            for (old, status, reason), count in sorted(transitions.items())
        ],
        "stack_offset_roots": dict(sorted(stack_roots.items())),
        "computed_offset_roots": dict(sorted(computed_offset_roots.items())),
        "unsupported_taxonomy": unsupported_taxonomy(current, model),
        "first_changed_finding": first_change,
    }


def corruption_controls(prior, current, first_change):
    altered = dict(current)
    findings = list(current["findings"])
    changed = dict(findings[first_change])
    changed["sample"] = dict(changed["sample"])
    changed["sample"]["count"] += 1
    findings[first_change] = changed
    altered["findings"] = findings
    try:
        compare(prior, altered)
    except ValueError:
        return ["changed retained event count"]
    raise ValueError("changed retained event count accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--controls", type=Path, required=True)
    parser.add_argument("--capture-tar", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {"passed": False}
    try:
        with gzip.open(args.prior, "rt") as stream:
            prior = json.load(stream)
        current = json.loads(args.current.read_text())
        controls = json.loads(args.controls.read_text())
        require(controls["passed"] and controls["count"] == 607, "component controls")
        require(controls["engine"] == current["engine"], "component solver changed")
        require(digest(args.prior) == PRIOR_SHA256, "prior audit identity")
        require(current["capture_tar_sha256"] == digest(args.capture_tar), "capture tar identity")
        with tarfile.open(args.capture_tar, "r:gz") as capture:
            require(capture.getnames().count(REPORT_MEMBER) == 1, "report member identity")
            report = capture.extractfile(REPORT_MEMBER)
            require(
                report is not None and hashlib.sha256(report.read()).hexdigest() == REPORT_SHA256,
                "retained report identity",
            )
        summary = compare(prior, current)
        counterfactual = reserved_counterfactual(current)
        address_counterfactual = address_of_counterfactual(current)
        result = {
            "passed": True,
            **{key: value for key, value in summary.items() if key != "first_changed_finding"},
            "corruption_controls": corruption_controls(
                prior, current, summary["first_changed_finding"]
            ),
            "reserved_unconstrained_counterfactual": counterfactual,
            "address_of_unconstrained_counterfactual": address_counterfactual,
            "prior_sha256": digest(args.prior),
            "current_sha256": digest(args.current),
            "controls_sha256": digest(args.controls),
            "capture_tar_sha256": digest(args.capture_tar),
        }
    except Exception as error:
        result["failure"] = type(error).__name__ + ": " + str(error)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
