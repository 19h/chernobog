"""Audit artifact attribution, unchanged telemetry semantics and isolated value rewrites."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import random
import sys

sys.dont_write_bytecode = True
from run_protected_mba_corpus import ROOT, require


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    report = json.loads(path.read_text())
    require(report["passed"] and report["native_analysis_disabled"], "analysis profile")
    require(len(report["runs"]) == 40, "analysis population")
    for name, sha in report["artifact_sha256"].items():
        item = (ROOT / name).resolve()
        require(item.is_relative_to(ROOT) and digest(item) == sha, "analysis artifact changed")
    for name, sha in report["source_sha256"].items():
        require(digest(ROOT / name) == sha, "analysis source changed")
    return report


def captures(report):
    result = {}
    for run in report["runs"]:
        path = next(p for p in run["artifact_sha256"] if p.endswith("/protected_mba.json"))
        capture = json.loads((ROOT / path).read_text())
        for entry in capture["entries"]:
            for kind, row in (("entry", entry), ("body", entry["body"])):
                if row is None:
                    continue
                key = run["architecture"], run["label"], run["disabled"], entry["name"], kind
                require(key not in result, "duplicate capture")
                result[key] = row
    return result


def compare(before, after):
    require(before["legacy_reasons"] and not after["legacy_reasons"], "prior/current profile")
    require(
        before["ida_sha256"] == after["ida_sha256"]
        and before["ida_components_sha256"] == after["ida_components_sha256"],
        "prior/current IDA toolchain",
    )
    old, new = captures(before), captures(after)
    require(old.keys() == new.keys(), "prior/current owner population")
    stages = captured = 0
    for key in old:
        left, right = old[key], new[key]
        require(
            all(left.get(k) == right.get(k) for k in ("entry", "owner", "status", "native_chunks")),
            "prior/current native identity",
        )
        require(len(left["stages"]) == len(right["stages"]), "prior/current stage population")
        for a, b in zip(left["stages"], right["stages"]):
            require(
                all(
                    a.get(k) == b.get(k)
                    for k in ("maturity", "status", "blocks", "error_code", "error_ea")
                ),
                "prior/current SDK shape",
            )
            for name in (
                "total_matches",
                "successful_matches",
                "instance_verified",
                "instance_disproved",
                "instance_unsupported",
                "instance_unknown",
            ):
                require(
                    a["statistics"][name] == b["statistics"][name], "prior/current proof outcomes"
                )
            stages += 1
            captured += b["status"] == "captured"
    return {"native_rows": len(new), "stages": stages, "captured_stages": captured}


OPS = {"m_bnot", "m_neg", "m_add", "m_sub", "m_mov"}


def variables(instruction):
    require(
        instruction["opcode"] in OPS and instruction["properties"] == 0, "isolated value opcode"
    )
    bits = 8 * instruction["destination"]["bytes"]
    require(bits in (8, 16, 32, 64), "isolated value width")
    require(instruction["destination"]["properties"] == 0, "isolated destination effects")
    unary = instruction["opcode"] in ("m_bnot", "m_neg", "m_mov")
    require(
        (instruction["right"]["kind_name"] == "mop_z") == unary,
        "isolated value arity",
    )
    result = set()
    for operand in (instruction["left"], instruction["right"]):
        require(operand["properties"] == 0, "isolated operand effects")
        kind = operand["kind_name"]
        if kind == "mop_z":
            continue
        require(operand["bytes"] * 8 == bits, "isolated implicit conversion")
        if kind == "mop_r":
            result.add((operand["register"], bits))
        elif kind == "mop_n":
            pass
        elif kind == "mop_d":
            require(
                operand["instruction"]["destination"]["bytes"] * 8 == bits, "isolated nested width"
            )
            result.update(variables(operand["instruction"]))
        else:
            raise ValueError("isolated value requires register/constant leaves")
    return result


def evaluate(instruction, inputs):
    bits = 8 * instruction["destination"]["bytes"]
    mask = (1 << bits) - 1

    def operand(value):
        kind = value["kind_name"]
        if kind == "mop_r":
            return inputs[value["register"], bits] & mask
        if kind == "mop_n":
            return value["value"] & mask
        if kind == "mop_d":
            return evaluate(value["instruction"], inputs)
        raise ValueError("unsupported isolated value leaf")

    left = operand(instruction["left"])
    opcode = instruction["opcode"]
    if opcode == "m_bnot":
        return left ^ mask
    if opcode == "m_neg":
        return (-left) & mask
    if opcode == "m_mov":
        return left
    right = operand(instruction["right"])
    if opcode == "m_add":
        return (left + right) & mask
    if opcode == "m_sub":
        return (left - right) & mask
    raise ValueError("unsupported isolated value operation")


def isolated_rewrites(report):
    corpus = captures(report)
    checks = []
    seed = 0x9827136AB5
    for key, after in corpus.items():
        architecture, label, disabled, name, kind = key
        if disabled or label == "original":
            continue
        before = corpus[architecture, label, True, name, kind]
        for old, new in zip(before["stages"], after["stages"]):
            if (
                old["maturity"] != 3
                or old["status"] != new["status"]
                or new["status"] != "captured"
            ):
                continue
            left = [i for b in old["blocks"] for i in b["instructions"]]
            right = [i for b in new["blocks"] for i in b["instructions"]]
            require(len(left) == len(right), "isolated instruction alignment")
            for a, b in zip(left, right):
                if a == b:
                    continue
                require(
                    a["ea"] == b["ea"] and a["destination"] == b["destination"],
                    "isolated destination",
                )
                inputs = variables(a) | variables(b)
                require(len(inputs) == 1 and next(iter(inputs))[1] == 32, "isolated input domain")
                variable = next(iter(inputs))
                rng = random.Random(seed)
                values = [
                    0,
                    1,
                    2,
                    0x7F,
                    0x80,
                    0x7FFF,
                    0x8000,
                    0x7FFFFFFF,
                    0x80000000,
                    0xFFFFFFFE,
                    0xFFFFFFFF,
                ]
                values += [rng.getrandbits(32) for _ in range(65536)]
                for value in values:
                    require(
                        evaluate(a, {variable: value}) == evaluate(b, {variable: value}),
                        "isolated value mismatch",
                    )
                corrupted = copy.deepcopy(b)
                corrupted["opcode"] = "m_add" if b["opcode"] == "m_sub" else "m_mov"
                require(
                    any(
                        evaluate(a, {variable: v}) != evaluate(corrupted, {variable: v})
                        for v in values
                    ),
                    "isolated wrong-proposal control accepted",
                )
                checks.append(
                    {
                        "architecture": architecture,
                        "label": label,
                        "name": name,
                        "kind": kind,
                        "maturity": 3,
                        "ea": a["ea"],
                        "before": a["text"],
                        "after": b["text"],
                        "width_bits": 32,
                        "input_seed": seed,
                        "comparisons": len(values),
                        "wrong_proposal_rejected": True,
                        "before_tree_sha256": hashlib.sha256(
                            json.dumps(a, sort_keys=True).encode()
                        ).hexdigest(),
                        "after_tree_sha256": hashlib.sha256(
                            json.dumps(b, sort_keys=True).encode()
                        ).hexdigest(),
                    }
                )
    require(len(checks) == 2, "isolated rewrite population")
    return checks


def controls(before, after):
    trials = []
    for label, change in (
        ("changed prior profile", lambda r: r.update(legacy_reasons=True)),
        ("missing process", lambda r: r["runs"].pop()),
        ("duplicate process", lambda r: r["runs"].append(copy.deepcopy(r["runs"][0]))),
    ):
        altered = copy.deepcopy(after)
        change(altered)
        try:
            compare(before, altered)
        except (ValueError, KeyError):
            trials.append(label)
        else:
            raise ValueError("comparison mutation accepted: " + label)
    return trials


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prior", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {
        "schema": 1,
        "passed": False,
        "scope": "telemetry preservation and two isolated 32-bit SDK value expressions; no whole-function ISA/flags/fault or recovery-accuracy claim",
    }
    try:
        before, after = load(args.prior), load(args.current)
        report.update(
            comparison=compare(before, after),
            isolated_value_checks=isolated_rewrites(after),
            mutation_controls=controls(before, after),
            input_sha256={
                str(p.relative_to(ROOT) if p.is_absolute() else p): digest(p)
                for p in (args.prior, args.current)
            },
            verifier_sha256=digest(Path(__file__)),
            passed=True,
        )
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
