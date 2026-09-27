"""Semantic reduction controls, width counterexamples and bounded solver failure."""

import argparse
import copy
import hashlib
import json
from pathlib import Path

from mba_matching_diagnostics import require
from mba_semantic_miss import (
    Primitive,
    constraint_reduction,
    engine_provenance,
    mask,
    primitive_reductions,
    verify_constraint_witness,
    verify_primitive_witness,
)


def controls(model):
    tags, ops = model["mops"], model["ops"]
    passed = []

    def leaf(kind, width, value, version=0, props=0):
        return ["v", width, [tags[kind], width, version, props, value]]

    def root(op, width, left, right=None):
        return ["n", width, [tags["z"], width, 0, 0, 0], ops[op], left, right]

    def check(label, expression, expected, **options):
        budgets = {"timeout_ms": 1000, "resource_limit": 1000000, **options}
        proof = primitive_reductions(expression, model, **budgets)
        require(proof["status"] == expected, "semantic control: " + label)
        for query in proof.get("queries", []):
            if query["state"] == "sat":
                verify_primitive_witness(expression, model, query, options.get("root_iprops"))
        passed.append(label)
        return proof

    for width in (1, 2, 4, 8):
        x, y = leaf("r", width, 8), leaf("r", width, 32)
        for op in ("add", "sub", "mul", "and", "or", "xor"):
            check(f"{op}:{width}:distinct", root(op, width, x, y), "primitive_reduction_refuted")
        for op in ("bnot", "neg"):
            check(f"{op}:{width}:free", root(op, width, x), "primitive_reduction_refuted")
        for op in ("sub", "xor", "and", "or"):
            check(f"{op}:{width}:same", root(op, width, x, copy.deepcopy(x)), "value_reduction")
        check(
            f"xor:{width}:different-version",
            root("xor", width, x, leaf("r", width, 8, version=1)),
            "primitive_reduction_refuted",
        )
        for rule, operation in (
            ("Sub1_FactorRule_2", "add"),
            ("And_Rule_3", "and"),
            ("Mul_Rule_4", "mul"),
        ):
            constant = leaf("n", width, 3)
            expression = (
                root(operation, width, constant, x)
                if operation == "mul"
                else root(operation, width, x, constant)
            )
            sample = {
                "outcome": "constant_constraint",
                "rule": rule,
                "width_bytes": width,
                "reason": f"constant_check_failed;numeric=c_minus_1:{width}:0x3;omitted=0",
                "input": {"root": expression},
            }
            proof = constraint_reduction(sample, model, timeout_ms=1000, resource_limit=1000000)
            require(proof["status"] == "sat", "actual typed constant rejection")
            verify_constraint_witness(sample, model, proof)
            passed.append(rule + ":" + str(width))

    for width in (1, 2, 4, 8):
        x, y = leaf("r", width, 8), leaf("r", width, 32)
        for op in (
            "cfadd",
            "ofadd",
            "seto",
            "setp",
            "setz",
            "setnz",
            "setb",
            "setae",
            "seta",
            "setbe",
            "setg",
            "setge",
            "setl",
            "setle",
        ):
            expression = root(op, 1, x, y)
            check(f"{op}:{width}:free", expression, "primitive_reduction_refuted", root_iprops=0)
            check(f"{op}:{width}:missing-metadata", expression, "unsupported")
            check(f"{op}:{width}:floating", expression, "unsupported", root_iprops=16)
            check(f"{op}:{width}:effects", expression, "unsupported", root_iprops=4096)
            if op not in ("cfadd", "ofadd"):
                check(
                    f"{op}:{width}:same",
                    root(op, 1, x, copy.deepcopy(x)),
                    "value_reduction",
                    root_iprops=0,
                )
            check(
                f"{op}:{width}:destination-width", root(op, 4, x, y), "unsupported", root_iprops=0
            )
            other = 4 if width == 8 else width * 2
            check(
                f"{op}:{width}:operand-width",
                root(op, 1, x, leaf("r", other, 32)),
                "unsupported",
                root_iprops=0,
            )
        for op in ("sets", "lnot"):
            check(
                f"{op}:{width}:free", root(op, 1, x), "primitive_reduction_refuted", root_iprops=0
            )
            for value in (0, 1, 1 << (width * 8 - 1)):
                check(
                    f"{op}:{width}:constant:{value}",
                    root(op, 1, leaf("n", width, value)),
                    "value_reduction",
                    root_iprops=0,
                )

    expression = root("xor", 2, leaf("r", 2, 8), leaf("r", 2, 9))
    proof = check("overlapping register bytes", expression, "primitive_reduction_refuted")
    primitive = Primitive(expression, model)
    require(len(primitive.cells) == 3, "exact overlap cell population")
    for query in proof["queries"]:
        for witness in query.get("counterexamples", [query.get("counterexample")]):
            if witness is not None:
                require(
                    witness["operands"]["L"] >> 8 == witness["operands"]["R"] & 255,
                    "overlapping byte witness",
                )
    check(
        "stack owner distinction",
        root("sub", 4, leaf("S", 4, [1, 8]), leaf("S", 4, [2, 8])),
        "primitive_reduction_refuted",
    )
    check(
        "stack same snapshot",
        root("sub", 4, leaf("S", 4, [1, 8]), leaf("S", 4, [1, 8])),
        "value_reduction",
    )
    check(
        "operand properties",
        root("xor", 4, leaf("r", 4, 8, props=1), leaf("r", 4, 8)),
        "unsupported",
    )
    check(
        "reserved condition state", root("or", 1, leaf("r", 1, 0), leaf("r", 1, 1)), "unsupported"
    )
    check(
        "implicit arithmetic width", root("xor", 4, leaf("r", 8, 8), leaf("r", 4, 8)), "unsupported"
    )

    for operation, src_width, dest_width, source, expected in (
        ("xdu", 1, 4, 128, 128),
        ("xds", 1, 4, 128, 0xFFFFFF80),
        ("low", 4, 1, 0x12345678, 0x78),
        ("high", 4, 1, 0x12345678, 0x12),
    ):
        expression = root(operation, dest_width, leaf("r", src_width, 8))
        proof = check(operation + ":typed", expression, "primitive_reduction_refuted")
        require(
            proof["ineligible_operand_targets"] == ["L"] and len(proof["queries"]) == 1,
            "width-changing MOV never proposed",
        )
        primitive = Primitive(expression, model)
        cells = {k: (source >> (8 * (v[-1] - 8))) & 255 for k, v in primitive.cells.items()}
        require(
            primitive.integer(primitive.values(cells)) == expected,
            "explicit extension/extraction arithmetic",
        )
    check("extension cannot narrow", root("xdu", 1, leaf("r", 4, 8)), "unsupported")
    check("extraction cannot widen", root("low", 4, leaf("r", 1, 8)), "unsupported")
    check("implicit MOV conversion", root("mov", 4, leaf("r", 1, 8)), "unsupported")
    check("same-width conversion", root("xds", 4, leaf("r", 4, 8)), "value_reduction")

    empty = [tags["z"], 4, 0, 0, 0]
    read = [ops["ldx"], 0, 0x1000, [tags["r"], 2, 0, 0, 116], [tags["r"], 8, 0, 0, 16], empty]
    expression = root("xor", 4, leaf("d", 4, read), leaf("d", 4, copy.deepcopy(read)))
    proof = check("separate explicit reads", expression, "primitive_reduction_refuted")
    require(
        len(proof["explicit_reads"]) == 2 and len(proof["snapshot_cells"]) == 8,
        "read occurrences remain independent",
    )
    check(
        "load identity value",
        root("xor", 4, leaf("d", 4, read), leaf("n", 4, 0)),
        "value_reduction",
    )
    broken = copy.deepcopy(read)
    broken[3] = [tags["n"], 2, 0, 0, None]
    check(
        "malformed load address",
        root("xor", 4, leaf("d", 4, broken), leaf("n", 4, 0)),
        "unsupported",
    )

    expression = root("and", 1, leaf("n", 1, 0), leaf("n", 1, 3))
    sample = {
        "outcome": "constant_constraint",
        "rule": "And_Rule_3",
        "width_bytes": 1,
        "reason": "constant_check_failed;numeric=c_minus_1:1:0x3;omitted=0",
        "input": {"root": expression},
    }
    require(
        constraint_reduction(sample, model)["status"] == "unsat",
        "family rejection need not reject an instantiated constant reduction",
    )
    passed.append("instantiated constant reduction")
    wrong = copy.deepcopy(sample)
    wrong["reason"] = "constant_check_failed;numeric=c_minus_1:1:0x4;omitted=0"
    try:
        constraint_reduction(wrong, model)
    except ValueError:
        passed.append("false bound constant rejected")
    else:
        raise ValueError("incorrect actual binding accepted")

    sample["input"]["root"][4] = leaf("r", 1, 8)
    proof = constraint_reduction(sample, model)
    verify_constraint_witness(sample, model, proof)
    for label, edit_sample, edit_proof in (
        ("persisted false binding", lambda s: s.update(reason=wrong["reason"]), None),
        ("persisted false instance width", lambda s: s.update(width_bytes=2), None),
        ("persisted false gate", lambda s: s.update(outcome="structural_mismatch"), None),
        ("persisted false bound path", None, lambda p: p.update(x_path="R")),
        ("persisted false proof width", None, lambda p: p.update(bits=16)),
        ("persisted false proof state", None, lambda p: p.update(status="unknown")),
        (
            "persisted false constraint result",
            None,
            lambda p: p["counterexample"].update(result=p["counterexample"]["result"] ^ 1),
        ),
        (
            "persisted false constraint replacement",
            None,
            lambda p: p["counterexample"].update(proposed=p["counterexample"]["proposed"] ^ 1),
        ),
    ):
        bad_sample, bad_proof = copy.deepcopy(sample), copy.deepcopy(proof)
        if edit_sample is not None:
            edit_sample(bad_sample)
        if edit_proof is not None:
            edit_proof(bad_proof)
        try:
            verify_constraint_witness(bad_sample, model, bad_proof)
        except ValueError:
            passed.append(label)
        else:
            raise ValueError("corrupted persisted constraint accepted: " + label)

    expression = root("xds", 4, leaf("r", 1, 8))
    primitive = Primitive(expression, model)
    witness = {
        "bytes": {k: 128 for k in primitive.cells},
        "operands": {"L": 128},
        "result": 0xFFFFFF80,
        "proposed": 128,
    }
    # An otherwise valid inequality cannot authorize a width-changing MOV.
    try:
        verify_primitive_witness(
            expression, model, {"state": "sat", "target": "L", "counterexample": witness}
        )
    except ValueError:
        passed.append("persisted width-changing MOV rejected")
    else:
        raise ValueError("invalid typed reduction target accepted")

    expression = root("mul", 8, leaf("r", 8, 8), leaf("r", 8, 32))
    proof = check("deterministic resource exhaustion", expression, "unknown", resource_limit=1)
    require(
        all(q["state"] == "unknown" and q["reason"] for q in proof["queries"]),
        "unknown cannot become a proof",
    )
    return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    args = parser.parse_args()
    fixture_sha = hashlib.sha256(args.fixtures.read_bytes()).hexdigest()
    fixture = json.loads(args.fixtures.read_text())
    engine = engine_provenance()
    passed = controls(fixture["catalog"]["model"])
    print(
        json.dumps(
            {
                "passed": True,
                "controls": passed,
                "count": len(passed),
                "fixture_sha256": fixture_sha,
                "engine": engine,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
