"""Semantic reduction controls, width counterexamples and bounded solver failure."""

import argparse
import copy
import hashlib
import json
from pathlib import Path

import z3

from mba_matching_diagnostics import require
from mba_semantic_miss import (
    NestedPrimitive,
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

    def nested(op, width, left, right=None):
        expression = root(op, width, left, right)
        expression[2] = [
            tags["d"],
            width,
            0,
            0,
            [
                ops[op],
                0,
                0x1000,
                left[2],
                right[2] if right is not None else [tags["z"], -1, 0, 0, 0],
                [tags["z"], width, 0, 0, 0],
            ],
        ]
        return expression

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
        for op in ("shl", "shr", "sar"):
            check(
                f"{op}:{width}:byte-count",
                root(op, width, x, leaf("r", 1, 32)),
                "primitive_reduction_refuted",
            )
            check(
                f"{op}:{width}:wide-count",
                root(op, width, x, leaf("r", 2, 32)),
                "unsupported",
            )
            for value in (0, 1, 1 << (8 * width - 1), mask(width)):
                for count in (0, 8 * width - 1, 8 * width, 255):
                    expression = root(op, width, leaf("n", width, value), leaf("n", 1, count))
                    primitive = Primitive(expression, model)
                    actual = primitive.integer({"L": value, "R": count})
                    symbolic, _, _ = primitive.symbolic("shift_boundary")
                    require(
                        z3.simplify(symbolic).as_long() == actual,
                        "shift symbolic/integer boundary",
                    )
            passed.append(f"{op}:{width}:boundaries")
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
        expression = root("setz", 1, nested("add", width, x, leaf("n", width, 0)), x)
        check(f"nested identity:{width}", expression, "value_reduction", root_iprops=0)
        expression = root("setz", 1, nested("add", width, x, y), x)
        check(f"nested free:{width}", expression, "primitive_reduction_refuted", root_iprops=0)
        expression = root("setz", 1, nested("shl", width, x, leaf("r", 1, 32)), x)
        check(f"nested shift:{width}", expression, "primitive_reduction_refuted", root_iprops=0)

    x = leaf("r", 2, 8)
    expression = root("setz", 1, nested("sub", 2, x, copy.deepcopy(x)), leaf("n", 2, 0))
    check("nested constant result", expression, "value_reduction", root_iprops=0)
    expression = root("setz", 1, nested("add", 2, x, leaf("r", 2, 9)), leaf("r", 2, 8))
    proof = check(
        "nested overlapping bytes", expression, "primitive_reduction_refuted", root_iprops=0
    )
    require(len(NestedPrimitive(expression, model, 0).cells) == 3, "nested shared-byte population")
    require(all(q["state"] == "sat" for q in proof["queries"]), "nested overlap witnesses")
    numbered = copy.deepcopy(expression)
    numbered[4][2][2] = 3
    check("nested value number", numbered, "primitive_reduction_refuted", root_iprops=0)

    two_level = root(
        "setz",
        1,
        nested("add", 2, nested("xor", 2, x, leaf("n", 2, 7)), leaf("r", 2, 9)),
        x,
    )
    check("two arithmetic children", two_level, "primitive_reduction_refuted", root_iprops=0)
    require(
        len(NestedPrimitive(two_level, model, 0).cells) == 3,
        "two-level shared snapshot bytes",
    )
    three_level = root(
        "setz",
        1,
        nested(
            "add",
            2,
            nested("xor", 2, nested("sub", 2, x, x), leaf("n", 2, 7)),
            leaf("r", 2, 9),
        ),
        x,
    )
    proof = check("three arithmetic children", three_level, "unsupported", root_iprops=0)
    require(proof["reason"] == "nested arithmetic depth budget", "bounded nested depth")

    unary_shapes = (
        ("neg", 2, leaf("r", 2, 8)),
        ("bnot", 2, leaf("r", 2, 8)),
        ("mov", 2, leaf("r", 2, 8)),
        ("xdu", 2, leaf("r", 1, 8)),
        ("xds", 2, leaf("r", 1, 8)),
        ("low", 2, leaf("r", 4, 8)),
        ("high", 2, leaf("r", 4, 8)),
    )
    for operation, width, operand in unary_shapes:
        candidate = root("xor", width, nested(operation, width, operand), leaf("r", width, 32))
        check("nested unary " + operation, candidate, "primitive_reduction_refuted")

    invalid_unary = root("xor", 2, nested("neg", 2, leaf("r", 2, 8)), leaf("r", 2, 32))
    invalid_unary[4][2][4][4] = leaf("n", 2, 0)[2]
    check("nested unary nonvoid right operand", invalid_unary, "unsupported")

    def replace_nested_left(candidate, operand):
        candidate[4][4] = operand
        candidate[4][2][4][3] = operand[2]

    read = [
        ops["ldx"],
        0,
        0x1000,
        [tags["r"], 2, 0, 0, 116],
        [tags["r"], 8, 0, 0, 16],
        [tags["z"], 2, 0, 0, 0],
    ]
    stack_read = copy.deepcopy(read)
    stack_read[4] = [tags["S"], 4, 0, 0, [1, 12]]
    stack_expression = root("xor", 2, x, leaf("d", 2, stack_read))
    proof = check("explicit load stack offset", stack_expression, "primitive_reduction_refuted")
    require(
        proof["explicit_reads"][0]["instruction"][4] == stack_read[4],
        "stack offset source retained",
    )
    check(
        "stack load same scalar bytes",
        root("xor", 2, leaf("S", 2, [1, 12]), leaf("d", 2, stack_read)),
        "unsupported",
    )
    check(
        "stack load disjoint scalar bytes",
        root("xor", 2, leaf("S", 2, [1, 8]), leaf("d", 2, stack_read)),
        "primitive_reduction_refuted",
    )
    for label, edit in (
        ("stack offset properties", lambda ins: ins[4].__setitem__(3, 1)),
        ("stack offset width", lambda ins: ins[4].__setitem__(1, 2)),
        ("stack offset identity", lambda ins: ins[4].__setitem__(4, [1])),
        ("stack selector", lambda ins: ins.__setitem__(3, copy.deepcopy(stack_read[4]))),
    ):
        invalid_read = copy.deepcopy(stack_read)
        edit(invalid_read)
        check(
            "explicit load " + label,
            root("xor", 2, x, leaf("d", 2, invalid_read)),
            "unsupported",
        )
    for offset_op in ("add", "sub"):
        computed = copy.deepcopy(read)
        computed[4] = [
            tags["d"],
            4,
            0,
            0,
            [
                ops[offset_op],
                0,
                0x1000,
                [tags["r"], 4, 0, 0, 32],
                [tags["n"], 4, 0, 0, 4],
                [tags["z"], 4, 0, 0, 0],
            ],
        ]
        proof = check(
            "explicit load computed " + offset_op,
            root("xor", 2, x, leaf("d", 2, computed)),
            "primitive_reduction_refuted",
        )
        require(
            proof["explicit_reads"][0]["instruction"][4] == computed[4],
            "computed offset descriptor retained",
        )
        for label, edit in (
            ("opcode", lambda operand: operand[4].__setitem__(0, ops["xor"])),
            ("effects", lambda operand: operand[4].__setitem__(1, 1)),
            ("result width", lambda operand: operand[4][5].__setitem__(1, 8)),
            ("left width", lambda operand: operand[4][3].__setitem__(1, 8)),
            ("reserved register", lambda operand: operand[4][3].__setitem__(4, 1)),
            ("right width", lambda operand: operand[4][4].__setitem__(1, 8)),
            ("right properties", lambda operand: operand[4][4].__setitem__(3, 1)),
            ("right domain", lambda operand: operand[4][4].__setitem__(4, 1 << 32)),
            ("nested offset", lambda operand: operand[4][4].__setitem__(0, tags["d"])),
        ):
            invalid = copy.deepcopy(computed)
            edit(invalid[4])
            check(
                "explicit load computed " + offset_op + " " + label,
                root("xor", 2, x, leaf("d", 2, invalid)),
                "unsupported",
            )
    with_load = copy.deepcopy(expression)
    replace_nested_left(with_load, leaf("d", 2, read))
    proof = check("nested explicit load", with_load, "primitive_reduction_refuted", root_iprops=0)
    require([load["path"] for load in proof["explicit_reads"]] == ["child/L"], "nested load scope")
    two_loads = root(
        "setz", 1, leaf("d", 2, copy.deepcopy(read)), nested("add", 2, leaf("d", 2, read), x)
    )
    proof = check(
        "nested equal-address reads", two_loads, "primitive_reduction_refuted", root_iprops=0
    )
    require(
        len(proof["snapshot_cells"]) == 6
        and [load["path"] for load in proof["explicit_reads"]] == ["root/L", "child/L"],
        "independent nested read occurrences",
    )
    deep_loads = root(
        "setz",
        1,
        leaf("d", 2, copy.deepcopy(read)),
        nested("add", 2, nested("neg", 2, leaf("d", 2, read)), x),
    )
    proof = check(
        "two-level equal-address reads", deep_loads, "primitive_reduction_refuted", root_iprops=0
    )
    require(
        [load["path"] for load in proof["explicit_reads"]] == ["root/L", "child/child/L"],
        "two-level independent read occurrences",
    )
    altered_deep = copy.deepcopy(two_level)
    altered_deep[4][4][2][4][3] = leaf("r", 2, 32)[2]
    proof = check("two-level altered source", altered_deep, "unsupported", root_iprops=0)
    require(proof["reason"] == "nested arithmetic instruction contract", "deep source identity")
    bad_read = copy.deepcopy(read)
    bad_read[1] = 4096
    for label, edit in (
        ("nested missing metadata", lambda e: None),
        ("nested instruction opcode", lambda e: e[4][2][4].__setitem__(0, ops["sub"])),
        ("nested instruction operand", lambda e: e[4][2][4].__setitem__(3, leaf("r", 2, 40)[2])),
        ("nested value properties", lambda e: e[4][2].__setitem__(3, 1)),
        ("nested effects", lambda e: e[4][2][4].__setitem__(1, 4096)),
        ("nested effectful load", lambda e: replace_nested_left(e, leaf("d", 2, bad_read))),
    ):
        altered = copy.deepcopy(expression)
        edit(altered)
        options = {} if label == "nested missing metadata" else {"root_iprops": 0}
        proof = check(label, altered, "unsupported", **options)
        if label == "nested effectful load":
            require(proof["reason"] == "unsupported nested value or explicit-load contract", label)

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
