"""Validate and compile the frozen typed CoBRA fixture manifest."""

from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/fixtures/mba_cobra_positive_manifest.json"


def walk(term):
    yield term
    for child in ("left", "right"):
        if child in term:
            yield from walk(term[child])


def cost(term):
    return sum(node["op"] not in ("Constant", "Variable") for node in walk(term))


def evaluate(term, values):
    bits = term["bits"]
    mask = (1 << bits) - 1
    op = term["op"]
    if op == "Constant":
        return int(term["value"]) & mask
    if op == "Variable":
        return values[term["name"]] & mask
    a = evaluate(term["left"], values)
    b = evaluate(term["right"], values) if "right" in term else None
    if op == "Add":
        result = a + b
    elif op == "Sub":
        result = a - b
    elif op == "Mul":
        result = a * b
    elif op == "And":
        result = a & b
    elif op == "Or":
        result = a | b
    elif op == "Xor":
        result = a ^ b
    elif op == "Not":
        result = ~a
    elif op == "ZeroExtend":
        result = a
    elif op == "SignExtend":
        w = term["left"]["bits"]
        result = a - (1 << w) if a & (1 << (w - 1)) else a
    elif op == "Sar":
        signed = a - (1 << bits) if a & (1 << (bits - 1)) else a
        result = signed >> b
    else:
        raise ValueError(op)
    return result & mask


def load():
    raw = MANIFEST.read_bytes()
    expected = MANIFEST.with_suffix(".sha256").read_text().split()[0]
    assert hashlib.sha256(raw).hexdigest() == expected, "frozen manifest digest mismatch"
    fixtures = json.loads(raw)["fixtures"]
    expected_ids = [
        f"POS-{category}-{i:02d}"
        for category, count in (
            ("LIN", 8),
            ("SEMI", 8),
            ("POLY", 8),
            ("MIXP", 6),
            ("OPAQ", 6),
            ("NEST", 6),
        )
        for i in range(1, count + 1)
    ]
    assert [f["id"] for f in fixtures] == expected_ids
    for fixture in fixtures:
        assert cost(fixture["input"]) == fixture["input_term_cost"]
        assert cost(fixture["reference"]) == fixture["reference_term_cost"]
        assert len(list(walk(fixture["reference"]))) == fixture["reference_nodes"]
        assert len(list(walk(fixture["input"]))) <= 512
    return fixtures


def cpp(term, variables):
    op, bits = term["op"], term["bits"]
    if op == "Constant":
        return f'constant(UINT64_C({term["value"]}), {bits})'
    if op == "Variable":
        return f'variable({variables[term["name"]]}, {bits})'
    a = cpp(term["left"], variables)
    b = cpp(term["right"], variables) if "right" in term else "Term{}"
    return f"expression(Op::{op}, {a}, {b}, {bits})"


def header(fixtures, output):
    rows = [
        "// Generated from the frozen JSON manifest; edit the manifest only through specification review.",
        "#pragma once",
        '#include "deobf/analysis/mba_smt.hpp"',
        "namespace chernobog::mba_smt::fixtures {",
        "struct Fixture { const char *id; Program program; Term reference; size_t max_nodes; bool half_cost; bool empty_support; unsigned inner_width; };",
        "inline std::vector<Fixture> make() { std::vector<Fixture> result;",
    ]
    for f in fixtures:
        variables = {v["name"]: i for i, v in enumerate(f["variables"])}
        widths = [v["bits"] for v in f["variables"]] + [f["width"]]
        rows.extend(
            [
                "{ Program program; program.widths={"
                + ",".join(map(str, widths))
                + "}; program.blocks.resize(1);",
                f'program.blocks[0].statements.push_back(Statement::assign({len(variables)}, {cpp(f["input"],variables)}));',
                f'result.push_back({{"{f["id"]}", std::move(program), {cpp(f["reference"],variables)}, {f.get("max_output_nodes",512)}, {str("max_cost_denominator" in f).lower()}, {str(f.get("canonical_support_empty",False)).lower()}, {f.get("inner_width",0)}}}); }}',
            ]
        )
    rows.extend(["return result; }", "}"])
    output.write_text("\n".join(rows) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--header", type=Path)
    args = parser.parse_args()
    fixtures = load()
    if args.header:
        header(fixtures, args.header)
        return
    rng = random.Random(0xC0B4A)
    comparisons = 0
    for f in fixtures:
        if f["id"] in ("POS-POLY-01", "POS-OPAQ-01"):
            assignments = ({"x": x, "y": y} for x in range(256) for y in range(256))
        else:
            assignments = (
                {v["name"]: rng.getrandbits(v["bits"]) for v in f["variables"]} for _ in range(2048)
            )
        for values in assignments:
            assert evaluate(f["input"], values) == evaluate(f["reference"], values), f["id"]
            comparisons += 1
    print(f"Validated {len(fixtures)} frozen fixtures; {comparisons} independent word comparisons")


if __name__ == "__main__":
    main()
