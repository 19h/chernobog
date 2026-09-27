"""Compare independent native status bits with typed integer and symbolic values."""

import argparse
import hashlib
import json
from pathlib import Path

import z3

from mba_matching_diagnostics import require
from mba_semantic_miss import Primitive, engine_provenance, mask


def cases():
    for x in range(256):
        for y in range(256):
            yield 1, x, y
    for width in (2, 4, 8):
        sign = 1 << (width * 8 - 1)
        corners = (0, 1, 2, sign - 1, sign, sign + 1, mask(width) - 1, mask(width))
        for x in corners:
            for y in corners:
                yield width, x, y


def audit(native, model):
    require(len(native) == 262912, "native flag population")
    templates = {}
    for width in (1, 2, 4, 8):
        for op in ("cfadd", "ofadd", "seto", "setp"):
            leaf = lambda register: ["v", width, [model["mops"]["r"], width, 0, 0, register]]
            root = ["n", 1, [model["mops"]["z"], 1, 0, 0, 0], model["ops"][op], leaf(8), leaf(32)]
            primitive = Primitive(root, model, 0)
            expression, _, values = primitive.symbolic("native:" + op + ":" + str(width))
            templates[width, op] = primitive, expression, values
    checks = 0
    for width, x, y in cases():
        for op in ("cfadd", "ofadd", "seto", "setp"):
            primitive, expression, values = templates[width, op]
            expected = native[checks]
            require(expected in (0, 1), "native status byte")
            require(primitive.integer({"L": x, "R": y}) == expected, "integer/native flag mismatch")
            concrete = z3.simplify(
                z3.substitute(
                    expression,
                    (values["L"], z3.BitVecVal(x, width * 8)),
                    (values["R"], z3.BitVecVal(y, width * 8)),
                )
            )
            require(
                z3.is_bv_value(concrete) and concrete.as_long() == expected,
                "symbolic/native flag mismatch",
            )
            checks += 1
    require(checks == len(native), "flag case accounting")
    return {
        "passed": True,
        "integer_checks": checks,
        "symbolic_checks": checks,
        "native_sha256": hashlib.sha256(native).hexdigest(),
        "engine": engine_provenance(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = json.loads(args.fixtures.read_text())
    result = audit(args.native.read_bytes(), fixture["catalog"]["model"])
    result["fixture_sha256"] = hashlib.sha256(args.fixtures.read_bytes()).hexdigest()
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "engine"}))


if __name__ == "__main__":
    main()
