"""Compare bounded shift semantics against the pinned Hex-Rays SDK oracle."""

import argparse
import copy
import csv
import hashlib
import json
from pathlib import Path

import z3

from mba_matching_diagnostics import require
from mba_semantic_miss import Primitive, mask


def check_rows(rows, model):
    tags, ops = model["mops"], model["ops"]
    expected = {
        (width, value, count)
        for width in (1, 2, 4, 8)
        for value in (0, 1, 1 << (8 * width - 1), mask(width))
        for count in (0, 8 * width - 1, 8 * width, 255)
    }
    require(len(rows) == 64, "SDK shift row population")
    seen = set()
    for row in rows:
        require(len(row) == 6, "SDK shift row arity")
        width, value, count, *sdk = (int(field) for field in row)
        key = (width, value, count)
        require(key in expected and key not in seen, "SDK shift row identity")
        seen.add(key)
        for name, actual in zip(("shl", "shr", "sar"), sdk):
            require(0 <= actual <= mask(width), "SDK shift result width")
            left = ["v", width, [tags["n"], width, 0, 0, value]]
            right = ["v", 1, [tags["n"], 1, 0, 0, count]]
            root = ["n", width, [tags["z"], width, 0, 0, 0], ops[name], left, right]
            primitive = Primitive(root, model)
            symbolic, _, _ = primitive.symbolic("sdk_shift")
            require(
                primitive.integer({"L": value, "R": count}) == actual
                and z3.simplify(symbolic).as_long() == actual,
                "SDK/integer/symbolic shift mismatch",
            )
    require(seen == expected, "SDK shift input population")
    return 192


def verify(rows, model):
    checks = check_rows(rows, model)
    changed = copy.deepcopy(rows)
    changed[0][3] = str(int(changed[0][3]) ^ 1)
    try:
        check_rows(changed, model)
    except ValueError:
        pass
    else:
        raise ValueError("altered SDK shift result accepted")
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sdk_bytes = args.sdk.read_bytes()
    fixtures_bytes = args.fixtures.read_bytes()
    rows = list(csv.reader(sdk_bytes.decode().splitlines()))
    fixture = json.loads(fixtures_bytes)
    checks = verify(rows, fixture["catalog"]["model"])
    result = {
        "passed": True,
        "rows": len(rows),
        "checks": checks,
        "corruption_rejected": True,
        "sdk_output_sha256": hashlib.sha256(sdk_bytes).hexdigest(),
        "fixture_sha256": hashlib.sha256(fixtures_bytes).hexdigest(),
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
