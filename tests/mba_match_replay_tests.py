"""Compare independent replay with real C++ matcher results and reject corruption."""

import copy
import json
from pathlib import Path
import subprocess
import sys

from mba_match_replay import capture, catalog, local_constants, match, operand_difference
from mba_matching_diagnostics import parse_match_failure, require


def main():
    result = subprocess.run(
        [sys.argv[1], "--matcher-input-fixtures"], capture_output=True, check=True
    )
    fixtures = json.loads(result.stdout)
    model, production = catalog(fixtures["catalog"])
    require(len(production) == 108, "actual wholly certified production catalog")
    controls = []
    boundary_run = subprocess.run(
        [sys.argv[1], "--address-limit-fixture"], capture_output=True, check=True
    )
    boundary = json.loads(boundary_run.stdout)
    require(boundary["schema"] == 2, "near-limit input schema")
    require(boundary["prefix_status"] == "byte_limit", "address prefix byte frontier")
    require(7000 < len(boundary_run.stdout.strip()) <= 8192, "bounded address input bytes")
    require(boundary["prefix"], "retained complete address prefix")
    capture(boundary, model)
    controls.append("near-limit address input")
    changed = copy.deepcopy(boundary)
    changed["prefix"][0][3][4][1] = 2**31
    try:
        capture(changed, model)
    except ValueError:
        controls.append("near-limit address extent corruption")
    else:
        raise ValueError("near-limit address extent corruption accepted")
    names = [name for name, _ in production]
    for label, kept in (
        ("partial certified catalog", production[::2]),
        ("empty certified catalog", []),
    ):
        partial = copy.deepcopy(fixtures["catalog"])
        partial["patterns"] = kept
        _, accepted = catalog(partial, names)
        require(accepted == kept, label)
        controls.append(label)
    for label, mutate in (
        ("reordered certified catalog", lambda v: v["patterns"].reverse()),
        ("unregistered certified rule", lambda v: v["patterns"][0].__setitem__(0, "absent")),
        ("duplicate certified rule", lambda v: v["patterns"].append(v["patterns"][0])),
    ):
        bad = copy.deepcopy(fixtures["catalog"])
        mutate(bad)
        try:
            catalog(bad, names)
        except ValueError:
            controls.append(label)
        else:
            raise ValueError("catalog corruption accepted: " + label)
    for row in fixtures["fixtures"]:
        _, templates = catalog(row["pattern_catalog"])
        require(row["input"]["schema"] == 2, "current fixture input schema")
        value = capture(row["input"], model)
        matched, failure = match(templates[0][1], value["root"], model)
        require(matched == row["matched"], "C++/independent match disagreement: " + row["name"])
        require(
            failure == (None if matched else parse_match_failure(row["failure"])),
            "C++/independent failed branch disagreement: " + row["name"],
        )
        transformed, resolved = local_constants(value, model)
        if row["resolved"] >= 0:
            require(len(resolved) == row["resolved"], "local byte facts: " + row["name"])
            if resolved:
                require(resolved[0]["value"] == row["value"], "overlap arithmetic")
        if row["name"] == "local_zero":
            require(
                match(templates[0][1], transformed, model)[0], "local zero enables existing shape"
            )
        if row["name"] == "overlapping_byte":
            require(
                not match(templates[0][1], transformed, model)[0],
                "partial write prevents zero match",
            )
        controls.append(row["name"])
    for row in fixtures["equalities"]:
        require(row["input"]["schema"] == 2, "current equality input schema")
        value = capture(row["input"], model)
        difference = operand_difference(value["root"][4][2], value["root"][5][2], model)
        require((difference is None) == row["equal"], "C++/independent strict equality")
        if difference is not None:
            failure = parse_match_failure(row["failure"])
            require(failure["kind"] == difference[0], "strict first field")
            if len(difference) == 3:
                require((failure["expected"], failure["actual"]) == difference[1:], "strict values")
        controls.append(row["name"])
    address = next(row["input"] for row in fixtures["equalities"] if row["name"] == "address_equal")
    for label, edit in (
        (
            "missing address extents",
            lambda v: v["root"][4][2].__setitem__(4, v["root"][4][2][4][0]),
        ),
        ("invalid input extent", lambda v: v["root"][4][2][4].__setitem__(1, 2**31)),
        ("legacy schema downgrade", lambda v: v.pop("schema")),
    ):
        altered = copy.deepcopy(address)
        edit(altered)
        try:
            capture(altered, model)
        except ValueError:
            controls.append(label)
        else:
            raise ValueError("address capture corruption accepted: " + label)
    value = fixtures["fixtures"][0]["input"]
    for name, mutate in (
        ("wrong schema", lambda v: v.update(host_pointer=1)),
        ("false frontier", lambda v: v.update(prefix_status="head_limit")),
        ("wrong SDK payload", lambda v: v["root"][4][2].__setitem__(4, "0x100")),
        ("unknown node", lambda v: v["root"].__setitem__(0, "host")),
        (
            "unbounded owner token",
            lambda v: v["root"][4].__setitem__(2, [model["mops"]["S"], 4, 0, 0, [513, 0]]),
        ),
    ):
        bad = copy.deepcopy(value)
        mutate(bad)
        try:
            capture(bad, model)
        except ValueError:
            controls.append(name)
        else:
            raise ValueError("corruption accepted: " + name)
    print(
        json.dumps(
            {"passed": True, "controls": controls, "fixture_count": len(fixtures["fixtures"])}
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
