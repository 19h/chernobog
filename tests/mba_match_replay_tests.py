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
    for row in fixtures["fixtures"]:
        _, templates = catalog(row["pattern_catalog"])
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
        value = capture(row["input"], model)
        difference = operand_difference(value["root"][4][2], value["root"][5][2], model)
        require((difference is None) == row["equal"], "C++/independent strict equality")
        if difference is not None:
            failure = parse_match_failure(row["failure"])
            require(failure["kind"] == difference[0], "strict first field")
            if len(difference) == 3:
                require((failure["expected"], failure["actual"]) == difference[1:], "strict values")
        controls.append(row["name"])
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
