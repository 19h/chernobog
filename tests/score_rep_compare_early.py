"""Score exact early-stop count targets against an independently decoded edge oracle."""

import argparse
import copy
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import capstone

import score_native_edge_benchmark_v2 as prior

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "tests/vmp_native/edge_oracle_v3.json"
DELTA = ROOT / "tests/vmp_native/edge_oracle_early_stop.json"
DELTA_SHA256 = "19c5041faba7214f5c0037ccbc79279a70c41a86aa64554ba171080553fb36b8"
NEW = {"df_repne_cmps_two_count_target", "df_repe_scas_two_count_target"}


def contract():
    prior.require(prior.digest(DELTA) == DELTA_SHA256, "early-stop oracle changed")
    delta = json.loads(DELTA.read_text())
    prior.require(delta["schema"] == 1 and delta["base"] == prior.relative(BASE), "invalid delta")
    prior.require(prior.digest(BASE) == delta["base_sha256"], "base oracle changed")
    oracle = copy.deepcopy(json.loads(BASE.read_text()))
    prior.require(oracle["schema"] == 3, "invalid base oracle")
    prior.require(
        set(delta["fixed"]) == NEW and not NEW.intersection(oracle["fixed"]), "fixed roots overlap"
    )
    oracle["scope"] = delta["scope"]
    oracle["fixed"].update(delta["fixed"])
    oracle["source_sha256"].update(delta["source_sha256"])
    oracle["native_checks"] = delta["native_checks"]
    oracle["expected_population"] = delta["expected_population"]
    for name, expected in oracle["source_sha256"].items():
        prior.require(prior.digest(ROOT / name) == expected, "reviewed source changed: " + name)
    groups = [set(oracle[name]) for name in ("fixed", "dynamic", "concrete_only")]
    prior.require(len(set.union(*groups)) == sum(map(len, groups)), "overlapping oracle classes")
    prior.require(
        oracle["expected_population"]
        == {
            "fixed_sites": len(groups[0]),
            "dynamic_sites": len(groups[1]),
            "eligible_sites": len(groups[0]) + len(groups[1]),
            "oracle_edges": len(groups[0]) + sum(map(len, oracle["dynamic"].values())),
            "concrete_only_sites": len(groups[2]),
        },
        "oracle population contradiction",
    )
    return oracle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owned-report", type=Path, required=True)
    parser.add_argument("--ownerless-report", type=Path, required=True)
    parser.add_argument("--nm", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    result = {"schema": 1, "passed": False, "runs": []}
    try:
        oracle = contract()
        pins = {
            BASE: prior.digest(BASE),
            DELTA: DELTA_SHA256,
            Path(__file__): prior.digest(__file__),
            Path(prior.__file__): prior.digest(prior.__file__),
            args.nm: prior.digest(args.nm),
            Path(capstone.__file__): prior.digest(capstone.__file__),
            Path(capstone._cs._name): prior.digest(capstone._cs._name),
        }
        pins.update({ROOT / name: value for name, value in oracle["source_sha256"].items()})
        owned, first = prior.load_report(args.owned_report, True, oracle, args.nm, pins)
        ownerless, second = prior.load_report(args.ownerless_report, False, oracle, args.nm, pins)
        prior.require(
            owned["plugin_sha256"] == ownerless["plugin_sha256"]
            and owned["ida_sha256"] == ownerless["ida_sha256"],
            "unmatched plugin or IDA profiles",
        )
        result["attribution_controls"] = prior.attribution_controls(
            args.owned_report, args.ownerless_report, oracle, args.nm
        )
        result["runs"] = first + second
        for run in result["runs"]:
            selected = {row["name"]: row for row in run["cases"] if row["name"] in NEW}
            prior.require(set(selected) == NEW, "early-stop root missing")
            expected = "correct" if run["architecture"] == "x86_64" else "unresolved"
            prior.require(
                all(row["edge_outcome"] == expected for row in selected.values()),
                "early-stop edge classification differs",
            )
            prior.require(
                run["counts"]["false_edges"] == 0 and run["counts"]["unsound_covers"] == 0,
                "false edge or unsound cover",
            )
        result.update(
            {
                "scope": oracle["scope"],
                "oracle_delta_sha256": DELTA_SHA256,
                "oracle_base_sha256": pins[BASE],
                "artifact_sha256": {
                    prior.relative(path): value
                    for path, value in pins.items()
                    if path.resolve().is_relative_to(ROOT)
                },
                "input_reports": [
                    prior.relative(args.owned_report),
                    prior.relative(args.ownerless_report),
                ],
                "plugin_sha256": owned["plugin_sha256"],
                "ida_sha256": owned["ida_sha256"],
                "nm_sha256": pins[args.nm],
                "capstone_version": capstone.__version__,
            }
        )
        for path, expected in pins.items():
            prior.require(prior.digest(path) == expected, "artifact changed during scoring")
        result["passed"] = True
    except Exception as error:
        result["failure"] = type(error).__name__ + ": " + str(error)
    destination = args.output_dir / "rep_compare_early_score.json"
    destination.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": result["passed"],
                "failure": result.get("failure"),
                "scores": [
                    [
                        row["architecture"],
                        row["analysis"],
                        row["counts"]["correct_edges"],
                        row["counts"]["oracle_edges"],
                    ]
                    for row in result["runs"]
                ],
            }
        )
    )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
