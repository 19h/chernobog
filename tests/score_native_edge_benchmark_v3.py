"""Score current probes against the unchanged population with a separate frozen contract."""

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from score_native_edge_benchmark_v2 import (
    ROOT,
    attribution_controls,
    capstone,
    digest,
    load_report,
    relative,
    require,
)

CONTRACT = ROOT / "tests/vmp_native/edge_oracle_v3.json"
CONTRACT_SHA256 = "6376601f6d4b75748bc9b4d9ebd03bee3e74f6e6e652bce4dcb69ab1e7af07ed"


def contract():
    require(digest(CONTRACT) == CONTRACT_SHA256, "oracle contract changed")
    result = json.loads(CONTRACT.read_text())
    require(result["schema"] == 3, "invalid oracle schema")
    for name, expected in result["source_sha256"].items():
        require(digest(ROOT / name) == expected, "reviewed source changed: " + name)
    classes = [set(result[name]) for name in ("fixed", "dynamic", "concrete_only")]
    require(len(set.union(*classes)) == sum(map(len, classes)), "overlapping oracle classes")
    require(
        result["expected_population"]
        == {
            "fixed_sites": len(classes[0]),
            "dynamic_sites": len(classes[1]),
            "eligible_sites": len(classes[0]) + len(classes[1]),
            "oracle_edges": len(classes[0]) + sum(map(len, result["dynamic"].values())),
            "concrete_only_sites": len(classes[2]),
        },
        "oracle population contradiction",
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owned-report", required=True, type=Path)
    parser.add_argument("--ownerless-report", required=True, type=Path)
    parser.add_argument("--nm", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": 3, "passed": False, "runs": []}
    try:
        oracle = contract()
        pins = {
            CONTRACT: CONTRACT_SHA256,
            Path(__file__): digest(__file__),
            args.nm: digest(args.nm),
            Path(capstone.__file__): digest(capstone.__file__),
            Path(capstone._cs._name): digest(capstone._cs._name),
        }
        pins.update({ROOT / name: h for name, h in oracle["source_sha256"].items()})
        first, runs = load_report(args.owned_report, True, oracle, args.nm, pins)
        second, others = load_report(args.ownerless_report, False, oracle, args.nm, pins)
        require(
            first["plugin_sha256"] == second["plugin_sha256"]
            and first["ida_sha256"] == second["ida_sha256"],
            "unmatched IDA or plugin profiles",
        )
        report["attribution_controls"] = attribution_controls(
            args.owned_report, args.ownerless_report, oracle, args.nm
        )
        report.update(
            {
                "oracle_contract_sha256": CONTRACT_SHA256,
                "artifact_sha256": {
                    relative(p): h for p, h in pins.items() if p.resolve().is_relative_to(ROOT)
                },
                "input_reports": [relative(args.owned_report), relative(args.ownerless_report)],
                "plugin_sha256": first["plugin_sha256"],
                "ida_sha256": first["ida_sha256"],
                "nm_sha256": pins[args.nm],
                "capstone": {
                    "version": capstone.__version__,
                    "binding_sha256": pins[Path(capstone.__file__)],
                    "library_sha256": pins[Path(capstone._cs._name)],
                },
                "scope": oracle["scope"],
                "runs": runs + others,
            }
        )
        for path, expected in pins.items():
            require(digest(path) == expected, "scored artifact changed during measurement")
        report["passed"] = all(
            r["counts"]["false_edges"] == 0 and r["counts"]["unsound_covers"] == 0
            for r in report["runs"]
        )
    except Exception as error:
        report["failure"] = type(error).__name__ + (
            ": " + str(error) if isinstance(error, ValueError) else ""
        )
    (output / "native_edge_benchmark_v3.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "failure": report.get("failure"),
                "runs": [
                    {
                        "architecture": r["architecture"],
                        "analysis": r["analysis"],
                        "counts": r["counts"],
                        "mutation_controls": len(r["mutation_controls"]),
                    }
                    for r in report["runs"]
                ],
            }
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
