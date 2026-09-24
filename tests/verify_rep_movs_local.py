"""Compare matched REP MOVS local-memory probes and frozen edge scores."""

import argparse
import hashlib
import json
from pathlib import Path

TARGETS = {"df_rep_movs_zero_target", "df_rep_movs_one_disjoint_target"}
CONDITIONS = {"df_rep_movs_zero_preserve", "df_rep_movs_one_reload"}
CHANGED = TARGETS | CONDITIONS
ZERO_CASES = {"df_rep_movs_zero_target", "df_rep_movs_zero_preserve"}
FIELDS = (
    "kind",
    "site",
    "truth",
    "status",
    "edge",
    "target",
    "value",
    "condition_value",
    "target_basis",
    "target_proof",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run_by_arch(report, architecture):
    matches = [run for run in report["runs"] if run["architecture"] == architecture]
    require(len(matches) == 1, "missing or duplicate architecture")
    return matches[0]


def rows(capture, mode):
    data = capture if mode == "owned" else capture.get("facts", {})
    return [
        row
        for row in data.get("records", [])
        if row.get("kind") in ("stack-transfer", "push-return", "setcc-value")
    ]


def projection(capture, mode):
    return sorted(
        json.dumps({key: row.get(key) for key in FIELDS}, sort_keys=True)
        for row in rows(capture, mode)
    )


def check_selected(capture, mode, current, architecture):
    for name in TARGETS:
        selected = [
            row
            for row in rows(capture[name], mode)
            if row["kind"] in ("stack-transfer", "push-return")
        ]
        require(len(selected) == 1, "target transfer absent or duplicate")
        row = selected[0]
        proved = current and (architecture == "x86_64" or name in ZERO_CASES)
        if mode == "owned":
            require(
                row["truth"] == ("native-proof" if proved else "candidate")
                and row["edge"] == ("true" if proved else "false")
                and row["target_basis"] == ("memory-definition" if proved else "unresolved"),
                "owned target classification mismatch",
            )
        else:
            require(
                row["status"] == ("proved" if proved else "unresolved")
                and row["target_proof"] == ("memory-definition" if proved else "unresolved"),
                "ownerless target classification mismatch",
            )
        require(
            (
                row.get("target", "unknown") != "unknown"
                if proved
                else row.get("target", "unknown") == "unknown"
            ),
            "target availability mismatch",
        )
    for name in CONDITIONS:
        selected = [row for row in rows(capture[name], mode) if row["kind"] == "setcc-value"]
        proved = current and (architecture == "x86_64" or name in ZERO_CASES)
        if mode == "owned":
            require(
                (
                    (
                        len(selected) == 1
                        and selected[0]["truth"] == "native-proof"
                        and selected[0]["value"] == "0x1"
                    )
                    if proved
                    else not selected
                ),
                "owned condition classification mismatch",
            )
        else:
            require(
                len(selected) == 1
                and selected[0]["status"] == ("proved" if proved else "unresolved")
                and selected[0]["value"] == ("0x1" if proved else "unknown"),
                "ownerless condition classification mismatch",
            )


def load_inspection(report_path, mode, architecture):
    filename = "dataflow.json" if mode == "owned" else "ownerless_dataflow.json"
    return json.loads((report_path.parent / architecture / "inspection" / filename).read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for profile in ("current", "prior"):
        for mode in ("owned", "ownerless"):
            parser.add_argument(f"--{profile}-{mode}", required=True, type=Path)
        parser.add_argument(f"--{profile}-score", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    paths = {
        (profile, mode): getattr(args, profile + "_" + mode)
        for profile in ("current", "prior")
        for mode in ("owned", "ownerless")
    }
    reports = {key: json.loads(path.read_text()) for key, path in paths.items()}
    scores = {
        profile: json.loads(getattr(args, profile + "_score").read_text())
        for profile in ("current", "prior")
    }
    require(all(report["passed"] for report in reports.values()), "input runner failed")
    current_plugin = reports["current", "owned"]["plugin_sha256"]
    prior_plugin = reports["prior", "owned"]["plugin_sha256"]
    require(current_plugin != prior_plugin, "matched plugin control absent")
    ida_hash = reports["current", "owned"]["ida_sha256"]
    for profile in ("current", "prior"):
        for mode in ("owned", "ownerless"):
            report = reports[profile, mode]
            require(report["ida_sha256"] == ida_hash, "IDA executable mismatch")
            require(
                report["plugin_sha256"]
                == (current_plugin if profile == "current" else prior_plugin),
                "profile plugin mismatch",
            )
            require(
                report["source_sha256"] == reports["current", mode]["source_sha256"],
                "matched source mismatch",
            )
        score = scores[profile]
        require(
            score["plugin_sha256"] == (current_plugin if profile == "current" else prior_plugin)
            and score["ida_sha256"] == ida_hash,
            "score tool identity mismatch",
        )
        require(
            set(score["input_report_sha256"].values())
            == {digest(paths[profile, mode]) for mode in ("owned", "ownerless")},
            "score input report mismatch",
        )
        for source, value in score["oracle_source_sha256"].items():
            require(
                reports[profile, "owned"]["source_sha256"][source] == value,
                "scored oracle source mismatch",
            )
    result = {
        "schema": 1,
        "matched_plugin_sha256": {"current": current_plugin, "prior": prior_plugin},
        "ida_sha256": ida_hash,
        "input_sha256": {
            f"{profile}_{mode}": digest(path) for (profile, mode), path in paths.items()
        },
        "score_sha256": {
            profile: digest(getattr(args, profile + "_score")) for profile in ("current", "prior")
        },
        "architectures": [],
    }
    for architecture in ("x86_64", "i386"):
        row = {"architecture": architecture, "changed_captures": {}, "edge_counts": {}}
        for mode in ("owned", "ownerless"):
            current_run = run_by_arch(reports["current", mode], architecture)
            prior_run = run_by_arch(reports["prior", mode], architecture)
            if mode == "owned":
                require(
                    current_run["binary_sha256"] == prior_run["binary_sha256"],
                    "owned binary mismatch",
                )
                expected_checks = 33278 if architecture == "x86_64" else 31998
                require(
                    current_run["native_result"]
                    == prior_run["native_result"]
                    == {"checks": expected_checks, "passed": True},
                    "native process oracle mismatch",
                )
            else:
                require(
                    current_run["executions"][0]["binary_sha256"]
                    == prior_run["executions"][0]["binary_sha256"],
                    "ownerless binary mismatch",
                )
                for run in (current_run, prior_run):
                    require(
                        [entry["native"]["exit_code"] for entry in run["executions"]] == [0, 1],
                        "ownerless corrupted oracle not rejected",
                    )
            current = load_inspection(paths["current", mode], mode, architecture)["captures"]
            prior = load_inspection(paths["prior", mode], mode, architecture)["captures"]
            require(current.keys() == prior.keys(), "capture inventory mismatch")
            changed = sorted(
                name
                for name in current
                if projection(current[name], mode) != projection(prior[name], mode)
            )
            require(
                changed == (sorted(CHANGED) if architecture == "x86_64" else sorted(ZERO_CASES)),
                "unexpected changed captures",
            )
            for capture, is_current in ((current, True), (prior, False)):
                check_selected(capture, mode, is_current, architecture)
            require(
                projection(current["df_rep_movs_disjoint_target"], mode)
                == projection(prior["df_rep_movs_disjoint_target"], mode),
                "variable-count negative changed",
            )
            row["changed_captures"][mode] = changed
            for profile in ("current", "prior"):
                matching = [
                    entry
                    for entry in scores[profile]["architectures"]
                    if entry["architecture"] == architecture
                ]
                require(len(matching) == 1, "score architecture absent")
                count = matching[0]["counts"][mode]
                expected_correct = 40 if profile == "current" else 38
                if architecture == "i386":
                    expected_correct = 31 if profile == "current" else 30
                require(
                    count["oracle_edges"] == 48
                    and count["correct_edges"] == expected_correct
                    and count["false_edges"] == 0,
                    "frozen edge score mismatch",
                )
                row["edge_counts"][f"{profile}_{mode}"] = count
        result["architectures"].append(row)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passed": True, "architectures": 2, "matched_profiles": 4}))


if __name__ == "__main__":
    main()
