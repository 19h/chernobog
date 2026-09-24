"""Compare matched known-count REPE/REPNE SCAS and CMPS evidence."""

import argparse
import hashlib
import json
from pathlib import Path

ZERO_CONDITIONS = {"df_repe_cmps_zero_preserve", "df_repne_scas_zero_preserve"}
ONE_CONDITIONS = {
    "df_repne_cmps_one_cf",
    "df_repe_cmps_one_zf",
    "df_repe_scas_one_cf",
    "df_repne_scas_one_zf",
}
COUNT_TARGETS = {"df_repe_cmps_one_count_target", "df_repne_scas_one_count_target"}
CHANGED_64 = ZERO_CONDITIONS | ONE_CONDITIONS | COUNT_TARGETS
CHANGED_32 = ZERO_CONDITIONS | COUNT_TARGETS
FIELDS = (
    "kind",
    "site",
    "truth",
    "status",
    "edge",
    "target",
    "value",
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


def check_selected(captures, mode, architecture, current):
    for name in sorted(COUNT_TARGETS):
        selected = [
            row
            for row in rows(captures[name], mode)
            if row["kind"] == ("stack-transfer" if mode == "owned" else "push-return")
        ]
        require(len(selected) == 1, "count target absent or duplicated")
        row = selected[0]
        if mode == "owned":
            require(
                row["truth"] == ("native-proof" if current else "candidate")
                and row["edge"] == ("true" if current else "false")
                and row["target_basis"] == ("register-definition" if current else "unresolved"),
                "owned count-target classification mismatch",
            )
        else:
            require(
                row["status"] == ("proved" if current else "unresolved")
                and row["target_proof"] == ("register-definition" if current else "unresolved"),
                "ownerless count-target classification mismatch",
            )
        require(
            (row.get("target", "unknown") != "unknown") == current,
            "count target availability mismatch",
        )
    for name in sorted(ZERO_CONDITIONS | ONE_CONDITIONS):
        selected = [row for row in rows(captures[name], mode) if row["kind"] == "setcc-value"]
        proved = current and (name in ZERO_CONDITIONS or architecture == "x86_64")
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


def load_captures(report_path, mode, architecture):
    filename = "dataflow.json" if mode == "owned" else "ownerless_dataflow.json"
    return json.loads((report_path.parent / architecture / "inspection" / filename).read_text())[
        "captures"
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for profile in ("current", "prior"):
        for mode in ("owned", "ownerless"):
            parser.add_argument(f"--{profile}-{mode}", required=True, type=Path)
        parser.add_argument(f"--{profile}-score", required=True, type=Path)
        parser.add_argument(f"--{profile}-protected", required=True, type=Path)
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
        protected_path = getattr(args, profile + "_protected")
        protected = json.loads(protected_path.read_text())
        run = json.loads((protected_path.parent / "run.json").read_text())
        require(
            run["plugin_sha256"] == (current_plugin if profile == "current" else prior_plugin)
            and run["ida_sha256"] == ida_hash
            and run["input_sha256"]
            == "c61935fe4f8a66a6d36e8c0027341a55b816833005dc0006dc0fdbdb342938a5"
            and run["runner_return_code"] == 0,
            "protected tool or input mismatch",
        )
        require(
            len(protected["checks"]) == 8
            and all(check["passed"] for check in protected["checks"])
            and protected["inventory_before"] == protected["inventory_after"]
            and len(protected["inspection"]["nodes"]) == 75
            and len(protected["inspection"]["edges"]) == 77
            and sum(row.get("status") == "unresolved" for row in protected["inspection"]["records"])
            == 3,
            "protected selected-root scope mismatch",
        )
    current_protected = args.current_protected.read_bytes()
    require(current_protected == args.prior_protected.read_bytes(), "protected report changed")
    result = {
        "schema": 1,
        "plugin_sha256": {"current": current_plugin, "prior": prior_plugin},
        "ida_sha256": ida_hash,
        "input_sha256": {
            f"{profile}_{mode}": digest(path) for (profile, mode), path in paths.items()
        },
        "score_sha256": {
            profile: digest(getattr(args, profile + "_score")) for profile in ("current", "prior")
        },
        "protected_sha256": digest(args.current_protected),
        "architectures": [],
    }
    for architecture in ("x86_64", "i386"):
        row = {"architecture": architecture, "changed_captures": {}, "edge_counts": {}}
        for mode in ("owned", "ownerless"):
            current_run = run_by_arch(reports["current", mode], architecture)
            prior_run = run_by_arch(reports["prior", mode], architecture)
            if mode == "owned":
                expected_checks = 35838 if architecture == "x86_64" else 34558
                require(
                    current_run["binary_sha256"] == prior_run["binary_sha256"]
                    and current_run["native_result"]
                    == prior_run["native_result"]
                    == {"checks": expected_checks, "passed": True},
                    "owned binary or native oracle mismatch",
                )
            else:
                require(
                    [entry["binary_sha256"] for entry in current_run["executions"]]
                    == [entry["binary_sha256"] for entry in prior_run["executions"]],
                    "ownerless binary mismatch",
                )
                for run in (current_run, prior_run):
                    require(
                        [entry["native"]["exit_code"] for entry in run["executions"]] == [0, 1],
                        "ownerless corrupted oracle not rejected",
                    )
            current = load_captures(paths["current", mode], mode, architecture)
            prior = load_captures(paths["prior", mode], mode, architecture)
            require(current.keys() == prior.keys(), "capture inventory mismatch")
            changed = sorted(
                name
                for name in current
                if projection(current[name], mode) != projection(prior[name], mode)
            )
            require(
                changed == sorted(CHANGED_64 if architecture == "x86_64" else CHANGED_32),
                "unexpected changed captures",
            )
            for captures, is_current in ((current, True), (prior, False)):
                check_selected(captures, mode, architecture, is_current)
            for name in (
                "df_rep_scas_count_ambiguity",
                "df_rep_cmps_count_ambiguity",
                "df_repe_scas_two_early_stop",
                "df_repne_cmps_two_early_stop",
            ):
                require(
                    projection(current[name], mode) == projection(prior[name], mode),
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
                expected_correct = (
                    (42 if profile == "current" else 40)
                    if architecture == "x86_64"
                    else (33 if profile == "current" else 31)
                )
                expected_unresolved = (
                    (5 if profile == "current" else 7)
                    if architecture == "x86_64"
                    else (14 if profile == "current" else 16)
                )
                require(
                    count["oracle_edges"] == 50
                    and count["correct_edges"] == expected_correct
                    and count["false_edges"] == 0
                    and count["unresolved_candidates"] == expected_unresolved,
                    "frozen edge score mismatch",
                )
                row["edge_counts"][f"{profile}_{mode}"] = count
        result["architectures"].append(row)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passed": True, "architectures": 2, "matched_profiles": 4}))


if __name__ == "__main__":
    main()
