"""Verify the paired live Hex-Rays AST-cache collision controls."""

import argparse
import copy
import hashlib
import json
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, label):
    if not condition:
        raise ValueError(label)


def valid_current(report):
    return (
        report["key_bytes"] == 64
        and report["ast_visits"] == 11
        and report["left_dest"] == 102
        and report["right_dest"] == 103
        and report["distinct_children"]
        and report["copied_operands_equal"]
    )


def load_run(directory, expected_status):
    report_bytes = (directory / "mba_collision.json").read_bytes()
    manifest_bytes = (directory / "run.json").read_bytes()
    report = json.loads(report_bytes)
    manifest = json.loads(manifest_bytes)
    require(report["schema"] == 1 and manifest["schema_version"] == 2, "schema")
    require(report["status"] == expected_status, "bridge status")
    require(report["passed"] == (expected_status == 0), "bridge outcome")
    require(manifest["process_return_code"] == (0 if expected_status == 0 else 1), "process exit")
    require(manifest["runner_return_code"] == (0 if expected_status == 0 else 1), "runner exit")
    require(manifest["expected_log_found"] and not manifest["internal_error_found"], "IDA log")
    require(
        manifest["expected_log_pattern"].endswith("PASS" if expected_status == 0 else "FAIL"),
        "log pattern",
    )
    for field in (
        "plugin_unchanged",
        "script_unchanged",
        "source_script_unchanged",
        "source_input_unchanged",
        "input_copy_matches_source",
        "ida_unchanged",
        "artifacts_unchanged",
        "local_paths_redacted",
    ):
        require(manifest[field], "manifest integrity: " + field)
    require(report["plugin_sha256"] == manifest["plugin_sha256"], "plugin digest")
    require(report["source_sha256"] == manifest["script_sha256"], "probe digest")
    require(
        digest((directory / "idauser/plugins/chernobog.dylib").read_bytes())
        == report["plugin_sha256"],
        "plugin copy",
    )
    require(
        digest((directory / "probe/ida_mba_collision_probe.py").read_bytes())
        == report["source_sha256"],
        "probe copy",
    )
    require(
        digest((directory / "flag-values-oracle").read_bytes()) == manifest["input_sha256"],
        "input copy",
    )
    require(manifest["ida_sha256"] == manifest["ida_sha256_after"], "IDA digest")
    log = (directory / "ida.log").read_text(errors="replace")
    require(
        "[chernobog][mba-collision] " + ("PASS" if expected_status == 0 else "FAIL") in log,
        "IDA log result",
    )
    return report, manifest, digest(report_bytes), digest(manifest_bytes)


def paired(prior, current, bridge):
    old, old_run, old_report_hash, old_run_hash = load_run(prior, 6)
    new, new_run, new_report_hash, new_run_hash = load_run(current, 0)
    for field in (
        "input_sha256",
        "source_input_sha256",
        "script_sha256",
        "source_script_sha256",
        "ida_sha256",
        "chernobog_environment_sha256",
    ):
        require(old_run[field] == new_run[field], "paired environment: " + field)
    require(old_run["input_sha256"] == old_run["source_input_sha256"], "input source")
    require(old_run["script_sha256"] == old_run["source_script_sha256"], "probe source")
    require(old["bridge_sha256"] == new["bridge_sha256"], "bridge identity")
    require(digest(bridge.read_bytes()) == new["bridge_sha256"], "bridge binary")
    require(old["plugin_sha256"] != new["plugin_sha256"], "plugin transition")
    require(old["reason"] == "ast_collision_merge", "prior collision response")
    require(
        set(old)
        == {
            "bridge_sha256",
            "passed",
            "plugin_sha256",
            "reason",
            "schema",
            "source_sha256",
            "status",
        },
        "prior result shape",
    )
    require(valid_current(new), "AST identity")
    altered = copy.deepcopy(new)
    altered["right_dest"] = altered["left_dest"]
    require(not valid_current(altered), "mutation control")
    return {
        "schema": 1,
        "passed": True,
        "scope": "constructed SDK-owned nested operand collision in paired isolated IDA processes",
        "prior_report_sha256": old_report_hash,
        "current_report_sha256": new_report_hash,
        "prior_run_sha256": old_run_hash,
        "current_run_sha256": new_run_hash,
        "prior_plugin_sha256": old["plugin_sha256"],
        "current_plugin_sha256": new["plugin_sha256"],
        "bridge_sha256": new["bridge_sha256"],
        "probe_sha256": new["source_sha256"],
        "input_sha256": new_run["input_sha256"],
        "ida_sha256": new_run["ida_sha256"],
        "environment_sha256": new_run["chernobog_environment_sha256"],
        "prior_status": old["status"],
        "current_status": new["status"],
        "key_bytes": new["key_bytes"],
        "ast_visits": new["ast_visits"],
        "destinations": [new["left_dest"], new["right_dest"]],
        "distinct_children": new["distinct_children"],
        "copied_operands_equal": new["copied_operands_equal"],
        "destination_mutation_rejected": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = paired(args.prior, args.current, args.bridge)
    if args.evidence is not None:
        evidence = json.loads(args.evidence.read_text())
        require(evidence["schema"] == 1 and evidence["passed"], "evidence schema")
        for name, field in (
            ("tests/verify_mba_live_collision.py", "verifier_sha256"),
            ("tests/ida_mba_collision_bridge.cpp", "bridge_source_sha256"),
            ("tests/ida_mba_collision_probe.py", "probe_source_sha256"),
        ):
            require(evidence[field] == digest(Path(name).read_bytes()), "source pin: " + name)
        require(evidence["result"] == result, "recorded result")
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print("MBA live AST collision: pass")


if __name__ == "__main__":
    main()
