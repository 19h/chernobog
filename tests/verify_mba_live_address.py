"""Verify paired live SDK-owned address-extent matcher controls."""

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


def load_run(directory, status):
    report_bytes = (directory / "mba_address.json").read_bytes()
    run_bytes = (directory / "run.json").read_bytes()
    report = json.loads(report_bytes)
    run = json.loads(run_bytes)
    require(report["schema"] == 1 and run["schema_version"] == 2, "schema")
    require(report["status"] == status and report["passed"] == (status == 0), "result status")
    require(run["process_return_code"] == (0 if status == 0 else 1), "process exit")
    require(run["runner_return_code"] == (0 if status == 0 else 1), "runner exit")
    require(run["expected_log_found"] and not run["internal_error_found"], "IDA log")
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
        require(run[field], "run integrity: " + field)
    require(report["plugin_sha256"] == run["plugin_sha256"], "plugin manifest")
    require(report["source_sha256"] == run["script_sha256"], "probe manifest")
    require(
        digest((directory / "idauser/plugins/chernobog.dylib").read_bytes())
        == report["plugin_sha256"],
        "plugin copy",
    )
    require(
        digest((directory / "probe/ida_mba_address_probe.py").read_bytes())
        == report["source_sha256"],
        "probe copy",
    )
    require(
        digest((directory / "flag-values-oracle").read_bytes()) == run["input_sha256"], "input copy"
    )
    require(run["ida_sha256"] == run["ida_sha256_after"], "IDA identity")
    marker = "[chernobog][mba-address] " + ("PASS" if status == 0 else "FAIL")
    require(marker in (directory / "ida.log").read_text(errors="replace"), "IDA log marker")
    return report, run, digest(report_bytes), digest(run_bytes)


def valid_current(report):
    return (
        report["key_bytes"] == 64
        and report["equal_matches"]
        and report["input_key_distinct"]
        and report["input_operands_differ"]
        and report["input_copies_preserved"]
        and not report["input_matches"]
        and report["input_failure"] == 22
        and report["output_key_distinct"]
        and report["output_operands_differ"]
        and report["output_copies_preserved"]
        and not report["output_matches"]
        and report["output_failure"] == 23
        and report["reason"] == "complete"
    )


def valid_prior(report):
    return (
        report["key_bytes"] == 64
        and report["equal_matches"]
        and not report["input_key_distinct"]
        and report["input_operands_differ"]
        and not report["input_copies_preserved"]
        and report["input_matches"]
        and report["input_failure"] == 0
        and not report["output_key_distinct"]
        and report["output_operands_differ"]
        and not report["output_copies_preserved"]
        and report["output_matches"]
        and report["output_failure"] == 0
        and report["reason"] == "input_extent_binding_failed"
    )


def paired(prior, keyed, current, bridge):
    old, old_run, old_report_hash, old_run_hash = load_run(prior, 6)
    middle, middle_run, middle_report_hash, middle_run_hash = load_run(keyed, 0)
    new, new_run, new_report_hash, new_run_hash = load_run(current, 0)
    for field in (
        "input_sha256",
        "source_input_sha256",
        "script_sha256",
        "source_script_sha256",
        "ida_sha256",
        "chernobog_environment_sha256",
    ):
        require(
            old_run[field] == middle_run[field] == new_run[field], "paired environment: " + field
        )
    require(old_run["input_sha256"] == old_run["source_input_sha256"], "input source")
    require(old_run["script_sha256"] == old_run["source_script_sha256"], "probe source")
    require(
        old["bridge_sha256"] == middle["bridge_sha256"] == new["bridge_sha256"], "bridge identity"
    )
    require(digest(bridge.read_bytes()) == new["bridge_sha256"], "bridge binary")
    require(
        len({old["plugin_sha256"], middle["plugin_sha256"], new["plugin_sha256"]}) == 3,
        "plugin transition",
    )
    require(valid_prior(old) and valid_current(middle) and valid_current(new), "extent transition")
    mutated = copy.deepcopy(new)
    mutated["input_matches"] = True
    require(not valid_current(mutated), "mutation rejection")
    return {
        "schema": 1,
        "passed": True,
        "scope": "SDK-owned mop_a input/output extent differences through full AST and repeated matcher binding",
        "prior_report_sha256": old_report_hash,
        "keyed_report_sha256": middle_report_hash,
        "current_report_sha256": new_report_hash,
        "prior_run_sha256": old_run_hash,
        "keyed_run_sha256": middle_run_hash,
        "current_run_sha256": new_run_hash,
        "prior_plugin_sha256": old["plugin_sha256"],
        "keyed_plugin_sha256": middle["plugin_sha256"],
        "current_plugin_sha256": new["plugin_sha256"],
        "bridge_sha256": new["bridge_sha256"],
        "probe_sha256": new["source_sha256"],
        "input_sha256": new_run["input_sha256"],
        "ida_sha256": new_run["ida_sha256"],
        "environment_sha256": new_run["chernobog_environment_sha256"],
        "prior_matches": [old["input_matches"], old["output_matches"]],
        "keyed_matches": [middle["input_matches"], middle["output_matches"]],
        "current_matches": [new["input_matches"], new["output_matches"]],
        "current_failure_kinds": [new["input_failure"], new["output_failure"]],
        "current_copies_preserved": [
            new["input_copies_preserved"],
            new["output_copies_preserved"],
        ],
        "match_mutation_rejected": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior", type=Path, required=True)
    parser.add_argument("--keyed", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = paired(args.prior, args.keyed, args.current, args.bridge)
    if args.evidence is not None:
        evidence = json.loads(args.evidence.read_text())
        require(evidence["schema"] == 1 and evidence["passed"], "evidence schema")
        for name, field in (
            ("tests/verify_mba_live_address.py", "verifier_sha256"),
            ("tests/ida_mba_address_bridge.cpp", "bridge_source_sha256"),
            ("tests/ida_mba_address_probe.py", "probe_source_sha256"),
        ):
            require(evidence[field] == digest(Path(name).read_bytes()), "source pin: " + name)
        require(evidence["result"] == result, "recorded result")
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print("MBA live address-extent matcher: pass")


if __name__ == "__main__":
    main()
