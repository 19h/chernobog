"""Verify real SDK-produced stack-address operands across three plugin stages."""

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
    result_bytes = (directory / "mba_observed_address.json").read_bytes()
    manifest_bytes = (directory / "run.json").read_bytes()
    result = json.loads(result_bytes)
    manifest = json.loads(manifest_bytes)
    require(result["schema"] == 1 and manifest["schema_version"] == 2, "schema")
    require(result["status"] == status and result["passed"] == (status == 0), "status")
    require(manifest["process_return_code"] == (0 if status == 0 else 1), "process status")
    require(manifest["runner_return_code"] == (0 if status == 0 else 1), "runner status")
    require(manifest["expected_log_found"] and not manifest["internal_error_found"], "IDA log")
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
    require(result["plugin_sha256"] == manifest["plugin_sha256"], "plugin manifest")
    require(result["source_sha256"] == manifest["script_sha256"], "probe manifest")
    require(
        digest((directory / "idauser/plugins/chernobog.dylib").read_bytes())
        == result["plugin_sha256"],
        "plugin copy",
    )
    require(
        digest((directory / "probe/ida_mba_observed_address_probe.py").read_bytes())
        == result["source_sha256"],
        "probe copy",
    )
    require(
        digest((directory / "virtualization-0").read_bytes()) == manifest["input_sha256"],
        "input copy",
    )
    require(manifest["ida_sha256"] == manifest["ida_sha256_after"], "IDA identity")
    marker = "[chernobog][mba-observed-address] " + ("PASS" if status == 0 else "FAIL")
    require(marker in (directory / "ida.log").read_text(errors="replace"), "IDA log marker")
    return result, manifest, digest(result_bytes), digest(manifest_bytes)


def source_identity(report):
    return (
        report["function_ea"] == 0x806F37B
        and report["source_ea"] == 0x8073510
        and report["maturity"] == 5
        and report["source_kind"] == 10
        and report["referent_kind"] == 5
        and report["source_size"] == 4
        and report["input_extent"] == -1
        and report["output_extent"] == -1
        and report["stack_offset"] == 140
        and report["source_preserved"]
        and report["input_strict_differs"]
        and report["output_strict_differs"]
    )


def valid_prior(report):
    return (
        source_identity(report)
        and not report["input_key_distinct"]
        and not report["input_copies_preserved"]
        and report["input_matches"]
        and report["input_failure"] == 0
        and not report["output_key_distinct"]
        and not report["output_copies_preserved"]
        and report["output_matches"]
        and report["output_failure"] == 0
        and report["reason"] == "extent_match_failed"
    )


def valid_current(report):
    return (
        source_identity(report)
        and report["input_key_distinct"]
        and report["input_copies_preserved"]
        and not report["input_matches"]
        and report["input_failure"] == 22
        and report["output_key_distinct"]
        and report["output_copies_preserved"]
        and not report["output_matches"]
        and report["output_failure"] == 23
        and report["reason"] == "complete"
    )


def checked(prior, keyed, current, bridge):
    old, old_run, old_hash, old_run_hash = load_run(prior, 6)
    middle, middle_run, middle_hash, middle_run_hash = load_run(keyed, 0)
    new, new_run, new_hash, new_run_hash = load_run(current, 0)
    for field in (
        "input_sha256",
        "source_input_sha256",
        "script_sha256",
        "source_script_sha256",
        "ida_sha256",
        "chernobog_environment_sha256",
    ):
        require(old_run[field] == middle_run[field] == new_run[field], "paired identity: " + field)
    require(old_run["input_sha256"] == old_run["source_input_sha256"], "input source")
    require(old_run["script_sha256"] == old_run["source_script_sha256"], "probe source")
    require(
        old["bridge_sha256"] == middle["bridge_sha256"] == new["bridge_sha256"],
        "bridge identity",
    )
    require(digest(bridge.read_bytes()) == new["bridge_sha256"], "bridge binary")
    require(
        len({old["plugin_sha256"], middle["plugin_sha256"], new["plugin_sha256"]}) == 3,
        "plugin transition",
    )
    require(valid_prior(old) and valid_current(middle) and valid_current(new), "matcher transition")
    changed = copy.deepcopy(new)
    changed["input_matches"] = True
    require(not valid_current(changed), "match mutation")
    changed = copy.deepcopy(new)
    changed["stack_offset"] += 1
    require(not valid_current(changed), "source mutation")
    changed = copy.deepcopy(new)
    changed["source_preserved"] = False
    require(not valid_current(changed), "source copy mutation")
    return {
        "schema": 1,
        "passed": True,
        "scope": "SDK-produced mop_a of mop_S; copied extent mutations through full AST and repeated binding",
        "prior_result_sha256": old_hash,
        "keyed_result_sha256": middle_hash,
        "current_result_sha256": new_hash,
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
        "source_function": new["function_ea"],
        "source_ea": new["source_ea"],
        "stack_offset": new["stack_offset"],
        "source_preserved": new["source_preserved"],
        "observed_extents": [new["input_extent"], new["output_extent"]],
        "prior_matches": [old["input_matches"], old["output_matches"]],
        "keyed_matches": [middle["input_matches"], middle["output_matches"]],
        "current_matches": [new["input_matches"], new["output_matches"]],
        "current_failure_kinds": [new["input_failure"], new["output_failure"]],
        "match_mutation_rejected": True,
        "source_mutation_rejected": True,
        "source_copy_mutation_rejected": True,
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
    result = checked(args.prior, args.keyed, args.current, args.bridge)
    if args.evidence is not None:
        evidence = json.loads(args.evidence.read_text())
        require(evidence["schema"] == 1 and evidence["passed"], "evidence schema")
        for name, field in (
            ("tests/verify_mba_observed_address.py", "verifier_sha256"),
            ("tests/ida_mba_observed_address_bridge.cpp", "bridge_source_sha256"),
            ("tests/ida_mba_observed_address_probe.py", "probe_source_sha256"),
        ):
            require(evidence[field] == digest(Path(name).read_bytes()), "source pin: " + name)
        require(evidence["result"] == result, "recorded result")
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print("MBA observed stack-address matcher: pass")


if __name__ == "__main__":
    main()
