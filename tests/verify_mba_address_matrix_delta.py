"""Compare the complete protected MBA matrix across address-capture schemas.

The historical capture has no address extents. The new capture is projected to
that schema only after every SDK-produced extent is checked explicitly. Timing
fields are the only other fields excluded from report equality.
"""

import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path

from mba_match_replay import capture, catalog

ROOT = Path(__file__).resolve().parent.parent
LABELS = (
    "original",
    *(
        f"{mode}-{seed}"
        for mode in ("mutation", "virtualization", "combined")
        for seed in (0, 1, 12648430)
    ),
)
EXPECTED = {
    (architecture, label, disabled)
    for architecture in ("x86_64", "i386")
    for label in LABELS
    for disabled in (True, False)
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def without_duration(value):
    if isinstance(value, dict):
        return {
            key: without_duration(item)
            for key, item in value.items()
            if key != "generation_elapsed_ns"
        }
    if isinstance(value, list):
        return [without_duration(item) for item in value]
    return value


def legacy_operand(value, address_tag):
    """Remove schema-2 extents only when their observed values are -1/-1."""
    if isinstance(value, list):
        if len(value) == 5 and value[0] == address_tag and isinstance(value[4], list):
            require(len(value[4]) == 3, "address extent shape")
            referent, insize, outsize = value[4]
            require((insize, outsize) == (-1, -1), "unobserved address extent")
            converted, nested = legacy_operand(referent, address_tag)
            return [*value[:4], converted], nested + 1
        children = [legacy_operand(item, address_tag) for item in value]
        return [item for item, _ in children], sum(count for _, count in children)
    if isinstance(value, dict):
        children = {key: legacy_operand(item, address_tag) for key, item in value.items()}
        return {key: item for key, (item, _) in children.items()}, sum(
            count for _, count in children.values()
        )
    return value, 0


def checked_artifacts(run, directory):
    artifacts = run["artifact_sha256"]
    require(len(artifacts) == 2, "SDK artifact population")
    found = {}
    for name, expected in artifacts.items():
        path = (ROOT / name).resolve()
        require(path.is_relative_to(directory) and path.is_file(), "SDK artifact path")
        require(digest(path.read_bytes()) == expected, "SDK artifact hash")
        require(path.name in ("run.json", "protected_mba.json"), "SDK artifact name")
        require(path.name not in found, "duplicate SDK artifact")
        found[path.name] = json.loads(path.read_bytes())
    require(set(found) == {"run.json", "protected_mba.json"}, "SDK artifact set")
    probe = found["protected_mba.json"]
    require(probe["architecture"] == run["architecture"], "SDK report architecture")
    require(
        probe["transformations_disabled"] == run["disabled"],
        "SDK report profile",
    )
    measurement = run["measurement"]
    require(
        measurement["exit_code"] == 0
        and not measurement["timed_out"]
        and not measurement["output_exceeded"],
        "SDK measurement",
    )
    return found["run.json"], found["protected_mba.json"]


def check_manifest(run, aggregate, manifest):
    require(manifest["schema_version"] == 2, "SDK run schema")
    require(manifest["input_sha256"] == run["binary_sha256"], "SDK binary identity")
    require(manifest["plugin_sha256"] == aggregate["plugin_sha256"], "SDK plugin identity")
    require(manifest["ida_sha256"] == aggregate["ida_sha256"], "SDK IDA identity")
    require(manifest["runner_return_code"] == manifest["process_return_code"] == 0, "SDK process")
    require(manifest["expected_log_found"] and not manifest["internal_error_found"], "SDK log")
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
        require(manifest[field], "SDK manifest: " + field)


def compare_reports(prior, current, counts):
    require(prior["passed"] and current["passed"], "SDK report status")
    require(not prior["errors"] and not current["errors"], "SDK report errors")
    for report in (prior, current):
        rules = report["rule_catalog"]
        require(rules["registered"] == 108 and rules["rejected"] == 0, "catalog population")
        require(
            rules["verified"] == (0 if report["transformations_disabled"] else 108),
            "catalog certification",
        )
    normalized = without_duration(current)
    model, _ = catalog(
        current["matcher_catalog"],
        current["rule_catalog"]["names"],
        current["transformations_disabled"],
    )
    address_tag = model["mops"]["a"]
    first_address = None
    for entry in normalized["entries"]:
        for row in (entry, entry.get("body")):
            if row is None:
                continue
            for stage in row["stages"]:
                inputs = stage["statistics"]["matching_inputs"]
                require(inputs["schema"] == 2 and inputs["sample_limit"] == 1024, "input profile")
                counts["events"] += inputs["events"]
                counts["unrecorded"] += inputs["unrecorded"]
                for sample in inputs["samples"]:
                    require(
                        sample["capture_status"] == "complete" and sample["input"] is not None,
                        "input completeness",
                    )
                    require(sample["input"].get("schema") == 2, "new input schema")
                    capture(sample["input"], model)
                    converted, addresses = legacy_operand(sample["input"], address_tag)
                    if addresses and first_address is None:
                        first_address = copy.deepcopy(sample["input"])
                    converted.pop("schema")
                    sample["input"] = converted
                    counts["retained_samples"] += 1
                    counts["address_occurrences"] += addresses
                    counts["address_occurrences_weighted"] += addresses * sample["count"]
                    if addresses:
                        counts["address_samples"] += 1
                        counts["address_events_weighted"] += sample["count"]
    require(without_duration(prior) == normalized, "historical/new SDK reports differ")
    return canonical(normalized), first_address, address_tag


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prior_path, current_path = args.prior.resolve(), args.current.resolve()
    prior_bytes, current_bytes = prior_path.read_bytes(), current_path.read_bytes()
    prior, current = json.loads(prior_bytes), json.loads(current_bytes)
    for aggregate in (prior, current):
        require(aggregate["schema"] == 1 and aggregate["passed"], "matrix status")
        require(len(aggregate["runs"]) == 40, "matrix population")
        require(
            aggregate["native_analysis_disabled"] is False
            and aggregate["matcher_inputs"] is True
            and aggregate["input_limit"] == 1024
            and aggregate["matching_diagnostics"] is True,
            "matrix profile",
        )
    require(prior["plugin_sha256"] != current["plugin_sha256"], "plugin transition")
    require(prior["ida_sha256"] == current["ida_sha256"], "IDA transition")
    require(prior["ida_components_sha256"] == current["ida_components_sha256"], "IDA components")
    require(prior["paired"] == current["paired"], "paired SDK results")
    old_runs = {(r["architecture"], r["label"], r["disabled"]): r for r in prior["runs"]}
    new_runs = {(r["architecture"], r["label"], r["disabled"]): r for r in current["runs"]}
    require(set(old_runs) == set(new_runs) == EXPECTED, "matrix profile identities")
    counts = Counter()
    normalized_hash = hashlib.sha256()
    first_address = None
    for key in sorted(EXPECTED):
        before, after = old_runs[key], new_runs[key]
        require(before["binary_sha256"] == after["binary_sha256"], "binary transition")
        require(before["counts"] == after["counts"], "SDK count transition")
        old_run, old_probe = checked_artifacts(before, prior_path.parent)
        new_run, new_probe = checked_artifacts(after, current_path.parent)
        check_manifest(before, prior, old_run)
        check_manifest(after, current, new_run)
        for field in (
            "input_sha256",
            "source_input_sha256",
            "script_sha256",
            "source_script_sha256",
            "ida_sha256",
            "chernobog_environment_sha256",
        ):
            require(old_run[field] == new_run[field], "SDK run transition: " + field)
        normalized, address_input, address_tag = compare_reports(old_probe, new_probe, counts)
        normalized_hash.update(canonical(key) + b"\0")
        normalized_hash.update(normalized + b"\0")
        if first_address is None and address_input is not None:
            first_address = address_input, address_tag
    require(
        counts
        == {
            "events": 14047,
            "unrecorded": 0,
            "retained_samples": 9729,
            "address_occurrences": 235,
            "address_occurrences_weighted": 361,
            "address_samples": 98,
            "address_events_weighted": 149,
        },
        "matrix capture counts",
    )
    # The same live input must fail conversion when one SDK extent changes.
    require(first_address is not None, "live address operand")
    altered = copy.deepcopy(first_address[0])

    def change_extent(value, address_tag):
        if isinstance(value, list):
            if (
                len(value) == 5
                and value[0] == address_tag
                and isinstance(value[4], list)
                and len(value[4]) == 3
            ):
                value[4][1] = 0
                return True
            return any(change_extent(item, address_tag) for item in value)
        if isinstance(value, dict):
            return any(change_extent(item, address_tag) for item in value.values())
        return False

    require(change_extent(altered, first_address[1]), "live address mutation")
    try:
        legacy_operand(altered, first_address[1])
    except ValueError:
        corruption_rejected = True
    else:
        corruption_rejected = False
    require(corruption_rejected, "address mutation accepted")
    result = {
        "schema": 1,
        "passed": True,
        "scope": "40 matched x86-64/i386 SDK profiles; new inputs projected to historical schema only after checking all live address extents",
        "prior_matrix_sha256": digest(prior_bytes),
        "current_matrix_sha256": digest(current_bytes),
        "prior_plugin_sha256": prior["plugin_sha256"],
        "current_plugin_sha256": current["plugin_sha256"],
        "ida_sha256": current["ida_sha256"],
        "normalized_reports_sha256": normalized_hash.hexdigest(),
        "counts": dict(counts),
        "live_extent_mutation_rejected": corruption_rejected,
    }
    if args.evidence is not None:
        evidence = json.loads(args.evidence.read_text())
        require(evidence["verifier_sha256"] == digest(Path(__file__).read_bytes()), "verifier pin")
        require(evidence["result"] == result, "recorded result")
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print("MBA address matrix delta: pass")


if __name__ == "__main__":
    main()
