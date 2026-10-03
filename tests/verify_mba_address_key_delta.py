"""Verify a same-input IDA control after address extents enter the AST key.

Only per-stage elapsed time is excluded from exact report comparison. The
reports are local IDA artifacts; this check does not infer unequal live extents
or a protected recovery gain from a corpus whose observed extents are -1/-1.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path

from mba_match_replay import capture, catalog


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


def addresses(value):
    if isinstance(value, list):
        if len(value) == 5 and value[0] == 10:
            yield value
        for item in value:
            yield from addresses(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from addresses(item)


def check_run(run):
    assert run["schema_version"] == 2
    assert run["runner_return_code"] == run["process_return_code"] == 0
    assert run["expected_log_found"] and not run["internal_error_found"]
    for key in (
        "plugin_unchanged",
        "script_unchanged",
        "source_script_unchanged",
        "source_input_unchanged",
        "input_copy_matches_source",
        "ida_unchanged",
        "artifacts_unchanged",
        "local_paths_redacted",
    ):
        assert run[key], key


def scan(report):
    assert report["schema"] == 1 and report["passed"] and not report["errors"]
    rules = report["rule_catalog"]
    assert (rules["registered"], rules["verified"], rules["rejected"]) == (108, 108, 0)
    model, patterns = catalog(report["matcher_catalog"], rules["names"])
    assert len(patterns) == 108 and model["mops"]["a"] == 10
    assert [entry["name"] for entry in report["entries"]] == [
        "corpus_transform",
        "corpus_branch",
    ]
    events = retained = unrecorded = address_events = address_occurrences = 0
    address_samples = 0
    first_address = None
    for entry in report["entries"]:
        assert entry["status"] == "owned" and entry["native_bytes_unchanged"]
        for stage in entry["body"]["stages"]:
            inputs = stage["statistics"]["matching_inputs"]
            assert inputs["schema"] == 2 and inputs["sample_limit"] == 1024
            events += inputs["events"]
            unrecorded += inputs["unrecorded"]
            retained += len(inputs["samples"])
            for sample in inputs["samples"]:
                assert sample["capture_status"] == "complete" and sample["input"] is not None
                value = capture(sample["input"], model)
                found = list(addresses(value["root"]))
                if found:
                    assert entry["name"] == "corpus_transform" and stage["maturity"] == 5
                    assert all(address[4][1:] == [-1, -1] for address in found)
                    address_samples += 1
                    address_events += sample["count"]
                    address_occurrences += sample["count"] * len(found)
                    if first_address is None:
                        first_address = value
    assert (events, retained, unrecorded) == (1693, 1138, 0)
    assert (address_samples, address_events, address_occurrences) == (12, 24, 28)
    assert first_address is not None
    changed = copy.deepcopy(first_address)
    next(addresses(changed["root"]))[4][1] = 2**31
    try:
        capture(changed, model)
    except ValueError:
        corruption_rejected = True
    else:
        corruption_rejected = False
    assert corruption_rejected
    return {
        "events": events,
        "retained_samples": retained,
        "unrecorded": unrecorded,
        "address_samples": address_samples,
        "address_events_weighted": address_events,
        "address_occurrences_weighted": address_occurrences,
        "address_extents": [-1, -1],
        "live_extent_corruption_rejected": corruption_rejected,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--prior-run", type=Path, required=True)
    parser.add_argument("--current-run", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prior_bytes, current_bytes = args.prior.read_bytes(), args.current.read_bytes()
    prior, current = json.loads(prior_bytes), json.loads(current_bytes)
    prior_run, current_run = json.loads(args.prior_run.read_bytes()), json.loads(
        args.current_run.read_bytes()
    )
    check_run(prior_run)
    check_run(current_run)
    for field in (
        "input_sha256",
        "source_input_sha256",
        "script_sha256",
        "source_script_sha256",
        "ida_sha256",
        "chernobog_environment_sha256",
    ):
        assert prior_run[field] == current_run[field], field
    assert prior_run["plugin_sha256"] != current_run["plugin_sha256"]
    before, after = without_duration(prior), without_duration(current)
    assert before == after
    counts = scan(current)
    assert scan(prior) == counts
    altered = copy.deepcopy(after)
    altered["entries"][0]["body"]["stages"][-1]["statistics"]["matching_inputs"]["events"] += 1
    assert before != altered
    result = {
        "schema": 1,
        "passed": True,
        "scope": "two selected i386 protected entries; exact report equality excluding elapsed time",
        "input_sha256": current_run["input_sha256"],
        "probe_sha256": current_run["script_sha256"],
        "ida_sha256": current_run["ida_sha256"],
        "environment_sha256": current_run["chernobog_environment_sha256"],
        "prior_plugin_sha256": prior_run["plugin_sha256"],
        "current_plugin_sha256": current_run["plugin_sha256"],
        "prior_report_sha256": digest(prior_bytes),
        "current_report_sha256": digest(current_bytes),
        "normalized_report_sha256": digest(canonical(before)),
        "counts": counts,
        "report_count_mutation_rejected": before != altered,
    }
    if args.evidence is not None:
        evidence = json.loads(args.evidence.read_text())
        assert evidence["schema"] == 1 and evidence["passed"]
        assert evidence["verifier_sha256"] == digest(Path(__file__).read_bytes())
        assert result == evidence["result"]
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print("MBA address-key protected control: pass")


if __name__ == "__main__":
    main()
