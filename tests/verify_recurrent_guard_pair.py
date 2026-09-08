#!/usr/bin/env python3
"""Assert matched artifact attribution, guarded rewrites, and negative retention.

Usage: python3 tests/verify_recurrent_guard_pair.py BEFORE_RUN AFTER_RUN
Both directories must contain run.json and recurrent_guard.json from the same
frozen IDA probe. This comparison supplies the explicit new-capability check;
the in-IDA probe supplies the independent native-reference semantic checks.
"""
import argparse
import json
from pathlib import Path


POSITIVE = {
    "rg_positive", "rg_global_effect", "rg_register_effect", "rg_restored_selector",
}
NEGATIVE = {
    "rg_late_guard", "rg_unknown_guard", "rg_escaped_state",
    "rg_recurrence_register", "rg_middle_entry", "rg_entry_cycle",
    "rg_corrupted_restore",
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def load(directory):
    report = json.loads((directory / "run.json").read_text())
    records = json.loads((directory / "recurrent_guard.json").read_text())
    require(report["runner_return_code"] == 0 and report["expected_log_found"],
            "%s: in-IDA semantic probe failed" % directory)
    require(report["artifacts_unchanged"], "%s: artifact integrity failed" % directory)
    by_name = {record["name"]: record for record in records}
    require(len(records) == 11 and set(by_name) == POSITIVE | NEGATIVE,
            "%s: missing or duplicate fixture function" % directory)
    require(sum(len(record["native_reference_checks"]) for record in records) == 16,
            "%s: scenario count differs" % directory)
    return report, by_name


def final_microcode(record):
    stages = {stage["maturity"]: stage for stage in record["microcode"]}
    require(set(stages) == {"LOCOPT", "GLBOPT3"}, "missing microcode stage")
    return stages["GLBOPT3"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    arguments = parser.parse_args()
    before_report, before = load(arguments.before)
    after_report, after = load(arguments.after)
    identity_keys = (
        "input_sha256", "script_sha256", "ida_sha256",
        "chernobog_environment_sha256", "expected_log_pattern",
    )
    for key in identity_keys:
        require(before_report[key] == after_report[key], "comparison identity differs: " + key)
    rows = []
    native_byte_count = 0
    after_mapped_count = 0
    for name in sorted(before):
        old, new = before[name], after[name]
        require(old["native_byte_integrity"]["unchanged"]
                and new["native_byte_integrity"]["unchanged"]
                and old["native_byte_integrity"] == new["native_byte_integrity"],
                name + ": native IDB bytes changed or differ across the pair")
        native_byte_count += sum(part["end"] - part["start"]
                                 for part in new["native_byte_integrity"]["before"])
        for record in (old, new):
            require(all(mapping["present_at_LOCOPT"]
                        for stage in record["microcode"]
                        for mapping in stage["fictional_address_mappings"]),
                    name + ": fictional instruction EA lacks its LOCOPT source")
        old_final, new_final = final_microcode(old), final_microcode(new)
        mapped_count = len(new_final["fictional_address_mappings"])
        after_mapped_count += mapped_count
        require(old_final["switch_count"] == 1, name + ": baseline dispatcher absent")
        old_semantics = [{key: scenario[key] for key in
                          ("argument", "result", "expected", "global_counter")}
                         for scenario in old["native_reference_checks"]]
        new_semantics = [{key: scenario[key] for key in
                          ("argument", "result", "expected", "global_counter")}
                         for scenario in new["native_reference_checks"]]
        require(old_semantics == new_semantics, name + ": concrete semantics changed")
        if name in POSITIVE:
            require(new_final["switch_count"] == 0, name + ": dispatcher was not removed")
            require(new_final["qty"] < old_final["qty"], name + ": CFG was not reduced")
        else:
            require(old["microcode"] == new["microcode"],
                    name + ": rejected fixture microcode changed")
            require(old["native_reference_checks"] == new["native_reference_checks"],
                    name + ": rejected fixture execution trace changed")
        rows.append({"name": name, "before_blocks": old_final["qty"],
                     "after_blocks": new_final["qty"],
                     "before_switches": old_final["switch_count"],
                     "after_switches": new_final["switch_count"],
                     "after_fictional_address_mappings": mapped_count,
                     "semantics": new_semantics})
    require(after_mapped_count > 0, "fixture did not exercise fictional instruction EAs")
    output = {
        "matched_identities": {key: before_report[key] for key in identity_keys},
        "before_plugin_sha256": before_report["plugin_sha256"],
        "after_plugin_sha256": after_report["plugin_sha256"],
        "scenario_count": 16, "rewritten_functions": 4,
        "unchanged_native_byte_count": native_byte_count,
        "after_fictional_address_mappings": after_mapped_count,
        "unchanged_negative_functions": 7, "functions": rows,
    }
    print(json.dumps(output, indent=2))
    print("PASS recurrent guard matched capability and semantics")


if __name__ == "__main__":
    main()
