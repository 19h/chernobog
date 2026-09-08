#!/usr/bin/env python3
"""Compare matched native-prefix probes without inferring elapsed speedups."""
import argparse
import json
from pathlib import Path


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def load(directory):
    report = json.loads((directory / "run.json").read_text())
    records = json.loads((directory / "native_prefix_gate.json").read_text())
    require(report["runner_return_code"] == 0 and report["artifacts_unchanged"],
            "%s: probe or integrity failed" % directory)
    by_name = {record["name"]: record for record in records}
    require(len(records) == len(by_name) == 11, "missing or duplicate prefix control")
    return report, by_name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    arguments = parser.parse_args()
    before_report, before = load(arguments.before)
    after_report, after = load(arguments.after)
    for key in ("input_sha256", "script_sha256", "ida_sha256",
                "chernobog_environment_sha256", "expected_log_pattern"):
        require(before_report[key] == after_report[key], "identity differs: " + key)
    require(set(before) == set(after), "control names differ")
    for name in sorted(before):
        old, new = before[name], after[name]
        for key in ("name", "start", "repeats", "raw_hex", "instruction"):
            require(old[key] == new[key], name + ": " + key + " changed")
        calls = old["repeats"]
        if name in ("np_plain_add", "np_plain_nop"):
            require(old["analysis_events"] == 2 * calls,
                    name + ": baseline recursive event not observed")
            require(new["analysis_events"] == calls,
                    name + ": ordinary opcode still recursively decoded")
        else:
            require(old["events_by_address"] == new["events_by_address"],
                    name + ": prefix-control analysis events changed")
        print("%s: %d -> %d analysis events / %d decode calls; semantics unchanged"
              % (name, old["analysis_events"], new["analysis_events"], calls))
    print("PASS matched native prefix gate operation counts and semantics")


if __name__ == "__main__":
    main()
