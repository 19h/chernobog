"""Compare rejected-case CFG metadata against IDA with native analysis disabled."""
import json
import sys
from pathlib import Path


def read(directory, name):
    return json.loads((Path(directory) / name).read_text())


def main():
    enabled, disabled = sys.argv[1:]
    reports = [read(directory, "run.json") for directory in (enabled, disabled)]
    for report in reports:
        assert report["runner_return_code"] == 0 and report["artifacts_unchanged"]
        assert report["expected_log_found"] and not report["internal_error_found"]
    for key in ("input_sha256", "plugin_sha256", "script_sha256", "ida_sha256"):
        assert reports[0][key] == reports[1][key], "artifact mismatch: " + key
    actual, baseline = read(enabled, "get_pc32.json"), read(disabled, "get_pc32.json")
    assert not actual["baseline"] and baseline["baseline"]
    assert not actual["errors"] and not baseline["errors"]
    left = {row["case"]: row for row in actual["records"] if row["case"].endswith(" rejected")}
    right = {row["case"]: row for row in baseline["records"] if row["case"].endswith(" rejected")}
    assert left.keys() == right.keys() and len(left) == 4
    for name, row in left.items():
        assert row["passed"] and right[name]["passed"], name
        assert row["targets"] == right[name]["targets"], name + " changed baseline edges"
        assert row["comment"] == right[name]["comment"], name + " changed baseline comments"
    print("[chernobog][get-pc32-baseline] PASS rejected_controls=4")


if __name__ == "__main__":
    main()
