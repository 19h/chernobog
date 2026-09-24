#!/usr/bin/env python3
"""Compare matched enabled/disabled IDA runs of the executed ELF32 fixture."""

import argparse
import json
from pathlib import Path


def load(directory):
    run = json.loads((directory / "run.json").read_text())
    probe = json.loads((directory / "get_pc32_rejections.json").read_text())
    assert run["runner_return_code"] == 0
    assert all(
        run[key]
        for key in (
            "plugin_unchanged",
            "ida_unchanged",
            "artifacts_unchanged",
            "source_script_unchanged",
            "source_input_unchanged",
            "input_copy_matches_source",
        )
    )
    assert not probe["errors"] and len(probe["records"]) == 11
    assert all(record["passed"] for record in probe["records"])
    return run, probe, {record["case"]: record for record in probe["records"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("enabled", type=Path)
    parser.add_argument("disabled", type=Path)
    args = parser.parse_args()
    enabled_run, enabled_probe, enabled = load(args.enabled)
    disabled_run, disabled_probe, disabled = load(args.disabled)
    assert not enabled_probe["baseline"] and disabled_probe["baseline"]
    for key in ("input_sha256", "script_sha256", "plugin_sha256", "ida_sha256"):
        assert enabled_run[key] == disabled_run[key], key
    assert enabled.keys() == disabled.keys()
    for label in enabled:
        for key in ("targets", "write_sources"):
            assert enabled[label].get(key) == disabled[label].get(key), (label, key)
    for name in ("gp32_unknown", "gp32_writable"):
        label = name + " ownership"
        assert "unresolved target" in enabled[label]["comment"]
        assert "[chernobog][ida-analysis]" not in disabled[label]["comment"]
    print("PASS matched ELF32 rejection runs: 11 assertions each, identical edge sets")


if __name__ == "__main__":
    main()
