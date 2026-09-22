"""Isolate two IDA processes to test native-string identity after database reopen."""

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from run_vmp_corpus import digest, execute


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--gui", type=Path)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expect-restart-collision", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    files = (
        "tests/run_native_string_lifecycle.py",
        "tests/ida_native_string_lifecycle.py",
        "tests/run_ida_smoke.py",
        "tests/run_vmp_corpus.py",
        "src/vm/ida_native_trace.cpp",
        "src/vm/ida_native_trace.hpp",
        "src/plugin/idc_api.cpp",
        "python/chernobog_temporal_strings.py",
    )
    sources = {name: digest(root / name) for name in files}
    report = {
        "schema": 1,
        "passed": False,
        "mode": "counterexample" if args.expect_restart_collision else "regression",
        "source_sha256": sources,
        "input_sha256": digest(args.input),
        "plugin_sha256": digest(args.plugin),
        "ida_sha256": digest(args.ida),
        "gui_sha256": digest(args.gui) if args.gui else None,
        "runs": [],
    }
    try:
        for label, ida in [("capture", args.ida), ("reopen", args.ida)] + (
            [("gui", args.gui)] if args.gui else []
        ):
            binary = args.input.resolve() if label == "capture" else output / "capture/capture.i64"
            command = [
                sys.executable,
                "-B",
                root / "tests/run_ida_smoke.py",
                binary,
                root / "tests/ida_native_string_lifecycle.py",
                "--ida",
                ida.resolve(),
                "--plugin",
                args.plugin.resolve(),
                "--output-dir",
                output / label,
                "--enable-rax",
                "--set",
                "CHERNOBOG_VIEW_MODULE=" + str(root / "python/chernobog_temporal_strings.py"),
            ]
            if label != "capture":
                command += [
                    "--allow-database",
                    "--set",
                    "CHERNOBOG_PRIOR_CAPTURE=" + str(output / "capture/string_lifecycle.json"),
                ]
            if args.expect_restart_collision:
                command += ["--set", "CHERNOBOG_COLLISION_EXPECTED=1"]
            measurement, _, _ = execute(command, timeout=120)
            assert (
                measurement["exit_code"] == 0
                and not measurement["timed_out"]
                and not measurement["output_exceeded"]
            )
            probe = json.loads((output / label / "string_lifecycle.json").read_text())
            run = json.loads((output / label / "run.json").read_text())
            assert not probe["errors"] and all(row["passed"] for row in probe["records"])
            assert run["runner_return_code"] == 0 and run["artifacts_unchanged"]
            assert run["plugin_sha256"] == report["plugin_sha256"] and run["ida_sha256"] == digest(
                ida
            )
            assert run["script_sha256"] == sources["tests/ida_native_string_lifecycle.py"]
            assert run["input_sha256"] == digest(binary)
            artifacts = ["run.json", "string_lifecycle.json"] + (
                ["historical_capture.png"] if label == "gui" else []
            )
            report["runs"].append(
                {
                    "label": label,
                    "checks": len(probe["records"]),
                    "measurement": measurement,
                    "artifact_sha256": {name: digest(output / label / name) for name in artifacts},
                }
            )
        assert all(digest(root / name) == value for name, value in sources.items())
        assert (
            digest(args.plugin) == report["plugin_sha256"]
            and digest(args.input) == report["input_sha256"]
        )
        assert digest(args.ida) == report["ida_sha256"] and (
            not args.gui or digest(args.gui) == report["gui_sha256"]
        )
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__
    (output / "lifecycle_analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "mode": report["mode"],
                "runs": len(report["runs"]),
                "failure": report.get("failure"),
            }
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
