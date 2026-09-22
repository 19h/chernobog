"""Verify scalar/model snapshots or interleaved native read streams."""

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from run_vmp_corpus import digest, execute


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--gui", type=Path)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--interleaved", choices=("separate", "shared"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sources = (
        "tests/run_native_use_snapshots.py",
        "tests/ida_region_strings_probe.py",
        "tests/vmp_native/native_snapshot_strings.c",
        "tests/vmp_native/native_interleaved_strings.c",
        "tests/run_ida_smoke.py",
        "tests/run_vmp_corpus.py",
        "tests/evidence_tests.cpp",
        "src/hybrid/native_read_strings.cpp",
        "src/vm/ida_native_trace.cpp",
        "python/chernobog_temporal_strings.py",
    )
    source_hashes = {name: digest(root / name) for name in sources}
    flags = [
        "-arch",
        "x86_64",
        "-O1",
        "-g0",
        "-fno-builtin",
        "-fno-unroll-loops",
        "-D_FORTIFY_SOURCE=0",
        "-Wl,-no_fixup_chains",
        "-Wl,-no_data_const",
    ]
    report = {
        "schema": 1,
        "passed": False,
        "fixture": "interleaved-" + args.interleaved if args.interleaved else "scalar-modeled",
        "source_sha256": source_hashes,
        "plugin_sha256": digest(args.plugin),
        "ida_sha256": digest(args.ida),
        "gui_sha256": digest(args.gui) if args.gui else None,
        "build_arguments": flags,
        "native": [],
        "inspections": [],
    }
    source = (
        root
        / "tests/vmp_native"
        / ("native_interleaved_strings.c" if args.interleaved else "native_snapshot_strings.c")
    )
    try:
        for label, definitions, expected in (
            ("original", [], 0),
            ("first-negative", ["-DSNAPSHOT_ORACLE_FIRST=0x5a7b2e3f28393f28ULL"], 1),
            ("second-negative", ["-DSNAPSHOT_ORACLE_SECOND=0x5a7b3e3435393f28ULL"], 1),
        ):
            if args.interleaved == "shared":
                definitions = [*definitions, "-DSHARED_ALLOCATION=1"]
            binary = output / label
            build, _, _ = execute(
                [
                    "xcrun",
                    "clang",
                    *flags,
                    *definitions,
                    source,
                    "-o",
                    binary,
                ],
                timeout=60,
            )
            assert build["exit_code"] == 0 and not build["timed_out"]
            native, _, _ = execute([binary], timeout=30)
            assert native["exit_code"] == expected and not native["timed_out"]
            assert not native["output_exceeded"]
            assert all(value not in binary.read_bytes() for value in (b"secret!", b"second!"))
            report["native"].append(
                {
                    "label": label,
                    "sha256": digest(binary),
                    "definitions": definitions,
                    "expected_exit": expected,
                    "measurement": native,
                }
            )
        for label, ida in [("console", args.ida)] + ([("gui", args.gui)] if args.gui else []):
            destination = output / label
            measurement, _, _ = execute(
                [
                    sys.executable,
                    "-B",
                    root / "tests/run_ida_smoke.py",
                    output / "original",
                    root / "tests/ida_region_strings_probe.py",
                    "--ida",
                    ida.resolve(),
                    "--plugin",
                    args.plugin.resolve(),
                    "--output-dir",
                    destination,
                    "--enable-rax",
                    "--set",
                    (
                        "CHERNOBOG_INTERLEAVED_READS=" + args.interleaved
                        if args.interleaved
                        else "CHERNOBOG_SNAPSHOT_USES=1"
                    ),
                    "--set",
                    "CHERNOBOG_EXPECT_RETURN=1",
                    "--set",
                    "CHERNOBOG_VIEW_MODULE=" + str(root / "python/chernobog_temporal_strings.py"),
                ],
                timeout=120,
            )
            assert measurement["exit_code"] == 0 and not measurement["timed_out"]
            assert not measurement["output_exceeded"]
            probe = json.loads((destination / "region_strings.json").read_text())
            run = json.loads((destination / "run.json").read_text())
            assert not probe["errors"] and all(row["passed"] for row in probe["records"])
            assert run["runner_return_code"] == 0 and run["artifacts_unchanged"]
            assert run["plugin_sha256"] == report["plugin_sha256"]
            assert run["ida_sha256"] == digest(ida)
            assert run["script_sha256"] == source_hashes["tests/ida_region_strings_probe.py"]
            assert run["input_sha256"] == report["native"][0]["sha256"]
            artifacts = ["run.json", "region_strings.json"] + (
                ["region_strings.png"] if label == "gui" else []
            )
            report["inspections"].append(
                {
                    "label": label,
                    "measurement": measurement,
                    "checks": len(probe["records"]),
                    "artifact_sha256": {name: digest(destination / name) for name in artifacts},
                }
            )
        assert all(digest(root / name) == value for name, value in source_hashes.items())
        assert (
            digest(args.plugin) == report["plugin_sha256"]
            and digest(args.ida) == report["ida_sha256"]
        )
        assert not args.gui or digest(args.gui) == report["gui_sha256"]
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__
    (output / "snapshot_analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "native": len(report["native"]),
                "inspections": report["inspections"],
                "failure": report.get("failure"),
            }
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
