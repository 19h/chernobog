"""Run independent correlated-join fixtures and fresh owned/ownerless IDA probes."""

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from run_vmp_corpus import digest, execute


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--linux32-image")
    parser.add_argument("--docker-context", default="orbstack")
    parser.add_argument("--baseline", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sources = [
        "src/common/bounded_dataflow.h",
        "src/ida_analysis/x86_analysis.cpp",
        "src/ida_analysis/x86_analysis.hpp",
        "src/ida_analysis/native_classifier.cpp",
        "src/ida_analysis/native_engine.cpp",
        "tests/x86_abstract_tests.cpp",
        "tests/vmp_native/join_asm.c",
        "tests/vmp_native/join_main.c",
        "tests/ida_join_probe.py",
        "tests/run_join.py",
        "tests/run_ida_smoke.py",
        "tests/run_vmp_corpus.py",
        "tests/vmp_corpus/linux32.py",
        "tests/vmp_corpus/linux32_exec.py",
    ]
    report = {
        "passed": False,
        "baseline": args.baseline,
        "source_sha256": {path: digest(root / path) for path in sources},
        "plugin_sha256": digest(args.plugin),
        "ida_sha256": digest(args.ida),
        "runs": [],
    }
    try:
        for architecture in (["x86_64", "i386"] if args.linux32_image else ["x86_64"]):
            directory = output / architecture
            directory.mkdir()
            binary = directory / "join"
            row = {"architecture": architecture}
            report["runs"].append(row)
            if architecture == "x86_64":
                build, _, _ = execute(
                    [
                        "xcrun",
                        "clang",
                        "-arch",
                        "x86_64",
                        "-O2",
                        "-g0",
                        root / "tests/vmp_native/join_asm.c",
                        root / "tests/vmp_native/join_main.c",
                        "-o",
                        binary,
                    ]
                )
                assert build["exit_code"] == 0 and not build["timed_out"]
                native, stdout, _ = execute([binary])
                row["runtime"] = "macOS x86-64 process; translated on arm64 hosts"
            else:
                from vmp_corpus.linux32 import Linux32

                backend = Linux32(root, directory, args.linux32_image, args.docker_context)
                build, _, _ = backend.execute(
                    [
                        "i686-linux-gnu-gcc",
                        "-O2",
                        "-g0",
                        "-fno-pie",
                        "-no-pie",
                        "/source/vmp_native/join_asm.c",
                        "/source/vmp_native/join_main.c",
                        "-o",
                        "/output/join",
                    ]
                )
                assert build["exit_code"] == 0 and not build["timed_out"]
                native, stdout, _ = backend.run(binary, 0)
                row["runtime"] = backend.metadata
            row["build"], row["native"] = build, native
            assert (
                native["exit_code"] == 0
                and not native["timed_out"]
                and not native["output_exceeded"]
            )
            row["native_result"] = json.loads(stdout)
            assert row["native_result"] == {"passed": True, "checks": 2560}
            row["binary_sha256"] = digest(binary)
            measurement, _, _ = execute(
                [
                    sys.executable,
                    "-B",
                    root / "tests/run_ida_smoke.py",
                    binary,
                    root / "tests/ida_join_probe.py",
                    "--ida",
                    args.ida.resolve(),
                    "--plugin",
                    args.plugin.resolve(),
                    "--output-dir",
                    directory / "inspection",
                    "--set",
                    "CHERNOBOG_IDA_REGISTER_SCAN_DEPTH=64",
                    *(["--set", "CHERNOBOG_JOIN_BASELINE=1"] if args.baseline else []),
                ],
                timeout=120,
            )
            row["inspection"] = measurement
            capture = json.loads((directory / "inspection/join.json").read_text())
            run = json.loads((directory / "inspection/run.json").read_text())
            row["checks"] = len(capture["checks"])
            row["errors"] = capture["errors"]
            assert measurement["exit_code"] == 0 and not measurement["timed_out"]
            assert not capture["errors"] and all(check["passed"] for check in capture["checks"])
            assert (
                run["artifacts_unchanged"]
                and run["source_script_unchanged"]
                and run["input_sha256"] == row["binary_sha256"]
            )
            assert (
                run["plugin_sha256"] == report["plugin_sha256"]
                and run["ida_sha256"] == report["ida_sha256"]
            )
            row["artifact_sha256"] = {
                path: digest(directory / path)
                for path in ("inspection/run.json", "inspection/join.json")
            }
            print(
                json.dumps(
                    {
                        "architecture": architecture,
                        "native_checks": 2560,
                        "ida_checks": row["checks"],
                    }
                ),
                flush=True,
            )
        assert all(digest(root / path) == value for path, value in report["source_sha256"].items())
        assert (
            digest(args.plugin) == report["plugin_sha256"]
            and digest(args.ida) == report["ida_sha256"]
        )
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__
    (output / "join_analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "failure": report.get("failure")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
