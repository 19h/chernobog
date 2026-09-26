"""Execute rotate oracles and inspect the same binaries in fresh IDA databases."""

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
        "src/common/x86_abstract.h",
        "src/ida_analysis/x86_analysis.cpp",
        "tests/x86_abstract_tests.cpp",
        "tests/vmp_native/rotate_asm.c",
        "tests/vmp_native/rotate.cpp",
        "tests/ida_rotate_probe.py",
        "tests/run_rotate.py",
        "tests/run_ida_smoke.py",
        "tests/run_vmp_corpus.py",
        "tests/vmp_corpus/rotate.Dockerfile",
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
            binary = directory / "rotate"
            row = {"architecture": architecture}
            report["runs"].append(row)
            if architecture == "x86_64":
                build, _, _ = execute(
                    [
                        "xcrun",
                        "clang++",
                        "-std=c++17",
                        "-x",
                        "c++",
                        "-I",
                        root / "src/common",
                        "-arch",
                        "x86_64",
                        "-O2",
                        "-g0",
                        root / "tests/vmp_native/rotate_asm.c",
                        root / "tests/vmp_native/rotate.cpp",
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
                backend.mounts += [
                    "--mount",
                    "type=bind,src=" + str(root / "src/common") + ",dst=/common,readonly",
                ]
                tools_status, tools_output, _ = backend.execute(
                    [
                        "sh",
                        "-c",
                        "sha256sum /usr/bin/i686-linux-gnu-g++ /usr/lib/gcc-cross/i686-linux-gnu/*/libstdc++.a",
                    ]
                )
                assert tools_status["exit_code"] == 0
                backend.metadata["cpp_tool_sha256"] = [
                    {"file": Path(line.split()[1]).name, "sha256": line.split()[0]}
                    for line in tools_output.decode().splitlines()
                ]
                build, _, _ = backend.execute(
                    [
                        "i686-linux-gnu-g++",
                        "-std=c++17",
                        "-I/common",
                        "-static-libstdc++",
                        "-static-libgcc",
                        "-O2",
                        "-g0",
                        "-fno-pie",
                        "-no-pie",
                        "/source/vmp_native/rotate_asm.c",
                        "/source/vmp_native/rotate.cpp",
                        "-o",
                        "/output/rotate",
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
            assert row["native_result"] == {
                "passed": True,
                "byte_cases": 1048576,
                "corner_cases": 245760 if architecture == "x86_64" else 184320,
                "static_inputs": 512,
            }
            row["binary_sha256"] = digest(binary)
            measurement, _, _ = execute(
                [
                    sys.executable,
                    "-B",
                    root / "tests/run_ida_smoke.py",
                    binary,
                    root / "tests/ida_rotate_probe.py",
                    "--ida",
                    args.ida.resolve(),
                    "--plugin",
                    args.plugin.resolve(),
                    "--output-dir",
                    directory / "inspection",
                    "--set",
                    "CHERNOBOG_IDA_FLAG_SCAN_DEPTH=64",
                    "--set",
                    "CHERNOBOG_IDA_REGISTER_SCAN_DEPTH=64",
                    *(["--set", "CHERNOBOG_ROTATE_BASELINE=1"] if args.baseline else []),
                ],
                timeout=120,
            )
            row["inspection"] = measurement
            assert measurement["exit_code"] == 0 and not measurement["timed_out"]
            capture = json.loads((directory / "inspection/rotate.json").read_text())
            run = json.loads((directory / "inspection/run.json").read_text())
            assert not capture["errors"] and all(check["passed"] for check in capture["checks"])
            assert run["artifacts_unchanged"] and run["source_script_unchanged"]
            assert run["input_sha256"] == row["binary_sha256"]
            assert (
                run["plugin_sha256"] == report["plugin_sha256"]
                and run["ida_sha256"] == report["ida_sha256"]
            )
            row["checks"] = len(capture["checks"])
            row["artifact_sha256"] = {
                path: digest(directory / path)
                for path in ("inspection/run.json", "inspection/rotate.json")
            }
            print(
                json.dumps(
                    {
                        "architecture": architecture,
                        "native_checks": row["native_result"]["byte_cases"]
                        + row["native_result"]["corner_cases"],
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
    (output / "rotate_analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "failure": report.get("failure")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
