#!/usr/bin/env python3
"""Build, execute and independently audit the condition-code microcode consumer.

All output paths in the evidence manifest are relative to the output directory.
The optional i386 run uses the pinned-image adapter from the paired VMP corpus.
"""

import argparse
import json
import platform
from pathlib import Path
import sys

from run_vmp_corpus import base_environment, digest, execute
from verify_conditions_microcode import verify, verify_faults, verify_optimized

SOURCES = (
    "src/ida_analysis/early_hexrays.cpp",
    "src/ida_analysis/early_hexrays.hpp",
    "src/ida_analysis/analysis_config.cpp",
    "src/ida_analysis/analysis_config.hpp",
    "src/ida_analysis/x86_analysis.cpp",
    "src/ida_analysis/x86_analysis.hpp",
    "src/common/x86_abstract.h",
    "src/plugin/idc_api.cpp",
    "tests/ida_conditions_microcode_probe.py",
    "tests/verify_conditions_microcode.py",
    "tests/run_conditions_microcode.py",
    "tests/vmp_native/conditions.S",
    "tests/vmp_native/conditions32.S",
    "tests/vmp_native/conditions_main.c",
    "tests/run_ida_smoke.py",
    "tests/vmp_native/conditions_faults.c",
    "tests/run_vmp_corpus.py",
    "tests/vmp_corpus/linux32.py",
    "tests/vmp_corpus/linux32_exec.py",
    "tests/vmp_corpus/linux32.Dockerfile",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida", required=True, type=Path)
    parser.add_argument("--plugin", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--linux32-image")
    parser.add_argument("--docker-context", default="orbstack")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    environment = base_environment()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    report = {
        "schema": 1,
        "source_sha256": {p: digest(root / p) for p in SOURCES},
        "plugin_sha256": digest(args.plugin),
        "host_architecture": platform.machine(),
        "sdk_sha256": {
            name: digest(root.parent / "ida-sdk/src/include" / name)
            for name in ("hexrays.hpp", "intel.hpp", "ua.hpp", "typeinf.hpp")
        },
        "architectures": {},
        "artifacts": {},
    }

    def checked(command, stage, timeout=120):
        measurement, stdout, stderr = execute(command, cwd=root, env=environment, timeout=timeout)
        if measurement["exit_code"] or measurement["timed_out"] or measurement["output_exceeded"]:
            raise RuntimeError(stage + " failed; exit=" + str(measurement["exit_code"]))
        return measurement, stdout

    for architecture in (["x86_64", "i386"] if args.linux32_image else ["x86_64"]):
        directory = output / architecture
        directory.mkdir()
        binary = directory / "conditions"
        fault_binary = directory / "conditions-faults"
        result = {}
        if architecture == "x86_64":
            result["compile"], _ = checked(
                [
                    "xcrun",
                    "clang",
                    "-arch",
                    "x86_64",
                    "-O2",
                    "-g0",
                    root / "tests/vmp_native/conditions.S",
                    root / "tests/vmp_native/conditions_main.c",
                    "-o",
                    binary,
                ],
                "x86-64 compile",
            )
            result["execute"], native = checked([binary], "x86-64 execution")
            result["fault_compile"], _ = checked(
                [
                    "xcrun",
                    "clang",
                    "-arch",
                    "x86_64",
                    "-O2",
                    "-g0",
                    root / "tests/vmp_native/conditions.S",
                    root / "tests/vmp_native/conditions_faults.c",
                    "-o",
                    fault_binary,
                ],
                "x86-64 fault-oracle compile",
            )
            result["fault_execute"], fault_native = checked(
                [fault_binary], "x86-64 fault-oracle execution"
            )
            result["runtime"] = "macOS x86-64 execution; translated on arm64 hosts"
        else:
            from vmp_corpus.linux32 import Linux32

            backend = Linux32(root, directory, args.linux32_image, args.docker_context)
            result["runtime"] = backend.metadata
            measurement, _, _ = backend.execute(
                [
                    "i686-linux-gnu-gcc",
                    "-O2",
                    "-g0",
                    "-fno-pie",
                    "-no-pie",
                    "/source/vmp_native/conditions32.S",
                    "/source/vmp_native/conditions_main.c",
                    "-o",
                    "/output/conditions",
                ]
            )
            if (
                measurement["exit_code"]
                or measurement["timed_out"]
                or measurement["output_exceeded"]
            ):
                raise RuntimeError("i386 compile failed")
            result["compile"] = measurement
            result["execute"], native, _ = backend.run(binary, 0)
            if result["execute"]["exit_code"]:
                raise RuntimeError("i386 execution failed")
            measurement, _, _ = backend.execute(
                [
                    "i686-linux-gnu-gcc",
                    "-O2",
                    "-g0",
                    "-fno-pie",
                    "-no-pie",
                    "/source/vmp_native/conditions32.S",
                    "/source/vmp_native/conditions_faults.c",
                    "-o",
                    "/output/conditions-faults",
                ]
            )
            if (
                measurement["exit_code"]
                or measurement["timed_out"]
                or measurement["output_exceeded"]
            ):
                raise RuntimeError("i386 fault-oracle compile failed")
            result["fault_compile"] = measurement
            result["fault_execute"], fault_native, _ = backend.run(fault_binary, 0)
            if result["fault_execute"]["exit_code"]:
                raise RuntimeError("i386 fault-oracle execution failed")
        (directory / "native.jsonl").write_bytes(native)
        (directory / "faults.jsonl").write_bytes(fault_native)
        result["input_sha256"] = digest(binary)
        captures = {}
        for mode in ("off", "on"):
            run = directory / mode
            result[mode], _ = checked(
                [
                    sys.executable,
                    "-B",
                    root / "tests/run_ida_smoke.py",
                    binary,
                    root / "tests/ida_conditions_microcode_probe.py",
                    "--ida",
                    args.ida.resolve(),
                    "--plugin",
                    args.plugin.resolve(),
                    "--output-dir",
                    run,
                    "--set",
                    "CHERNOBOG_IDA_CONDITION_CODEGEN=" + ("1" if mode == "on" else "0"),
                    "--set",
                    "CHERNOBOG_IDA_CALL_POP_CODEGEN=0",
                    "--set",
                    "CHERNOBOG_CONDITION_DECOMPILE=1",
                ],
                architecture + " " + mode + " capture",
                180,
            )
            captures[mode] = json.loads((run / "conditions_microcode.json").read_text())
            assert all(r["ctree"] for r in captures[mode]["records"] if r["phase"] == "initial")
        assert digest(binary) == result["input_sha256"], "fixture changed during capture"
        result["verification"] = verify(
            captures["on"], captures["off"], [json.loads(line) for line in native.splitlines()]
        )
        result["fault_verification"] = verify_faults(
            captures["on"], [json.loads(line) for line in fault_native.splitlines()]
        )
        result["optimized"] = []
        for stage in ("MMAT_PREOPTIMIZED", "MMAT_GLBOPT3"):
            run = directory / stage
            measurement, _ = checked(
                [
                    sys.executable,
                    "-B",
                    root / "tests/run_ida_smoke.py",
                    binary,
                    root / "tests/ida_conditions_microcode_probe.py",
                    "--ida",
                    args.ida.resolve(),
                    "--plugin",
                    args.plugin.resolve(),
                    "--output-dir",
                    run,
                    "--set",
                    "CHERNOBOG_IDA_CONDITION_CODEGEN=1",
                    "--set",
                    "CHERNOBOG_IDA_CALL_POP_CODEGEN=0",
                    "--set",
                    "CHERNOBOG_CONDITION_DECOMPILE=1",
                    "--set",
                    "CHERNOBOG_CONDITION_MATURITY=" + stage,
                ],
                architecture + " " + stage,
                180,
            )
            optimized = json.loads((run / "conditions_microcode.json").read_text())
            result["optimized"].append(
                {"run": measurement, "verification": verify_optimized(optimized)}
            )
        report["architectures"][architecture] = result
    assert digest(args.plugin) == report["plugin_sha256"], "plugin changed during execution"
    assert all(
        digest(root / p) == sha for p, sha in report["source_sha256"].items()
    ), "sources changed during audit"
    for path in sorted(output.rglob("*")):
        if path.is_file() and (
            path.name
            in (
                "conditions",
                "conditions-faults",
                "native.jsonl",
                "faults.jsonl",
                "conditions_microcode.json",
                "run.json",
            )
            or path.parent.name == "guest-runs"
        ):
            report["artifacts"][str(path.relative_to(output))] = digest(path)
    (output / "evidence.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "status": "pass",
                "architectures": {
                    key: {
                        "effects": value["verification"],
                        "faults": value["fault_verification"],
                        "optimized": [stage["verification"] for stage in value["optimized"]],
                    }
                    for key, value in report["architectures"].items()
                },
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
