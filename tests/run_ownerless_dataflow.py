"""Execute independent ownerless-CFG oracles and inspect the read-only IDA API."""

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
    parser.add_argument("--rep-count-baseline", action="store_true")
    parser.add_argument("--stack-store-baseline", action="store_true")
    parser.add_argument("--string-count-baseline", action="store_true")
    parser.add_argument("--scas-baseline", action="store_true")
    parser.add_argument("--cmps-baseline", action="store_true")
    parser.add_argument("--stos-local-baseline", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sources = [
        "src/common/bounded_dataflow.h",
        "src/common/x86_abstract.h",
        "src/ida_analysis/x86_analysis.cpp",
        "src/ida_analysis/x86_analysis.hpp",
        "src/ida_analysis/native_engine.cpp",
        "src/ida_analysis/native_engine.hpp",
        "src/plugin/idc_api.cpp",
        "python/chernobog_evidence.py",
        "tests/vmp_native/dataflow.S",
        "tests/vmp_native/ownerless_dataflow.S",
        "tests/vmp_native/ownerless_dataflow.c",
        "tests/ida_ownerless_dataflow_probe.py",
        "tests/run_ownerless_dataflow.py",
        "tests/run_ida_smoke.py",
        "tests/run_vmp_corpus.py",
        "tests/vmp_corpus/linux32.py",
        "tests/vmp_corpus/linux32_exec.py",
    ]
    report = {
        "passed": False,
        "source_sha256": {name: digest(root / name) for name in sources},
        "plugin_sha256": digest(args.plugin),
        "ida_sha256": digest(args.ida),
        "runs": [],
    }
    try:
        for architecture in (["x86_64", "i386"] if args.linux32_image else ["x86_64"]):
            directory = output / architecture
            directory.mkdir()
            row = {"architecture": architecture, "executions": []}
            report["runs"].append(row)
            backend = None
            if architecture == "i386":
                from vmp_corpus.linux32 import Linux32

                backend = Linux32(root, directory, args.linux32_image, args.docker_context)
                row["runtime"] = backend.metadata
            else:
                row["runtime"] = "macOS x86-64 process; translated on arm64 hosts"
            for corrupted in (False, True):
                binary = directory / ("ownerless-corrupt" if corrupted else "ownerless")
                defines = ["-DOWNERLESS_CORRUPT_EXPECTATION=1"] if corrupted else []
                assembly = ["dataflow.S", "ownerless_dataflow.S", "ownerless_dataflow.c"]
                if backend:
                    build, _, _ = backend.execute(
                        [
                            "i686-linux-gnu-gcc",
                            "-O2",
                            "-g0",
                            "-fno-pie",
                            "-no-pie",
                            *defines,
                            *("/source/vmp_native/" + name for name in assembly),
                            "-o",
                            "/output/" + binary.name,
                        ]
                    )
                else:
                    build, _, _ = execute(
                        [
                            "xcrun",
                            "clang",
                            "-arch",
                            "x86_64",
                            "-O2",
                            "-g0",
                            *defines,
                            *(root / "tests/vmp_native" / name for name in assembly),
                            "-o",
                            binary,
                        ]
                    )
                assert build["exit_code"] == 0 and not build["timed_out"]
                native, stdout, _ = backend.run(binary, 0) if backend else execute([binary])
                assert not native["timed_out"] and not native["output_exceeded"]
                result = json.loads(stdout)
                row["executions"].append(
                    {
                        "expected_result_corrupted": corrupted,
                        "build": build,
                        "native": native,
                        "result": result,
                        "binary_sha256": digest(binary),
                    }
                )
                if corrupted:
                    assert native["exit_code"] == 1
                    assert result == {
                        "checks": 0,
                        "passed": False,
                        "case": "od_equal",
                        "actual": 1,
                        "expected": 0,
                    }
                else:
                    assert native["exit_code"] == 0
                    assert result == {"checks": 4094, "passed": True}
            binary = directory / "ownerless"
            measurement, _, _ = execute(
                [
                    sys.executable,
                    "-B",
                    root / "tests/run_ida_smoke.py",
                    binary,
                    root / "tests/ida_ownerless_dataflow_probe.py",
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
                    *(
                        ["--set", "CHERNOBOG_REP_COUNT_BASELINE=1"]
                        if args.rep_count_baseline
                        else []
                    ),
                    *(
                        ["--set", "CHERNOBOG_STACK_STORE_BASELINE=1"]
                        if args.stack_store_baseline
                        else []
                    ),
                    *(
                        ["--set", "CHERNOBOG_STRING_COUNT_BASELINE=1"]
                        if args.string_count_baseline
                        else []
                    ),
                    *(["--set", "CHERNOBOG_SCAS_BASELINE=1"] if args.scas_baseline else []),
                    *(["--set", "CHERNOBOG_CMPS_BASELINE=1"] if args.cmps_baseline else []),
                    *(
                        ["--set", "CHERNOBOG_STOS_LOCAL_BASELINE=1"]
                        if args.stos_local_baseline
                        else []
                    ),
                ],
                timeout=180,
            )
            row["inspection"] = measurement
            assert measurement["exit_code"] == 0 and not measurement["timed_out"]
            capture = json.loads((directory / "inspection/ownerless_dataflow.json").read_text())
            run = json.loads((directory / "inspection/run.json").read_text())
            assert not capture["errors"] and all(item["passed"] for item in capture["checks"])
            assert run["artifacts_unchanged"] and run["source_script_unchanged"]
            assert run["input_sha256"] == row["executions"][0]["binary_sha256"]
            assert run["plugin_sha256"] == report["plugin_sha256"]
            assert run["ida_sha256"] == report["ida_sha256"]
            row["checks"] = len(capture["checks"])
            row["artifact_sha256"] = {
                name: digest(directory / name)
                for name in ("inspection/run.json", "inspection/ownerless_dataflow.json")
            }
            print(
                json.dumps(
                    {
                        "architecture": architecture,
                        "native_checks": 4094,
                        "corrupt_oracle_rejected": True,
                        "inspection_checks": row["checks"],
                    }
                ),
                flush=True,
            )
        assert all(digest(root / name) == value for name, value in report["source_sha256"].items())
        assert digest(args.plugin) == report["plugin_sha256"]
        assert digest(args.ida) == report["ida_sha256"]
        report["passed"] = True
    except Exception as error:
        # Exception types preserve useful failure identity without host paths.
        report["failure"] = type(error).__name__
    (output / "ownerless_dataflow_analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "failure": report.get("failure")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
