"""Run correlated condition proofs and independent microcode effect checks."""

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from run_vmp_corpus import digest, execute


def verify_ir(capture, baseline, expected_members=30, expected_checks=140):
    if baseline:
        return 0
    from verify_conditions_microcode import Machine, ReadFault

    profiles = {
        "be_true": (1, 8),
        "a_false": (1, 8),
        "l_true": (16, 32),
        "l_false": (0, 48),
        "ge_true": (0, 48),
        "ge_false": (16, 32),
        "le_true": (16, 32),
        "le_false": (0, 48),
        "g_true": (0, 48),
        "g_false": (16, 32),
    }
    registers, opcodes, word = capture["registers"], capture["opcodes"], capture["word_bytes"]
    observed = tuple(registers)
    checks, members = 0, 0
    for name, record in capture["microcode"].items():
        if (
            name == "rc_cap"
            or name.startswith("rc_lock_")
            or name.endswith(("_dynamic", "_patched", "_snippet"))
        ):
            continue
        case = "_".join(name.split("_")[1:3])
        truth = case.endswith("_true")
        setter, memory = name.endswith("_set"), name.endswith("_memory")
        initial = 0x123400 if setter else 8
        expected = initial | int(truth) if setter else 7 if truth else 8
        members += 1
        for profile in profiles[case]:

            def machine():
                value = Machine(
                    {
                        "name": name,
                        "destination": initial,
                        "source": 7,
                        "memory_before": 7,
                        "seed": profile,
                    },
                    registers,
                    opcodes,
                    word,
                )
                value.write(registers["rax"], word, initial)
                value.write(registers["rcx"], word, 7)
                value.write(registers["rdx"], word, value.pointer)
                for flag, bit in {"cf": 1, "pf": 2, "zf": 8, "sf": 16, "of": 32}.items():
                    value.write(registers[flag], 1, int(bool(profile & bit)))
                value.initial = dict(value.regs)
                return value

            def unchanged(value, names):
                for key in names:
                    width = (
                        2 if key == "ds" else 1 if key in ("cf", "pf", "zf", "sf", "of") else word
                    )
                    register = registers[key]
                    assert all(
                        value.regs[register + i] == value.initial[register + i]
                        for i in range(width)
                    ), (name, key)

            value = machine()
            value.execute(record["snippet"])
            assert value.read({"register": registers["rax"], "size": word}) == expected, name
            unchanged(value, (key for key in observed if key != "rax"))
            assert value.memory == value.initial_memory
            assert value.reads == ([(value.pointer, 4)] if memory else [])
            checks += 1
            if memory:
                for missing in range(4):
                    value = machine()
                    del value.memory[value.pointer + missing]
                    try:
                        value.execute(record["snippet"])
                    except ReadFault as error:
                        assert error.address == value.pointer + missing
                    else:
                        raise AssertionError("memory read fault disappeared")
                    unchanged(value, observed)
                    checks += 1
    assert members == expected_members and checks == expected_checks
    return checks


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
        "src/common/x86_abstract.h",
        "src/ida_analysis/get_pc_ida.cpp",
        "python/chernobog_evidence.py",
        "src/ida_analysis/x86_analysis.cpp",
        "src/ida_analysis/x86_analysis.hpp",
        "src/ida_analysis/native_classifier.cpp",
        "src/ida_analysis/native_engine.cpp",
        "src/ida_analysis/early_hexrays.cpp",
        "tests/verify_conditions_microcode.py",
        "tests/x86_abstract_tests.cpp",
        "tests/vmp_native/relational_conditions.c",
        "tests/vmp_native/relational_conditions_main.c",
        "tests/ida_relational_conditions_probe.py",
        "tests/run_relational_conditions.py",
        "tests/run_ida_smoke.py",
        "tests/run_vmp_corpus.py",
        "tests/vmp_corpus/linux32.py",
        "tests/vmp_corpus/linux32_exec.py",
        "tests/vmp_corpus/relations32.Dockerfile",
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
            binary = directory / "relation"
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
                        root / "tests/vmp_native/relational_conditions.c",
                        root / "tests/vmp_native/relational_conditions_main.c",
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
                        "/source/vmp_native/relational_conditions.c",
                        "/source/vmp_native/relational_conditions_main.c",
                        "-o",
                        "/output/relation",
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
            assert row["native_result"] == {"passed": True, "checks": 41476}
            row["binary_sha256"] = digest(binary)
            measurement, _, _ = execute(
                [
                    sys.executable,
                    "-B",
                    root / "tests/run_ida_smoke.py",
                    binary,
                    root / "tests/ida_relational_conditions_probe.py",
                    "--ida",
                    args.ida.resolve(),
                    "--plugin",
                    args.plugin.resolve(),
                    "--output-dir",
                    directory / "inspection",
                    "--set",
                    "CHERNOBOG_IDA_REGISTER_SCAN_DEPTH=64",
                    "--set",
                    "CHERNOBOG_IDA_FLAG_SCAN_DEPTH=64",
                    "--set",
                    "CHERNOBOG_VIEW_MODULE=" + str(root / "python/chernobog_evidence.py"),
                    *(["--set", "CHERNOBOG_RELATION_BASELINE=1"] if args.baseline else []),
                ],
                timeout=120,
            )
            row["inspection"] = measurement
            capture = json.loads((directory / "inspection/relation.json").read_text())
            run = json.loads((directory / "inspection/run.json").read_text())
            row["checks"] = len(capture["checks"])
            row["errors"] = capture["errors"]
            row["microcode_effect_checks"] = verify_ir(capture, args.baseline)
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
                for path in ("inspection/run.json", "inspection/relation.json")
            }
            print(
                json.dumps(
                    {
                        "architecture": architecture,
                        "native_checks": 41476,
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
    (output / "relation_analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "failure": report.get("failure")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
