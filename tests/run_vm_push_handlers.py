"""Native and IDA checks for synthetic source-grammar immediate-push handlers."""

import argparse
import itertools
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
from run_vmp_corpus import digest, execute

VALUES = (0, (1 << 64) - 1, 0x80017FFFAB0080FE)
KEYS = (0, (1 << 64) - 1, 0x9A785634A581F03C)
CANARY = 0xA5A5A5A5A5A5A5A5
LEFT = 0x3C3C3C3C3C3C3C3C
RIGHT = 0x5A5A5A5A5A5A5A5A


def mask(bits):
    return (1 << bits) - 1


def rotate(value, bits, count):
    return ((value << count) | (value >> (bits - count))) & mask(bits)


def expected(config, index, equal):
    """Python integer/byte oracle, independent of the C oracle and VM evaluator."""
    mode, bits = config["mode"], config["bits"]
    dispatch_bits = 32 if config["relative"] else 8
    payload_bytes, dispatch_bytes = bits // 8, dispatch_bits // 8
    encoded, key = VALUES[index] & mask(bits), KEYS[index] & mask(mode)
    decoded = (rotate((encoded ^ key) & mask(bits), bits, 3) + 7) & mask(bits)
    decoded = ((decoded ^ 0x5A) - 9) & mask(bits)
    payload_key = key ^ decoded
    delta = (-32, 0x7FFFFFFF, -0x80000000)[index] if config["relative"] else 0
    key_after = payload_key ^ (delta & mask(32))
    inverse = ((((delta + 9) & mask(dispatch_bits)) ^ 0x5A) - 7) & mask(dispatch_bits)
    encrypted_dispatch = rotate(inverse, dispatch_bits, dispatch_bits - 3)
    encrypted_dispatch ^= payload_key & mask(dispatch_bits)
    code = bytearray(16)
    payload_at = dispatch_bytes if config["backward"] else 0
    dispatch_at = 0 if config["backward"] else payload_bytes
    code[payload_at : payload_at + payload_bytes] = encoded.to_bytes(payload_bytes, "little")
    code[dispatch_at : dispatch_at + dispatch_bytes] = encrypted_dispatch.to_bytes(
        dispatch_bytes, "little"
    )
    code[12:16] = (delta & mask(32)).to_bytes(4, "little")
    consumed = payload_bytes + (dispatch_bytes if config["relative"] or not equal else 0)
    vip = payload_bytes + dispatch_bytes - consumed if config["backward"] else consumed
    stored = (CANARY & ~mask(max(2, payload_bytes) * 8)) | decoded
    before = bytes(code) + struct.pack("<7Q", key, 0, 0, 0, 0, 0, 0)
    after = bytes(code) + struct.pack("<7Q", key, stored, key_after, vip, 1 - equal, LEFT, RIGHT)
    return {
        "index": index,
        "equal": equal,
        "encoded": encoded,
        "key": key,
        "decoded": decoded,
        "signed_dispatch_delta": delta,
        "result": 1 - equal,
        "stored": stored,
        "key_after": key_after,
        "vip_after": vip,
        "left": LEFT,
        "right": RIGHT,
        "initial": before.hex(),
        "final": after.hex(),
    }


def verify_native(stdout, config, negative=False):
    rows = []
    lines = stdout.decode("ascii").splitlines()
    assert len(lines) == 6
    for line, (index, equal) in zip(lines, itertools.product(range(3), range(2))):
        fields = line.split()
        assert len(fields) == 11
        actual = [int(value, 10 if at in (0, 1, 10) else 16) for at, value in enumerate(fields)]
        want = expected(config, index, equal)
        assert actual == [
            index,
            equal,
            *[
                want[key]
                for key in (
                    "encoded",
                    "key",
                    "result",
                    "stored",
                    "key_after",
                    "vip_after",
                    "left",
                    "right",
                )
            ],
            int(not negative),
        ]
        rows.append(want)
    return rows


def successful(measurement, expected_exit=0):
    return (
        measurement["exit_code"] == expected_exit
        and not measurement["timed_out"]
        and not measurement["output_exceeded"]
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", choices=("x86_64", "i386"), default="x86_64")
    parser.add_argument("--linux32-image")
    parser.add_argument("--docker-context", default="default")
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--ida", type=Path)
    parser.add_argument("--plugin", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.native_only and (not args.ida or not args.plugin):
        parser.error("IDA validation requires --ida and --plugin")
    if args.architecture == "i386" and not args.linux32_image:
        parser.error("i386 validation requires --linux32-image")
    root = Path(__file__).resolve().parent.parent
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    mode = 64 if args.architecture == "x86_64" else 32
    sources = [
        "tests/vmp_native/vm_push_handlers.S",
        "tests/vmp_native/vm_push_handlers.c",
        "tests/run_vm_push_handlers.py",
        "tests/ida_vm_push_handlers_probe.py",
        "tests/run_vmp_corpus.py",
    ]
    if mode == 32:
        sources += ["tests/vmp_corpus/linux32.py", "tests/vmp_corpus/linux32_exec.py"]
    if not args.native_only:
        sources += [
            "tests/run_ida_smoke.py",
            "tests/verify_vm_native_observations.py",
            "src/vm/region.cpp",
            "src/vm/region.hpp",
            "src/vm/semantics.cpp",
            "src/vm/semantics.hpp",
            "src/vm/transition.cpp",
            "src/vm/ida_regions.cpp",
            "src/vm/native_observations.cpp",
            "src/vm/ida_native_trace.cpp",
            "src/vm/summary_view.cpp",
        ]
    hashes = {name: digest(root / name) for name in sources}
    report = {
        "schema": 1,
        "passed": False,
        "scope": "synthetic source-grammar fixture; no protector-source or protected-binary authenticity claim",
        "excluded_transfer_shape": "target equals native fallthrough; the initial x64 diagnostic stopped without a transfer witness",
        "validation": "native-only" if args.native_only else "native-and-ida",
        "architecture": args.architecture,
        "source_sha256": hashes,
        "plugin_sha256": None if args.native_only else digest(args.plugin),
        "ida_sha256": None if args.native_only else digest(args.ida),
        "runs": [],
    }
    try:
        linux32 = None
        if mode == 32:
            from vmp_corpus.linux32 import Linux32

            linux32 = Linux32(root, output, args.linux32_image, args.docker_context)
            report["linux32_environment"] = linux32.metadata
        else:
            status, path, _ = execute(["xcrun", "--find", "clang"])
            assert successful(status)
            report["compiler_sha256"] = digest(Path(path.decode().strip()))
        if not args.native_only:
            import capstone
            from verify_vm_native_observations import guard_replay_controls, verify_row

            report["capstone_version"] = capstone.__version__
            report["independent_replay_controls"] = guard_replay_controls()
        for bits, backward, relative in itertools.product(
            (8, 16, 32, 64) if mode == 64 else (8, 16, 32), (False, True), (False, True)
        ):
            config = {"mode": mode, "bits": bits, "backward": backward, "relative": relative}
            label = f"push{bits}-{'backward' if backward else 'forward'}-{'relative' if relative else 'table'}"
            definitions = [
                f"-DVM_PUSH_BITS={bits}",
                f"-DVM_PUSH_BACKWARD={int(backward)}",
                f"-DVM_PUSH_RELATIVE={int(relative)}",
            ]
            binary = output / label
            if linux32:
                command = [
                    "i686-linux-gnu-gcc",
                    "-O2",
                    "-g0",
                    "-fno-pie",
                    "-no-pie",
                    "-fcf-protection=none",
                    *definitions,
                    "/source/vmp_native/vm_push_handlers.c",
                    "/source/vmp_native/vm_push_handlers.S",
                    "-o",
                    "/output/" + label,
                ]
                build, _, _ = linux32.execute(command)
            else:
                command = [
                    "xcrun",
                    "clang",
                    "-arch",
                    "x86_64",
                    "-O2",
                    "-g0",
                    "-Wl,-no_fixup_chains",
                    "-Wl,-no_data_const",
                    *definitions,
                    "tests/vmp_native/vm_push_handlers.c",
                    "tests/vmp_native/vm_push_handlers.S",
                    "-o",
                    binary,
                ]
                build, _, _ = execute(command, cwd=root, timeout=60)
            assert successful(build)
            native, stdout, _ = linux32.run(binary, 0) if linux32 else execute([binary])
            assert successful(native)
            item = {
                "label": label,
                "config": config,
                "definitions": definitions,
                "binary_sha256": digest(binary),
                "build": build,
                "native": native,
                "native_oracle": verify_native(stdout, config),
            }
            report["runs"].append(item)
            if len(report["runs"]) == 1:
                negative = output / (label + "-bad-oracle")
                altered = [*command[:-2], "-DVM_PUSH_ORACLE_XOR=1", "-o"]
                altered += ["/output/" + negative.name if linux32 else negative]
                build_control, _, _ = (
                    linux32.execute(altered) if linux32 else execute(altered, cwd=root, timeout=60)
                )
                assert successful(build_control)
                control, control_stdout, _ = (
                    linux32.run(negative, 0) if linux32 else execute([negative])
                )
                assert successful(control, 1)
                verify_native(control_stdout, config, negative=True)
                report["negative_oracle_control"] = {
                    "binary_sha256": digest(negative),
                    "build": build_control,
                    "measurement": control,
                    "deliberate_difference": "independent C expected stored value XOR 1",
                    "cases_rejected": 6,
                }
            if not args.native_only:
                destination = output / (label + "-ida")
                measurement, _, _ = execute(
                    [
                        sys.executable,
                        "-B",
                        root / "tests/run_ida_smoke.py",
                        binary,
                        root / "tests/ida_vm_push_handlers_probe.py",
                        "--ida",
                        args.ida.resolve(),
                        "--plugin",
                        args.plugin.resolve(),
                        "--output-dir",
                        destination,
                        "--enable-rax",
                        "--set",
                        "CHERNOBOG_VM_PUSH_CONFIG=" + json.dumps(config, separators=(",", ":")),
                    ],
                    timeout=180,
                )
                item["ida_measurement"] = measurement
                assert successful(measurement)
                run = json.loads((destination / "run.json").read_text())
                probe = json.loads((destination / "vm_push_handlers.json").read_text())
                assert run["runner_return_code"] == 0 and run["artifacts_unchanged"]
                assert run["source_script_unchanged"]
                assert run["plugin_sha256"] == report["plugin_sha256"]
                assert run["ida_sha256"] == report["ida_sha256"]
                assert run["script_sha256"] == hashes["tests/ida_vm_push_handlers_probe.py"]
                assert run["input_sha256"] == item["binary_sha256"]
                assert probe["passed"] and not probe["errors"]
                assert all(check["passed"] for check in probe["checks"])
                assert len(probe["captures"]) == 6
                replayed = []
                for record in probe["captures"]:
                    want = expected(config, record["index"], record["equal"])
                    trace = record["trace"]
                    assert trace["input_objects"][0]["initial"] == want["initial"]
                    assert trace["input_objects"][0]["final"] == want["final"]
                    registers = {
                        int(row["reg"]): int(row["value"], 0) for row in trace["final_registers"]
                    }
                    assert registers[0x100 if mode == 64 else 0x200] == want["result"]
                    selected = [
                        row
                        for row in trace["native_observations"]["records"]
                        if int(row["site"], 0) == probe["symbols"]["handler"]
                        and row.get("payload_bits") == str(bits)
                    ]
                    assert len(selected) == int(not record["equal"])
                    replayed += [verify_row(trace, row) for row in selected]
                item["ida_checks"] = len(probe["checks"])
                item["independent_transition_replays"] = replayed
                item["artifact_sha256"] = {
                    name: digest(destination / name)
                    for name in ("run.json", "vm_push_handlers.json")
                }
            print(
                json.dumps({"label": label, "native_cases": 6, "ida": not args.native_only}),
                flush=True,
            )
        assert all(digest(root / name) == value for name, value in hashes.items())
        assert all(digest(output / row["label"]) == row["binary_sha256"] for row in report["runs"])
        if not args.native_only:
            assert digest(args.plugin) == report["plugin_sha256"]
            assert digest(args.ida) == report["ida_sha256"]
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__
    (output / "vm_push_analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "runs": len(report["runs"]),
                "failure": report.get("failure"),
            }
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
