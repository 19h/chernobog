"""Build and execute a fixed-time Morok keygen ELF64 paired process control."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

from run_morok_paired_control import checked, digest, tool_path
from run_vmp_corpus import base_environment, execute, terminate_bounded_process

SEED = 31337
SOURCE = "programs/int_woma_keygen.c"
PROTECTED = "int_woma_keygen-linux-x86_64-static"
CONFIG = "tests/e2e/native_pack.toml"
EPOCH = 1700000000
CASES = {
    "empty": b"",
    "bad_mathid": b"1\nbad\n",
    "valid_v14_1": b"1\n1234-56789-01234\n800001\n20270101\n",
    "valid_v14_0": b"2\n1234-56789-01234\n800001\n",
    "default_date": b"1\n1234-56789-01234\n800001\nd\n",
}
VALID = {"valid_v14_1", "valid_v14_0", "default_date"}
TOOL_INPUTS = (
    SOURCE,
    CONFIG,
    "cross_build.sh",
    "runtime/native_pack_loader.c",
    "runtime/native_pack_meta.S",
    "runtime/native_pack.ld",
    "build/src/pipeline/libMorok.dylib",
    "build/src/packer/morok-native-pack",
)


def compile_clean(morok, shim, output, clang, cc, strip, epoch):
    crt1 = checked([cc, "-print-file-name=crt1.o"])[1].decode().strip()
    libgcc = checked([cc, "-print-libgcc-file-name"])[1].decode().strip()
    sysroot = checked([cc, "-print-sysroot"])[1].decode().strip()
    if not Path(crt1).is_file() or not Path(libgcc).is_file():
        raise RuntimeError("musl startup objects or libgcc are absent")
    command = [
        clang,
        "--target=x86_64-linux-musl",
        f"-B{Path(cc).parent}",
        f"-B{Path(libgcc).parent}",
        f"-B{Path(crt1).parent}",
        f"-L{Path(libgcc).parent}",
        "-D_GNU_SOURCE",
        "-static",
        "-O3",
        "-std=c11",
        f"-DMOROK_FIXED_EPOCH={epoch}",
        SOURCE,
        shim,
        "-lm",
        "-o",
        output,
    ]
    if sysroot:
        command.insert(2, f"--sysroot={sysroot}")
    checked(command, cwd=morok)
    checked([strip, "-s", output])


def build_protected(morok, shim, output, clang):
    env = os.environ.copy()
    env.update(SEAL_BINARIES="0", AUDIT_BINARIES="0")
    checked(
        [
            morok / "cross_build.sh",
            "--source",
            SOURCE,
            "--extra-sources",
            shim,
            "--out-dir",
            output,
            "--config",
            CONFIG,
            "--seed",
            str(SEED),
            "--clang",
            clang,
            "--native-pack",
            "--linux-only",
            "--linux-target",
            "x86_64-linux-musl",
            "--libs",
            "-lm",
        ],
        cwd=morok,
        env=env,
    )
    return output / PROTECTED


def execute_input(arguments, stdin, timeout=10):
    started = time.perf_counter_ns()
    timed_out = output_exceeded = False
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(
            [str(arg) for arg in arguments],
            env=base_environment(),
            stdin=subprocess.PIPE,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        process.stdin.write(stdin)
        process.stdin.close()
        while True:
            pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if pid:
                break
            output_exceeded = (
                os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size
                > 2 * 1024 * 1024
            )
            timed_out = time.perf_counter_ns() - started > timeout * 1_000_000_000
            if timed_out or output_exceeded:
                terminate_bounded_process(process)
                _, status, usage = os.wait4(process.pid, 0)
                break
            time.sleep(0.02)
        stdout.seek(0)
        stderr.seek(0)
        out, err = stdout.read(2 * 1024 * 1024), stderr.read(2 * 1024 * 1024)
    return (
        {
            "exit_code": os.waitstatus_to_exitcode(status),
            "elapsed_ns": time.perf_counter_ns() - started,
            "peak_host_resident_bytes": int(usage.ru_maxrss)
            * (1 if sys.platform == "darwin" else 1024),
            "timed_out": timed_out,
            "output_exceeded": output_exceeded,
            "stdout_sha256": hashlib.sha256(out).hexdigest(),
            "stderr_sha256": hashlib.sha256(err).hexdigest(),
        },
        out,
        err,
    )


def run_guest(docker, context, image_id, output, binary, stdin):
    name = "chernobog-morok-keygen-" + uuid.uuid4().hex
    status, stdout, stderr = execute_input(
        [
            docker,
            "--context",
            context,
            "run",
            "--rm",
            "--name",
            name,
            "-i",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            "512m",
            "--pids-limit",
            "64",
            "--platform",
            "linux/amd64",
            "--mount",
            f"type=bind,src={output},dst=/artifacts,readonly",
            image_id,
            "/artifacts/" + binary.relative_to(output).as_posix(),
        ],
        stdin,
    )
    if status["timed_out"] or status["output_exceeded"]:
        execute([docker, "--context", context, "rm", "-f", name], timeout=10)
        raise RuntimeError("guest execution exceeded a process bound")
    return status, stdout, stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--morok-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--docker-context", default="orbstack")
    parser.add_argument("--image", default="ubuntu:24.04")
    parser.add_argument("--supplied-sample", type=Path)
    args = parser.parse_args()
    morok = args.morok_dir.resolve(strict=True)
    root = Path(__file__).resolve().parents[1]
    shim = root / "tests/vmp_corpus/morok_fixed_time.c"
    output = args.output_dir.resolve()
    if output.exists():
        raise RuntimeError("output directory must be new")
    output.mkdir(parents=True)
    for name in ("original", "shifted", "protected-first", "protected-second"):
        (output / name).mkdir()
    clang = tool_path("clang-23")
    cc = tool_path("x86_64-linux-musl-gcc")
    strip = tool_path("x86_64-linux-musl-strip")
    docker = tool_path("docker")
    original = output / "original/keygen-original"
    shifted = output / "shifted/keygen-shifted"
    compile_clean(morok, shim, original, clang, cc, strip, EPOCH)
    compile_clean(morok, shim, shifted, clang, cc, strip, EPOCH + 1)
    first = build_protected(morok, shim, output / "protected-first", clang)
    second = build_protected(morok, shim, output / "protected-second", clang)
    packer = morok / "build/src/packer/morok-native-pack"
    _, verification, _ = checked([packer, "verify", first])
    if not re.search(rb"protected_bytes=[1-9][0-9]*", verification):
        raise RuntimeError("native pack did not verify a nonempty protected region")
    _, image_out, _ = checked(
        [
            docker,
            "--context",
            args.docker_context,
            "image",
            "inspect",
            args.image,
            "--format",
            "{{.Id}} {{.Architecture}} {{.Os}}",
        ]
    )
    image = image_out.decode().split()
    if (
        len(image) != 3
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", image[0])
        or image[1:] != ["amd64", "linux"]
    ):
        raise RuntimeError("expected an identified linux/amd64 container image")
    artifacts = {"original": original, "shifted": shifted, "first": first, "second": second}
    hashes = {name: digest(path) for name, path in artifacts.items()}
    if hashes["first"] != hashes["second"] or hashes["first"] == hashes["original"]:
        raise RuntimeError("fixed-seed protected builds differ or equal the original")
    cases = {}
    for case, stdin in CASES.items():
        observations = []
        outputs = []
        for name in ("original", "first", "second"):
            for _ in range(2):
                status, stdout, stderr = run_guest(
                    docker, args.docker_context, image[0], output, artifacts[name], stdin
                )
                observations.append({"artifact": name, **status})
                outputs.append((status["exit_code"], stdout, stderr))
        expected_exit = 0 if case in VALID else 1
        if len(set(outputs)) != 1 or outputs[0][0] != expected_exit:
            raise RuntimeError(f"paired process behavior differed for {case}")
        if case in VALID and (b"Password:" not in outputs[0][1] or outputs[0][2]):
            raise RuntimeError(f"valid keygen path was not reached for {case}")
        cases[case] = {
            "input_sha256": hashlib.sha256(stdin).hexdigest(),
            "input_bytes": len(stdin),
            "exit_code": expected_exit,
            "stdout_sha256": hashlib.sha256(outputs[0][1]).hexdigest(),
            "stdout_bytes": len(outputs[0][1]),
            "stderr_sha256": hashlib.sha256(outputs[0][2]).hexdigest(),
            "stderr_bytes": len(outputs[0][2]),
            "observations": observations,
            "paired_equal": True,
        }
    shifted_status, shifted_out, shifted_err = run_guest(
        docker, args.docker_context, image[0], output, shifted, CASES["valid_v14_1"]
    )
    if shifted_status["exit_code"] or not shifted_out or shifted_err:
        raise RuntimeError("shifted-time control failed its valid path")
    if hashlib.sha256(shifted_out).hexdigest() == cases["valid_v14_1"]["stdout_sha256"]:
        raise RuntimeError("shifted-time control did not change the valid output")
    if hashes != {name: digest(path) for name, path in artifacts.items()}:
        raise RuntimeError("an executable changed during observation")
    report = {
        "schema": 1,
        "runner_sha256": digest(__file__),
        "shared_runner_sha256": digest(root / "tests/run_morok_paired_control.py"),
        "shim_sha256": digest(shim),
        "seed": SEED,
        "epoch_seconds": EPOCH,
        "shifted_epoch_seconds": EPOCH + 1,
        "source": SOURCE,
        "config": CONFIG,
        "build_settings": {
            "target": "x86_64-linux-musl",
            "link": "static",
            "optimization": "-O3",
            "language": "c11",
            "native_pack": True,
            "seal_binaries": False,
            "audit_binaries": False,
            "strip": True,
            "extra_sources": ["tests/vmp_corpus/morok_fixed_time.c"],
            "libs": ["-lm"],
        },
        "input_sha256": {name: digest(morok / name) for name in TOOL_INPUTS},
        "tool_sha256": {
            name: digest(path)
            for name, path in (
                ("clang-23", clang),
                ("x86_64-linux-musl-gcc", cc),
                ("x86_64-linux-musl-strip", strip),
                ("docker", docker),
            )
        },
        "derived_config_sha256": digest(
            output / "protected-first/.morok-static-int_woma_keygen.toml"
        ),
        "image": {"id": image[0], "architecture": image[1], "os": image[2]},
        "artifact_sha256": hashes,
        "artifact_bytes": {name: path.stat().st_size for name, path in artifacts.items()},
        "pack_verification": verification.decode().strip(),
        "cases": cases,
        "shifted_valid_stdout_sha256": hashlib.sha256(shifted_out).hexdigest(),
        "sample_lineage": "unknown",
    }
    if args.supplied_sample is not None:
        report["supplied_sample_sha256"] = digest(args.supplied_sample)
        report["fresh_differs_from_supplied"] = hashes["first"] != report["supplied_sample_sha256"]
    report_path = output / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"report_sha256": digest(report_path), "paired_equal": True}, sort_keys=True))


if __name__ == "__main__":
    main()
