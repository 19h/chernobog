"""Build and execute a source-controlled Morok ELF64 paired process control."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import uuid

from run_vmp_corpus import execute

SEED = 31337
SOURCE = "boo.c"
CONFIG = "tests/e2e/native_pack.toml"
PROTECTED = "boo-linux-x86_64-static"
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


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def checked(args, *, cwd=None, env=None, timeout=60):
    status, stdout, stderr = execute(args, cwd=cwd, env=env, timeout=timeout)
    if status["exit_code"] or status["timed_out"] or status["output_exceeded"]:
        raise RuntimeError(
            f"command failed: {Path(args[0]).name}; status={status}; " f"stderr={stderr[:500]!r}"
        )
    return status, stdout, stderr


def tool_path(name):
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"missing tool: {name}")
    # Some multi-call tools dispatch on argv[0] (Docker is one such tool).
    return Path(path).absolute()


def clean_compile(morok, output, clang, cc, strip):
    crt1 = checked([cc, "-print-file-name=crt1.o"])[1].decode().strip()
    libgcc = checked([cc, "-print-libgcc-file-name"])[1].decode().strip()
    sysroot = checked([cc, "-print-sysroot"])[1].decode().strip()
    if not Path(crt1).is_file() or not Path(libgcc).is_file():
        raise RuntimeError("musl startup objects or libgcc are absent")
    args = [
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
        SOURCE,
        "-o",
        output,
    ]
    if sysroot:
        args.insert(2, f"--sysroot={sysroot}")
    checked(args, cwd=morok)
    checked([strip, "-s", output])


def build_protected(morok, output, clang):
    env = os.environ.copy()
    env.update(SEAL_BINARIES="0", AUDIT_BINARIES="0")
    checked(
        [
            morok / "cross_build.sh",
            "--source",
            SOURCE,
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
        ],
        cwd=morok,
        env=env,
    )
    return output / PROTECTED


def run_guest(docker, context, image_id, output, binary):
    name = "chernobog-morok-" + uuid.uuid4().hex
    status, stdout, stderr = execute(
        [
            docker,
            "--context",
            context,
            "run",
            "--rm",
            "--name",
            name,
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
        timeout=10,
    )
    if status["exit_code"] or status["timed_out"] or status["output_exceeded"]:
        execute([docker, "--context", context, "rm", "-f", name], timeout=10)
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
    output = args.output_dir.resolve()
    if output.exists():
        raise RuntimeError("output directory must be new")
    output.mkdir(parents=True)
    original_dir = output / "original"
    first_dir = output / "protected-first"
    second_dir = output / "protected-second"
    for directory in (original_dir, first_dir, second_dir):
        directory.mkdir()
    clang = tool_path("clang-23")
    cc = tool_path("x86_64-linux-musl-gcc")
    strip = tool_path("x86_64-linux-musl-strip")
    docker = tool_path("docker")
    original = original_dir / "boo-original"
    clean_compile(morok, original, clang, cc, strip)
    first = build_protected(morok, first_dir, clang)
    second = build_protected(morok, second_dir, clang)
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
    image_fields = image_out.decode().split()
    if (
        len(image_fields) != 3
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_fields[0])
        or image_fields[1:] != ["amd64", "linux"]
    ):
        raise RuntimeError("expected an identified linux/amd64 container image")
    initial_hashes = {
        name: digest(path)
        for name, path in (("original", original), ("first", first), ("second", second))
    }
    if initial_hashes["first"] != initial_hashes["second"]:
        raise RuntimeError("fixed-seed protected rebuilds differ")
    observations = {}
    outputs = []
    for name, path in (("original", original), ("first", first), ("second", second)):
        observations[name] = []
        for _ in range(3):
            status, stdout, stderr = run_guest(
                docker, args.docker_context, image_fields[0], output, path
            )
            observations[name].append(status)
            outputs.append((status["exit_code"], stdout, stderr))
            if status["timed_out"] or status["output_exceeded"]:
                raise RuntimeError("guest execution exceeded a process bound")
    if len(set(outputs)) != 1 or outputs[0][0] != 0 or not outputs[0][1] or outputs[0][2]:
        raise RuntimeError("paired process output, stderr, or exit status differed")
    if initial_hashes != {
        name: digest(path)
        for name, path in (("original", original), ("first", first), ("second", second))
    }:
        raise RuntimeError("an executable changed during observation")
    report = {
        "schema": 1,
        "runner_sha256": digest(__file__),
        "seed": SEED,
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
        "derived_config_sha256": digest(first_dir / ".morok-static-boo.toml"),
        "image": {"id": image_fields[0], "architecture": image_fields[1], "os": image_fields[2]},
        "artifact_sha256": initial_hashes,
        "artifact_bytes": {
            name: path.stat().st_size
            for name, path in (("original", original), ("first", first), ("second", second))
        },
        "pack_verification": verification.decode().strip(),
        "observations": observations,
        "stdout_sha256": hashlib.sha256(outputs[0][1]).hexdigest(),
        "stderr_sha256": hashlib.sha256(outputs[0][2]).hexdigest(),
        "stdout_bytes": len(outputs[0][1]),
        "paired_equal": True,
        "sample_lineage": "unknown",
    }
    if args.supplied_sample is not None:
        report["supplied_sample_sha256"] = digest(args.supplied_sample)
        report["fresh_differs_from_supplied"] = (
            initial_hashes["first"] != report["supplied_sample_sha256"]
        )
    report_path = output / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {"report_sha256": digest(report_path), "paired_equal": True, "fixed_seed_equal": True},
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    main()
