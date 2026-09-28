"""Compare the exact supplied Morok keygen with a clean source build."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import uuid

from run_morok_keygen_control import CASES, VALID, execute_input
from run_morok_paired_control import checked, digest, tool_path

SOURCE = "programs/int_woma_keygen.c"
SOURCE_SHA256 = "988a6144b6b3924c7ed432486d114c327f837e4ef424abb29c220fe6ee4f3628"
SAMPLE_SHA256 = "7d1971b1db221174caac0a5922a7452e1bebe214ca2355ab36c889a635699fd9"
SHELL = r"""cat >/tmp/keygen.in
ish=$(sha256sum /tmp/keygen.in | cut -d' ' -f1)
ib=$(wc -c </tmp/keygen.in)
t0=$(date +%s)
if [ "$1" = clean-first ]; then
    /artifacts/clean-keygen </tmp/keygen.in >/tmp/clean.out 2>/tmp/clean.err; a=$?
    /samples/keygen </tmp/keygen.in >/tmp/protected.out 2>/tmp/protected.err; b=$?
else
    /samples/keygen </tmp/keygen.in >/tmp/protected.out 2>/tmp/protected.err; b=$?
    /artifacts/clean-keygen </tmp/keygen.in >/tmp/clean.out 2>/tmp/clean.err; a=$?
fi
t1=$(date +%s)
co=$(sha256sum /tmp/clean.out | cut -d' ' -f1)
po=$(sha256sum /tmp/protected.out | cut -d' ' -f1)
ce=$(sha256sum /tmp/clean.err | cut -d' ' -f1)
pe=$(sha256sum /tmp/protected.err | cut -d' ' -f1)
cob=$(wc -c </tmp/clean.out)
pob=$(wc -c </tmp/protected.out)
ceb=$(wc -c </tmp/clean.err)
peb=$(wc -c </tmp/protected.err)
cmp -s /tmp/clean.out /tmp/protected.out; eqo=$?
cmp -s /tmp/clean.err /tmp/protected.err; eqe=$?
grep -Fq 'Password:' /tmp/clean.out; cpw=$?
grep -Fq 'Password:' /tmp/protected.out; ppw=$?
grep -Fq 'Bad MathID!' /tmp/clean.out; cbad=$?
grep -Fq 'Bad MathID!' /tmp/protected.out; pbad=$?
printf 'META'
for value in "$ish" "$ib" "$t0" "$t1" "$a" "$b" "$co" "$po" "$ce" "$pe" \
    "$cob" "$pob" "$ceb" "$peb" "$eqo" "$eqe" \
    "$cpw" "$ppw" "$cbad" "$pbad" "$1"; do
    printf ' %s' "$value"
done
printf '\n'
"""


def clean_build(morok, output, clang, cc, strip):
    crt1 = Path(checked([cc, "-print-file-name=crt1.o"])[1].decode().strip())
    libgcc = Path(checked([cc, "-print-libgcc-file-name"])[1].decode().strip())
    sysroot = checked([cc, "-print-sysroot"])[1].decode().strip()
    if not crt1.is_file() or not libgcc.is_file():
        raise RuntimeError("musl startup objects or libgcc are absent")
    command = [
        clang,
        "--target=x86_64-linux-musl",
        f"-B{cc.parent}",
        f"-B{libgcc.parent}",
        f"-B{crt1.parent}",
        f"-L{libgcc.parent}",
        "-D_GNU_SOURCE",
        "-static",
        "-O3",
        "-std=c11",
        SOURCE,
        "-lm",
        "-o",
        output,
    ]
    if sysroot:
        command.insert(2, f"--sysroot={sysroot}")
    checked(command, cwd=morok)
    checked([strip, "-s", output])
    return {"crt1": digest(crt1), "libgcc": digest(libgcc)}


def guest_command(docker, context, image_id, output, sample, order, name):
    return [
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
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=16m",
        "--platform",
        "linux/amd64",
        "--env",
        "TZ=UTC",
        "--env",
        "LC_ALL=C",
        "--mount",
        f"type=bind,src={output},dst=/artifacts,readonly",
        "--mount",
        f"type=bind,src={sample},dst=/samples/keygen,readonly",
        image_id,
        "/bin/sh",
        "-c",
        SHELL,
        "keygen-pair",
        order,
    ]


def parse_guest(stdout, order, expected_input):
    values = stdout.decode("ascii").strip().split()
    if len(values) != 22 or values[0] != "META" or values[-1] != order:
        raise RuntimeError("malformed guest result")
    if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in values[7:11]):
        raise RuntimeError("malformed guest digest")
    if values[1] != hashlib.sha256(expected_input).hexdigest() or int(values[2]) != len(
        expected_input
    ):
        raise RuntimeError("guest input differs from source case")
    fields = [int(value) for value in values[3:7]] + [int(value) for value in values[11:21]]
    t0, t1, clean_exit, protected_exit = fields[:4]
    (
        clean_out_bytes,
        protected_out_bytes,
        clean_err_bytes,
        protected_err_bytes,
        out_cmp,
        err_cmp,
        clean_password,
        protected_password,
        clean_bad_mathid,
        protected_bad_mathid,
    ) = fields[4:]
    if any(size > 2 * 1024 * 1024 for size in fields[4:8]):
        raise RuntimeError("guest program output exceeded 2 MiB")
    if any(value not in (0, 1) for value in fields[8:]):
        raise RuntimeError("guest comparison failed")
    return {
        "epoch_before_s": t0,
        "epoch_after_s": t1,
        "guest_input_sha256": values[1],
        "guest_input_bytes": int(values[2]),
        "clean_exit": clean_exit,
        "protected_exit": protected_exit,
        "clean_stdout_sha256": values[7],
        "protected_stdout_sha256": values[8],
        "clean_stderr_sha256": values[9],
        "protected_stderr_sha256": values[10],
        "clean_stdout_bytes": clean_out_bytes,
        "protected_stdout_bytes": protected_out_bytes,
        "clean_stderr_bytes": clean_err_bytes,
        "protected_stderr_bytes": protected_err_bytes,
        "stdout_equal": out_cmp == 0,
        "stderr_equal": err_cmp == 0,
        "clean_password_output": clean_password == 0,
        "protected_password_output": protected_password == 0,
        "clean_bad_mathid_output": clean_bad_mathid == 0,
        "protected_bad_mathid_output": protected_bad_mathid == 0,
        "order": order,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--morok-dir", type=Path, default=Path("../morok"))
    parser.add_argument(
        "--sample", type=Path, default=Path("samples/int_woma_keygen-linux-x86_64-static")
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--docker-context", default="orbstack")
    parser.add_argument("--image", default="ubuntu:24.04")
    args = parser.parse_args()
    morok, sample = args.morok_dir.resolve(strict=True), args.sample.resolve(strict=True)
    output = args.output_dir.resolve()
    if output.exists():
        raise RuntimeError("output directory must be new")
    if digest(morok / SOURCE) != SOURCE_SHA256 or digest(sample) != SAMPLE_SHA256:
        raise RuntimeError("source or supplied sample identity changed")
    output.mkdir(parents=True)
    clean = output / "clean-keygen"
    clang, cc, strip, docker = (
        tool_path(name)
        for name in ("clang-23", "x86_64-linux-musl-gcc", "x86_64-linux-musl-strip", "docker")
    )
    runtime_hashes = clean_build(morok, clean, clang, cc, strip)
    clean_sha = digest(clean)
    _, image_stdout, _ = checked(
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
    image = image_stdout.decode().split()
    if (
        len(image) != 3
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", image[0])
        or image[1:] != ["amd64", "linux"]
    ):
        raise RuntimeError("expected an identified linux/amd64 container image")
    observed = {}
    discarded = []
    for case, input_bytes in CASES.items():
        accepted = []
        for repetition, order in enumerate(("clean-first", "protected-first")):
            for attempt in range(12):
                name = "chernobog-supplied-keygen-" + uuid.uuid4().hex
                status, stdout, stderr = execute_input(
                    guest_command(
                        docker, args.docker_context, image[0], output, sample, order, name
                    ),
                    input_bytes,
                    timeout=15,
                )
                if status["timed_out"] or status["output_exceeded"]:
                    subprocess.run(
                        [docker, "--context", args.docker_context, "rm", "-f", name],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                if (
                    status["exit_code"]
                    or status["timed_out"]
                    or status["output_exceeded"]
                    or stderr
                ):
                    raise RuntimeError(
                        f"guest failed for {case}: {status}; stderr={stderr[:300]!r}"
                    )
                result = parse_guest(stdout, order, input_bytes)
                result["host_elapsed_ns"] = status["elapsed_ns"]
                result["peak_host_resident_bytes"] = status["peak_host_resident_bytes"]
                if result["epoch_before_s"] != result["epoch_after_s"]:
                    discarded.append(
                        {
                            "case": case,
                            "repetition": repetition,
                            "reason": "clock_boundary",
                            "result": result,
                        }
                    )
                    continue
                if accepted and result["epoch_before_s"] == accepted[0]["epoch_before_s"]:
                    discarded.append(
                        {
                            "case": case,
                            "repetition": repetition,
                            "reason": "same_epoch",
                            "result": result,
                        }
                    )
                    time.sleep(0.1)
                    continue
                if (
                    case == "valid_v14_1"
                    and accepted
                    and result["clean_stdout_sha256"] == accepted[0]["clean_stdout_sha256"]
                ):
                    discarded.append(
                        {
                            "case": case,
                            "repetition": repetition,
                            "reason": "same_output",
                            "result": result,
                        }
                    )
                    continue
                expected_exit = 0 if case in VALID else 1
                if (
                    result["clean_exit"] != expected_exit
                    or result["protected_exit"] != expected_exit
                    or not result["stdout_equal"]
                    or not result["stderr_equal"]
                    or result["clean_stdout_sha256"] != result["protected_stdout_sha256"]
                    or result["clean_stderr_sha256"] != result["protected_stderr_sha256"]
                    or result["clean_password_output"] != (case in VALID)
                    or result["protected_password_output"] != (case in VALID)
                    or result["clean_bad_mathid_output"] != (case == "bad_mathid")
                    or result["protected_bad_mathid_output"] != (case == "bad_mathid")
                ):
                    raise RuntimeError(f"paired process behavior differed for {case}")
                accepted.append(result)
                break
            else:
                raise RuntimeError(f"could not obtain same-second pair for {case}")
        observed[case] = {
            "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
            "input_bytes": len(input_bytes),
            "observations": accepted,
        }
        print(f"{case}: 2 matched same-second pairs", flush=True)
    if digest(clean) != clean_sha or digest(sample) != SAMPLE_SHA256:
        raise RuntimeError("an executable changed during observation")
    report = {
        "schema": 1,
        "scope": "five finite stdin cases; exact supplied Morok keygen versus clean build of candidate source",
        "source_sha256": SOURCE_SHA256,
        "sample_sha256": SAMPLE_SHA256,
        "clean_sha256": clean_sha,
        "runner_sha256": digest(__file__),
        "shared_runner_sha256": {
            name: digest(Path(__file__).parent / name)
            for name in (
                "run_morok_keygen_control.py",
                "run_morok_paired_control.py",
                "run_vmp_corpus.py",
            )
        },
        "tool_sha256": {
            name: digest(path)
            for name, path in (
                ("clang-23", clang),
                ("musl-gcc", cc),
                ("musl-strip", strip),
                ("docker", docker),
            )
        },
        "runtime_sha256": runtime_hashes,
        "image": {"id": image[0], "architecture": image[1], "os": image[2]},
        "build": {
            "target": "x86_64-linux-musl",
            "static": True,
            "optimization": "-O3",
            "language": "c11",
            "strip": True,
            "libs": ["-lm"],
            "time_shim": False,
        },
        "constraints": {
            "network": "none",
            "read_only": True,
            "capabilities": "none",
            "memory_bytes": 536870912,
            "pids": 64,
            "tmp_bytes": 16777216,
            "output_bytes_per_stream": 2097152,
            "timeout_s": 15,
            "timezone": "UTC",
        },
        "matched_cases": observed,
        "discarded_attempts": discarded,
        "accepted_pair_count": sum(len(row["observations"]) for row in observed.values()),
        "all_accepted_pairs_equal": True,
        "time_sensitivity_control": "valid_v14_1 clean stdout differs across two accepted seconds",
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("paired behavior PASS", flush=True)


if __name__ == "__main__":
    main()
