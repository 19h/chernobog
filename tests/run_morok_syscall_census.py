"""Capture guest syscall evidence for the supplied Morok packed-code census."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid

from run_morok_keygen_control import CASES, VALID
from run_morok_packed_execution_census import (
    CONTROL_OUTPUT_SHA256,
    CONTROL_SHA256,
    SUPPLIED_SHA256,
    packed_section,
)
from run_morok_paired_control import digest, tool_path

IMAGE_ID = "sha256:a4d366ca019230fb6e3f0423bf0cbebaab63d7f32336f19ab007cb18063a7d12"
SYSCALL = re.compile(rb"(?<![A-Za-z_0-9])(\d+) ([a-z][a-z_0-9]*)\(")
FORK = re.compile(rb"(?<![A-Za-z_0-9])(\d+) (fork|vfork)\(\) = (\d+)")
CLONE = re.compile(rb"(?<![A-Za-z_0-9])(\d+) clone\([^\n]*\) = (\d+)")
MPROTECT = re.compile(
    rb"(?<![A-Za-z_0-9])(\d+) mprotect\((0x[0-9a-f]+),(\d+),([A-Z_|]+)\) = (-?\d+)"
)
GUEST_SCRIPT = r"""import hashlib,json,pathlib,subprocess,sys
name=sys.argv[1]
stdin=sys.stdin.buffer.read()
result=subprocess.run(['qemu-x86_64','-strace','/binary'],input=stdin,capture_output=True,timeout=12)
if len(result.stdout)>2*1024*1024 or len(result.stderr)>2*1024*1024:
    raise RuntimeError('guest output bound exceeded')
out=pathlib.Path('/out')
(out/(name+'.stdout')).write_bytes(result.stdout)
(out/(name+'.syscalls')).write_bytes(result.stderr)
print(json.dumps({'input_sha256':hashlib.sha256(stdin).hexdigest(),'input_bytes':len(stdin),'return_code':result.returncode}))
"""


def inventory(data, first, end):
    forks = [
        {"parent": int(parent), "kind": kind.decode(), "child": int(child)}
        for parent, kind, child in FORK.findall(data)
    ]
    root = re.match(rb"(\d+) [a-z][a-z_0-9]*\(", data)
    if root is None:
        raise RuntimeError("missing first guest syscall")
    guest_pids = {int(root.group(1))}
    guest_pids.update(item["child"] for item in forks)
    guest_pids.update(int(child) for _, child in CLONE.findall(data))
    # Concurrent stderr writes can concatenate a return value and the next
    # PID (for example '= 6' followed by '6 wait4' appears as '= 66 wait4').
    calls = Counter(
        (int(pid), name.decode()) for pid, name in SYSCALL.findall(data) if int(pid) in guest_pids
    )
    protections = []
    for pid, address, length, flags, status in MPROTECT.findall(data):
        address, length = int(address, 16), int(length)
        protections.append(
            {
                "pid": int(pid),
                "address": hex(address),
                "length": length,
                "flags": flags.decode(),
                "return_code": int(status),
                "intersects_packed": address < end and address + length > first,
            }
        )
    if not calls:
        raise RuntimeError("QEMU produced no guest syscall records")
    if data.count(b"mprotect(") != len(protections):
        raise RuntimeError("unparsed guest mprotect call")
    if data.count(b"fork(") + data.count(b"vfork(") != len(forks):
        raise RuntimeError("unparsed guest fork call")
    return {
        "syscall_records": sum(calls.values()),
        "guest_pids": sorted(guest_pids),
        "forks": forks,
        "clone_calls": sum(count for (pid, name), count in calls.items() if name == "clone"),
        "child_exits": sorted(
            pid for pid, name in calls if name == "exit" and any(f["child"] == pid for f in forks)
        ),
        "mprotect": protections,
        "packed_mprotect": [item for item in protections if item["intersects_packed"]],
    }


def run_guest(docker, context, image, binary, output, name, stdin):
    container_name = "chernobog-syscall-census-" + uuid.uuid4().hex
    command = [
        docker,
        "--context",
        context,
        "run",
        "--rm",
        "--name",
        container_name,
        "-i",
        "--platform",
        "linux/arm64",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "2g",
        "--pids-limit",
        "128",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=128m",
        "--mount",
        f"type=bind,src={binary},dst=/binary,readonly",
        "--mount",
        f"type=bind,src={output},dst=/out",
        "--entrypoint",
        "python3",
        image,
        "-c",
        GUEST_SCRIPT,
        name,
    ]
    try:
        result = subprocess.run(command, input=stdin, capture_output=True, timeout=25)
    except subprocess.TimeoutExpired:
        subprocess.run(
            [docker, "--context", context, "rm", "-f", container_name],
            capture_output=True,
            timeout=10,
            check=False,
        )
        raise RuntimeError("guest container exceeded 25 s") from None
    if result.returncode or result.stderr:
        raise RuntimeError(f"guest {name} failed: status={result.returncode}")
    guest = json.loads(result.stdout)
    if guest["input_sha256"] != hashlib.sha256(stdin).hexdigest() or guest["input_bytes"] != len(
        stdin
    ):
        raise RuntimeError("guest input changed")
    return guest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sample", type=Path, default=Path("samples/int_woma_keygen-linux-x86_64-static")
    )
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--image", default="chernobog-vmp-qemu10-gdb:local")
    parser.add_argument("--docker-context", default="orbstack")
    args = parser.parse_args()
    sample, control = args.sample.resolve(strict=True), args.control.resolve(strict=True)
    output = args.output_dir.resolve()
    if output.exists():
        raise RuntimeError("output directory must be new")
    if digest(sample) != SUPPLIED_SHA256 or digest(control) != CONTROL_SHA256:
        raise RuntimeError("binary identity changed")
    _, supplied_region = packed_section(sample, 0x4C0000, 262144)
    _, control_region = packed_section(control, 0x430000, 65536)
    docker = tool_path("docker")
    image_id = subprocess.run(
        [
            docker,
            "--context",
            args.docker_context,
            "image",
            "inspect",
            args.image,
            "--format",
            "{{.Id}}",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    ).stdout.strip()
    if image_id != IMAGE_ID:
        raise RuntimeError("QEMU image identity changed")
    output.mkdir(parents=True)
    runs = {}
    cases = [("supplied-" + case, sample, data, supplied_region) for case, data in CASES.items()]
    cases.append(("fixed-seed-positive", control, CASES["valid_v14_1"], control_region))
    for label, binary, stdin, region in cases:
        guest = run_guest(docker, args.docker_context, args.image, binary, output, label, stdin)
        stdout = (output / (label + ".stdout")).read_bytes()
        raw = (output / (label + ".syscalls")).read_bytes()
        first, end = int(region["address"], 16), int(region["end"], 16)
        observed = inventory(raw, first, end)
        expected_exit = (
            0 if label == "fixed-seed-positive" or label.removeprefix("supplied-") in VALID else 1
        )
        if guest["return_code"] != expected_exit or (b"Password:" in stdout) != (
            expected_exit == 0
        ):
            raise RuntimeError(f"unexpected output path for {label}")
        if label == "fixed-seed-positive":
            if hashlib.sha256(stdout).hexdigest() != CONTROL_OUTPUT_SHA256:
                raise RuntimeError("positive-control stdout changed")
            if [
                (item["address"], item["length"], item["flags"], item["return_code"])
                for item in observed["packed_mprotect"]
            ] != [
                ("0x430000", 65536, "PROT_READ|PROT_WRITE", 0),
                ("0x430000", 65536, "PROT_EXEC|PROT_READ", 0),
            ]:
                raise RuntimeError("positive-control packed-page transition changed")
        elif observed["packed_mprotect"] or not observed["forks"]:
            raise RuntimeError(
                f"supplied process-tree or packed-page observation changed for {label}"
            )
        runs[label] = {
            "input_sha256": hashlib.sha256(stdin).hexdigest(),
            "input_bytes": len(stdin),
            "return_code": guest["return_code"],
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stdout_bytes": len(stdout),
            "syscalls_sha256": hashlib.sha256(raw).hexdigest(),
            "syscalls_bytes": len(raw),
            **observed,
        }
        print(
            f"{label}: {len(observed['forks'])} forks, {len(observed['packed_mprotect'])} packed mprotect calls",
            flush=True,
        )
    if digest(sample) != SUPPLIED_SHA256 or digest(control) != CONTROL_SHA256:
        raise RuntimeError("binary identity changed during capture")
    report = {
        "schema": 1,
        "scope": "QEMU 10.0.13 guest syscall observations over five supplied inputs and one distinct packed positive control",
        "runner_sha256": digest(__file__),
        "image_id": image_id,
        "binary_sha256": {"supplied": SUPPLIED_SHA256, "fixed_seed_positive": CONTROL_SHA256},
        "packed_regions": {"supplied": supplied_region, "fixed_seed_positive": control_region},
        "runs": runs,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Morok syscall census PASS", flush=True)


if __name__ == "__main__":
    main()
