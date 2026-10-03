#!/usr/bin/env python3
"""Capture and verify two protected Morok caller continuations."""

import hashlib
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "build/morok-after-return-v1"
BINARY = OUTPUT / "protected-keygen"
BINARY_SHA256 = "f479ae1ab6f03857a0598d61df4674e24c787328dcec77461be532e3d962bbae"
CONTAINER_IMAGE = "chernobog-linux-ci:latest"
CONTAINER_IMAGE_ID = "sha256:b27cd74d026e02bdcdd8bac7c97447fe0d598174f76e252f106239aeb9722cfa"
CONTAINER_SCRIPT = """set -eu
if ! command -v qemu-x86_64 >/dev/null || ! command -v gdb-multiarch >/dev/null; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-user gdb-multiarch >/dev/null
fi
test -x /usr/bin/qemu-x86_64
test -x /usr/bin/gdb-multiarch
(/usr/bin/qemu-x86_64 -g 1234 "$CHERNOBOG_PACKED_BINARY" <"$CHERNOBOG_PACKED_STDIN" &)
sleep 1
timeout 180s /usr/bin/gdb-multiarch -q -nx -batch \
  -ex "source /probe/morok_qemu_after_return.py" \
  "$CHERNOBOG_PACKED_BINARY" >"$CHERNOBOG_GDB_LOG" 2>&1
"""


def run(arguments):
    result = subprocess.run(arguments, cwd=ROOT, check=False)
    if result.returncode:
        raise SystemExit(f"{arguments[0]} exited with status {result.returncode}")


def container_run(version):
    label = version.replace("_", "-")
    environment = {
        "CHERNOBOG_PACKED_BINARY": "/artifacts/protected-keygen",
        "CHERNOBOG_PACKED_STDIN": f"/probe/vmp_native/morok_keygen_{version}.stdin",
        "CHERNOBOG_PACKED_BRANCH_CONTINUATION_OUTPUT": f"/out/branch-{label}.json",
        "CHERNOBOG_OWNED_CHECKPOINT_OUTPUT": f"/out/owned-{label}.json",
        "CHERNOBOG_OWNED_SHADOW_OUTPUT": f"/out/owned-{label}.bin",
        "CHERNOBOG_POST_SYSCALL_OUTPUT": f"/out/post-{label}.json",
        "CHERNOBOG_POST_SYSCALL_SHADOW_OUTPUT": f"/out/post-{label}.bin",
        "CHERNOBOG_AFTER_RETURN_OUTPUT": f"/out/after-{label}.json",
        "CHERNOBOG_GDB_LOG": f"/out/gdb-{label}.log",
        "CHERNOBOG_CONTAINER_IMAGE_ID": CONTAINER_IMAGE_ID,
    }
    arguments = [
        "docker",
        "--context",
        "orbstack",
        "run",
        "--rm",
        "--platform",
        "linux/arm64",
        "--memory",
        "2g",
        "--pids-limit",
        "128",
        "--mount",
        f"type=bind,src={OUTPUT},dst=/artifacts,readonly",
        "--mount",
        f"type=bind,src={ROOT / 'tests'},dst=/probe,readonly",
        "--mount",
        f"type=bind,src={OUTPUT},dst=/out",
    ]
    for key, value in environment.items():
        arguments.extend(("--env", f"{key}={value}"))
    arguments.extend(("--entrypoint", "sh", CONTAINER_IMAGE_ID, "-c", CONTAINER_SCRIPT))
    run(arguments)


def require_container_image():
    inspection = subprocess.run(
        [
            "docker",
            "--context",
            "orbstack",
            "image",
            "inspect",
            CONTAINER_IMAGE,
            "--format",
            "{{.Id}}",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if inspection.returncode or inspection.stdout.strip() != CONTAINER_IMAGE_ID:
        raise SystemExit("container image ID differs from the pinned Morok evidence")


def main():
    run(
        [
            sys.executable,
            "-B",
            "tests/verify_native_after_return_archive.py",
            "--archive",
            "docs/VMP_NATIVE_AFTER_RETURN_CAPTURE.json.gz.b64",
            "--prior",
            "docs/VMP_NATIVE_POST_SYSCALL_CAPTURE.json.gz",
            "--evidence",
            "docs/VMP_NATIVE_AFTER_RETURN_EVIDENCE.json",
        ]
    )
    run(
        [
            sys.executable,
            "-B",
            "tests/prepare_native_after_return_observation.py",
            "--prior",
            "docs/VMP_NATIVE_POST_SYSCALL_CAPTURE.json.gz",
            "--prior-evidence",
            "docs/VMP_NATIVE_POST_SYSCALL_EVIDENCE.json",
            "--after",
            "docs/VMP_NATIVE_AFTER_RETURN_CAPTURE.json.gz.b64",
            "--after-evidence",
            "docs/VMP_NATIVE_AFTER_RETURN_EVIDENCE.json",
            "--output-dir",
            str(OUTPUT),
        ]
    )
    if hashlib.sha256(BINARY.read_bytes()).hexdigest() != BINARY_SHA256:
        raise SystemExit("protected binary hash mismatch")
    daemon = subprocess.run(
        ["docker", "--context", "orbstack", "info", "--format", "{{.ServerVersion}}"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if daemon.returncode:
        raise SystemExit("OrbStack Docker daemon unavailable; run `orb start` in a normal Terminal")
    require_container_image()
    for version in ("v14_1", "v14_0"):
        container_run(version)
        require_container_image()
    run(
        [
            sys.executable,
            "-B",
            "tests/verify_native_after_return_observed.py",
            "--binary",
            str(BINARY),
            "--first-input",
            "tests/vmp_native/morok_keygen_v14_1.stdin",
            "--first-old-post",
            str(OUTPUT / "archive/v14-1/post.json"),
            "--first-new-branch",
            str(OUTPUT / "branch-v14-1.json"),
            "--first-new-owned",
            str(OUTPUT / "owned-v14-1.json"),
            "--first-new-post",
            str(OUTPUT / "post-v14-1.json"),
            "--first-ida",
            str(OUTPUT / "archive/v14-1/after_return_probe.json"),
            "--first-observed",
            str(OUTPUT / "after-v14-1.json"),
            "--second-input",
            "tests/vmp_native/morok_keygen_v14_0.stdin",
            "--second-old-post",
            str(OUTPUT / "archive/v14-0/post.json"),
            "--second-new-branch",
            str(OUTPUT / "branch-v14-0.json"),
            "--second-new-owned",
            str(OUTPUT / "owned-v14-0.json"),
            "--second-new-post",
            str(OUTPUT / "post-v14-0.json"),
            "--second-ida",
            str(OUTPUT / "archive/v14-0/after_return_probe.json"),
            "--second-observed",
            str(OUTPUT / "after-v14-0.json"),
            "--output",
            str(OUTPUT / "verification.json"),
        ]
    )


if __name__ == "__main__":
    main()
