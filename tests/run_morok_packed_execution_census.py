"""Census QEMU executed blocks in supplied and known packed Morok regions."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import uuid

from run_morok_keygen_control import CASES, VALID
from run_morok_paired_control import digest, tool_path

SUPPLIED_SHA256 = "7d1971b1db221174caac0a5922a7452e1bebe214ca2355ab36c889a635699fd9"
CONTROL_SHA256 = "f479ae1ab6f03857a0598d61df4674e24c787328dcec77461be532e3d962bbae"
CONTROL_OUTPUT_SHA256 = "2ff6c69467f441be9b4db70e72dc935503171785b53d1d60f54ed290db965855"
TRACE_PATTERN = re.compile(rb"\[[0-9a-f]+/([0-9a-f]+)/")
GUEST_SCRIPT = r"""import hashlib,json,pathlib,shutil,subprocess,sys
name=sys.argv[1]
stdin=sys.stdin.buffer.read()
trace=pathlib.Path('/tmp/trace.log')
result=subprocess.run(['qemu-x86_64','-d','exec,nochain','-D',str(trace),'/binary'],input=stdin,capture_output=True,timeout=12)
if trace.stat().st_size>96*1024*1024 or len(result.stdout)>2*1024*1024 or len(result.stderr)>2*1024*1024:
    raise RuntimeError('trace or output bound exceeded')
out=pathlib.Path('/out')
shutil.copyfile(trace,out/(name+'.trace.log'))
(out/(name+'.stdout')).write_bytes(result.stdout)
(out/(name+'.stderr')).write_bytes(result.stderr)
print(json.dumps({'input_sha256':hashlib.sha256(stdin).hexdigest(),'input_bytes':len(stdin),'return_code':result.returncode}))
"""


def packed_section(binary, address, length):
    data = binary.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 62:
        raise RuntimeError("expected little-endian ELF64 x86-64")
    entry = struct.unpack_from("<Q", data, 24)[0]
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    entry_size, count = struct.unpack_from("<HH", data, 58)
    if entry_size != 64 or section_offset + count * entry_size > len(data):
        raise RuntimeError("invalid section table")
    matches = []
    for index in range(count):
        offset = section_offset + index * entry_size
        kind, flags, base, file_offset, size = (
            struct.unpack_from("<I", data, offset + 4)[0],
            struct.unpack_from("<Q", data, offset + 8)[0],
            struct.unpack_from("<Q", data, offset + 16)[0],
            struct.unpack_from("<Q", data, offset + 24)[0],
            struct.unpack_from("<Q", data, offset + 32)[0],
        )
        if base == address and size == length and kind == 1 and flags & 0x6 == 0x6:
            if file_offset + size > len(data):
                raise RuntimeError("packed section exceeds file")
            matches.append(
                {
                    "address": hex(base),
                    "end": hex(base + size),
                    "file_offset": file_offset,
                    "file_sha256": hashlib.sha256(
                        data[file_offset : file_offset + size]
                    ).hexdigest(),
                }
            )
    if len(matches) != 1:
        raise RuntimeError("expected exactly one matching executable packed section")
    return entry, matches[0]


def trace_inventory(path, first, end):
    counts = Counter()
    first_packed = None
    first_trace = None
    trace_blocks = 0
    with path.open("rb") as handle:
        for line in handle:
            if not line.startswith(b"Trace "):
                continue
            match = TRACE_PATTERN.search(line)
            if match is None:
                raise RuntimeError("unparsed QEMU executed-block record")
            pc = int(match.group(1), 16)
            if first_trace is None:
                first_trace = pc
            if first_packed is None and first <= pc < end:
                first_packed = pc
            counts[pc] += 1
            trace_blocks += 1
    if trace_blocks == 0:
        raise RuntimeError("QEMU produced no executed-block records")
    return {
        "trace_sha256": digest(path),
        "trace_bytes": path.stat().st_size,
        "trace_blocks": trace_blocks,
        "unique_block_starts": len(counts),
        "first_trace_pc": hex(first_trace),
        "packed_blocks": sum(count for pc, count in counts.items() if first <= pc < end),
        "first_packed_pc": None if first_packed is None else hex(first_packed),
        "pc_counts": {hex(pc): counts[pc] for pc in sorted(counts)},
    }


def run_guest(docker, context, image, binary, output, name, stdin):
    container_name = "chernobog-packed-census-" + uuid.uuid4().hex
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
        result = subprocess.run(command, input=stdin, capture_output=True, timeout=25, check=False)
    except subprocess.TimeoutExpired:
        subprocess.run(
            [docker, "--context", context, "rm", "-f", container_name],
            capture_output=True,
            timeout=10,
            check=False,
        )
        raise RuntimeError("guest container exceeded 25 s") from None
    if result.returncode or result.stderr:
        raise RuntimeError(
            f"guest {name} failed: status={result.returncode}, stderr={result.stderr[:300]!r}"
        )
    try:
        guest = json.loads(result.stdout)
    except (ValueError, UnicodeDecodeError) as error:
        raise RuntimeError("invalid guest result") from error
    if guest["input_sha256"] != hashlib.sha256(stdin).hexdigest() or guest["input_bytes"] != len(
        stdin
    ):
        raise RuntimeError("guest received different input bytes")
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
        raise RuntimeError("supplied or positive-control artifact changed")
    supplied_entry, supplied_region = packed_section(sample, 0x4C0000, 262144)
    control_entry, control_region = packed_section(control, 0x430000, 65536)
    docker = tool_path("docker")
    image_info = subprocess.run(
        [
            docker,
            "--context",
            args.docker_context,
            "image",
            "inspect",
            args.image,
            "--format",
            "{{.Id}} {{.Architecture}} {{.Os}}",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    ).stdout.split()
    if (
        len(image_info) != 3
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_info[0])
        or image_info[1:] != ["arm64", "linux"]
    ):
        raise RuntimeError("expected identified Linux/arm64 QEMU image")
    version = subprocess.run(
        [
            docker,
            "--context",
            args.docker_context,
            "run",
            "--rm",
            "--platform",
            "linux/arm64",
            "--network",
            "none",
            "--entrypoint",
            "qemu-x86_64",
            args.image,
            "--version",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    ).stdout.splitlines()[0]
    if "version 10.0.13" not in version:
        raise RuntimeError("expected QEMU x86-64 10.0.13")
    output.mkdir(parents=True)
    runs = {}
    for label, binary, stdin, first, end, entry in [
        ("supplied-" + case, sample, data, 0x4C0000, 0x500000, supplied_entry)
        for case, data in CASES.items()
    ] + [("fixed-seed-positive", control, CASES["valid_v14_1"], 0x430000, 0x440000, control_entry)]:
        guest = run_guest(docker, args.docker_context, args.image, binary, output, label, stdin)
        trace = output / (label + ".trace.log")
        stdout, stderr = tuple(
            (output / (label + suffix)).read_bytes() for suffix in (".stdout", ".stderr")
        )
        inventory = trace_inventory(trace, first, end)
        if inventory["first_trace_pc"] != hex(entry):
            raise RuntimeError(f"QEMU trace does not start at ELF entry for {label}")
        expected_exit = (
            0 if label == "fixed-seed-positive" or label.removeprefix("supplied-") in VALID else 1
        )
        if guest["return_code"] != expected_exit:
            raise RuntimeError(f"unexpected guest exit for {label}")
        if (b"Password:" in stdout) != (expected_exit == 0):
            raise RuntimeError(f"unexpected password path for {label}")
        if label == "fixed-seed-positive":
            if hashlib.sha256(stdout).hexdigest() != CONTROL_OUTPUT_SHA256 or stderr:
                raise RuntimeError("fixed-seed positive-control output changed")
            if inventory["packed_blocks"] == 0 or inventory["first_packed_pc"] != "0x430000":
                raise RuntimeError("QEMU trace missed known packed-section execution")
        runs[label] = {
            "input_sha256": hashlib.sha256(stdin).hexdigest(),
            "input_bytes": len(stdin),
            "return_code": guest["return_code"],
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stdout_bytes": len(stdout),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "stderr_bytes": len(stderr),
            **inventory,
        }
        print(f"{label}: {inventory['packed_blocks']} packed-section blocks", flush=True)
    if digest(sample) != SUPPLIED_SHA256 or digest(control) != CONTROL_SHA256:
        raise RuntimeError("an executable changed during observation")
    report = {
        "schema": 1,
        "scope": "QEMU translated-block logs for five supplied-keygen inputs and one fixed-seed packed positive control; not an instruction-entry or all-process proof",
        "runner_sha256": digest(__file__),
        "shared_runner_sha256": digest(Path(__file__).parent / "run_morok_keygen_control.py"),
        "docker_sha256": digest(docker),
        "image": {"id": image_info[0], "architecture": image_info[1], "os": image_info[2]},
        "qemu_version": version,
        "qemu_log_options": "exec,nochain",
        "binary_sha256": {"supplied": SUPPLIED_SHA256, "fixed_seed_positive": CONTROL_SHA256},
        "elf_entry": {"supplied": hex(supplied_entry), "fixed_seed_positive": hex(control_entry)},
        "packed_regions": {"supplied": supplied_region, "fixed_seed_positive": control_region},
        "limits": {
            "guest_timeout_s": 12,
            "container_timeout_s": 25,
            "trace_bytes": 100663296,
            "output_bytes_per_stream": 2097152,
            "container_memory_bytes": 2147483648,
            "container_pids": 128,
            "tmp_bytes": 134217728,
        },
        "runs": runs,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("packed execution census PASS", flush=True)


if __name__ == "__main__":
    main()
