"""Run the supplied hello pair with an x86-64 printf return-state interposer."""

import argparse
import hashlib
import json
import os
import struct
import subprocess
from pathlib import Path

MAGIC = 0x4348504F53544331
POSTCALL = 0x100001452
WINDOW_SIZE = 40
CAPTURE_SIZE = 328
GPRS = (
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(binary, environment):
    completed = subprocess.run(
        [str(binary)], capture_output=True, timeout=10, env=environment, check=False
    )
    if completed.returncode != 0 or completed.stdout != b"Hello World" or completed.stderr:
        raise RuntimeError("unexpected process result for " + binary.name)
    return {
        "exit_status": completed.returncode,
        "stdout_hex": completed.stdout.hex(),
        "stdout_sha256": digest(completed.stdout),
    }


def parse_capture(raw, window):
    if len(raw) != CAPTURE_SIZE:
        raise RuntimeError("capture record has wrong length")
    magic, count, return_pc = struct.unpack_from("<3Q", raw)
    gprs = struct.unpack_from("<16Q", raw, 24)
    rflags = struct.unpack_from("<Q", raw, 152)[0]
    stack = raw[160:288]
    code = raw[288:328]
    slide = return_pc - POSTCALL
    if (
        magic != MAGIC
        or count != 1
        or return_pc < POSTCALL
        or code != window
        or len(code) != WINDOW_SIZE
        or gprs[0] != 11
        or gprs[4] % 16 != 0
        or gprs[5] != gprs[4]
        or struct.unpack_from("<Q", stack, 8)[0] == 0
    ):
        raise RuntimeError("capture record violates the selected hello contract")
    return {
        "magic": hex(magic),
        "count": count,
        "return_pc": hex(return_pc),
        "slide": hex(slide),
        "gprs": {name: hex(value) for name, value in zip(GPRS, gprs, strict=True)},
        "rflags": hex(rflags),
        "stack_above_hex": stack.hex(),
        "runtime_window_hex": code.hex(),
        "caller_return_pc": hex(struct.unpack_from("<Q", stack, 8)[0]),
        "capture_sha256": digest(raw),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--protected", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--window", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    window = options.window.read_bytes()
    if len(window) != WINDOW_SIZE:
        raise RuntimeError("runtime window must contain 40 bytes")
    library = options.library.resolve()
    output = options.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": 1,
        "capture_kind": "dyld-interposed printf process return checkpoint",
        "runtime_provenance": "instrumented process; wrapper calls the resolved original printf symbol",
        "library_sha256": digest(library.read_bytes()),
        "window_sha256": digest(window),
        "binary_sha256": {},
        "baseline": {},
        "captures": {},
    }
    for name, binary in (
        ("original", options.original.resolve()),
        ("protected", options.protected.resolve()),
    ):
        report["binary_sha256"][name] = digest(binary.read_bytes())
        environment = dict(os.environ)
        environment.pop("DYLD_INSERT_LIBRARIES", None)
        environment.pop("CHERNOBOG_HELLO_POSTCALL_CAPTURE", None)
        baseline = run(binary, environment)
        report["baseline"][name] = baseline
        reports = []
        for index in range(2):
            capture_file = output.parent / f"postcall-{name}-{index}.bin"
            capture_file.unlink(missing_ok=True)
            instrumented = dict(environment)
            instrumented["DYLD_INSERT_LIBRARIES"] = str(library)
            instrumented["CHERNOBOG_HELLO_POSTCALL_CAPTURE"] = str(capture_file)
            process = run(binary, instrumented)
            if process != baseline:
                raise RuntimeError("instrumented process changed observable result")
            reports.append(parse_capture(capture_file.read_bytes(), window))
        report["captures"][name] = reports
    output.write_text(json.dumps(report, indent=2) + "\n")
    print("[chernobog][hello-postcall-interpose] PASS: 4 captures")


if __name__ == "__main__":
    main()
