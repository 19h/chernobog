"""Capture live register states from a Morok branch through its next boundary."""

import hashlib
import json
import os
import time
from pathlib import Path

import gdb

ROOT = 0x430000
COMPARE = 0x430315
BOUNDARY = 0x41D6C9
DATA_START = 0x444000
DATA_LENGTH = 0x1000
STACK_BELOW = 1024
STACK_ABOVE = 256
MAX_STEPS = 4096
REGISTERS = (
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
    "rip",
    "eflags",
)


def registers():
    return {
        name: hex(int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFFFFFFFFFF) for name in REGISTERS
    }


def memory(address, size):
    return gdb.selected_inferior().read_memory(address, size).tobytes()


def main():
    output = Path(os.environ["CHERNOBOG_PACKED_BRANCH_CONTINUATION_OUTPUT"])
    binary = Path(os.environ["CHERNOBOG_PACKED_BINARY"])
    stdin = Path(os.environ["CHERNOBOG_PACKED_STDIN"])
    gdb.execute("set pagination off", to_string=True)
    gdb.execute("set architecture i386:x86-64", to_string=True)
    gdb.execute("target remote :1234", to_string=True)
    entry_breakpoint = gdb.Breakpoint(f"*{ROOT:#x}")
    gdb.execute("continue", to_string=True)
    entry_breakpoint.delete()
    if int(registers()["rip"], 16) != ROOT:
        raise RuntimeError("unpacked entry stop differs")
    packed_hash = hashlib.sha256(memory(ROOT, 65536)).hexdigest()
    breakpoint = gdb.Breakpoint(f"*{COMPARE:#x}")
    gdb.execute("continue", to_string=True)
    breakpoint.delete()
    before = registers()
    if int(before["rip"], 16) != COMPARE:
        raise RuntimeError("compare stop differs")
    sp = int(before["rsp"], 16)
    report = {
        "schema": 1,
        "capture_source_sha256": hashlib.sha256(
            Path("/probe/morok_qemu_packed_branch_continuation.py").read_bytes()
        ).hexdigest(),
        "qemu_executable_sha256": hashlib.sha256(
            Path("/usr/bin/qemu-x86_64").read_bytes()
        ).hexdigest(),
        "gdb_executable_sha256": hashlib.sha256(
            Path("/usr/bin/gdb-multiarch").read_bytes()
        ).hexdigest(),
        "gdb_version": gdb.VERSION,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "input_sha256": hashlib.sha256(stdin.read_bytes()).hexdigest(),
        "entry_packed_65536_sha256": packed_hash,
        "branch_packed_65536_sha256": hashlib.sha256(memory(ROOT, 65536)).hexdigest(),
        "compare_registers": before,
        "compare_bytes_16_hex": memory(COMPARE, 16).hex(),
        "compare_data_hex": memory(DATA_START, DATA_LENGTH).hex(),
        "compare_stack_hex": memory(sp - STACK_BELOW, STACK_BELOW + STACK_ABOVE).hex(),
        "stack_base_observed": hex(sp - STACK_BELOW),
        "data_start": hex(DATA_START),
        "data_length": DATA_LENGTH,
        "stack_below": STACK_BELOW,
        "stack_above": STACK_ABOVE,
        "boundary_pc": hex(BOUNDARY),
        "maximum_steps": MAX_STEPS,
    }
    begin = time.monotonic_ns()
    entries = []
    for _ in range(MAX_STEPS):
        state = registers()
        pc = int(state["rip"], 16)
        if pc == BOUNDARY:
            break
        entries.append({"pc": hex(pc), "bytes_16_hex": memory(pc, 16).hex(), "registers": state})
        gdb.execute("stepi", to_string=True)
    else:
        raise RuntimeError("boundary not reached within instruction budget")
    report["elapsed_ns"] = time.monotonic_ns() - begin
    report["entries"] = entries
    report["boundary_registers"] = registers()
    report["boundary_data_hex"] = memory(DATA_START, DATA_LENGTH).hex()
    report["boundary_stack_hex"] = memory(sp - STACK_BELOW, STACK_BELOW + STACK_ABOVE).hex()
    output.write_text(json.dumps(report, separators=(",", ":")) + "\n")
    print(f"[chernobog][packed-branch-continuation] {len(entries)} entries; {BOUNDARY:#x}")


main()
