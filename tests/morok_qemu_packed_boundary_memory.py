"""Capture Morok data and stack memory at entry and one bounded path boundary."""

import hashlib
import json
import os
import time
from pathlib import Path

import gdb

ROOT = 0x430000
BOUNDARY = 0x40C89B
DATA_START = 0x444000
DATA_LENGTH = 0x6A0
STACK_BELOW = 1024
STACK_ABOVE = 128
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
    output = Path(os.environ["CHERNOBOG_PACKED_BOUNDARY_MEMORY_OUTPUT"])
    binary = Path(os.environ["CHERNOBOG_PACKED_BINARY"])
    stdin = Path(os.environ["CHERNOBOG_PACKED_STDIN"])
    gdb.execute("set pagination off", to_string=True)
    gdb.execute("set architecture i386:x86-64", to_string=True)
    gdb.execute("target remote :1234", to_string=True)
    entry_breakpoint = gdb.Breakpoint(f"*{ROOT:#x}")
    gdb.execute("continue", to_string=True)
    entry_breakpoint.delete()
    entry = registers()
    if int(entry["rip"], 16) != ROOT:
        raise RuntimeError("packed entry breakpoint did not stop at expected root")
    sp = int(entry["rsp"], 16)
    report = {
        "schema": 1,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "input_sha256": hashlib.sha256(stdin.read_bytes()).hexdigest(),
        "entry_packed_65536_sha256": hashlib.sha256(memory(ROOT, 65536)).hexdigest(),
        "entry_registers": entry,
        "entry_data_hex": memory(DATA_START, DATA_LENGTH).hex(),
        "entry_stack_hex": memory(sp - STACK_BELOW, STACK_BELOW + STACK_ABOVE).hex(),
        "stack_base_observed": hex(sp - STACK_BELOW),
        "data_start": hex(DATA_START),
        "data_length": DATA_LENGTH,
        "stack_below": STACK_BELOW,
        "stack_above": STACK_ABOVE,
    }
    reported_path = []
    begin = time.monotonic_ns()
    for _ in range(4096):
        pc = int(gdb.parse_and_eval("$rip")) & 0xFFFFFFFFFFFFFFFF
        if pc == BOUNDARY:
            break
        reported_path.append({"pc": hex(pc), "bytes_16_hex": memory(pc, 16).hex()})
        gdb.execute("stepi", to_string=True)
    else:
        raise RuntimeError("bounded path did not reach the expected instruction")
    report["elapsed_ns"] = time.monotonic_ns() - begin
    report["reported_path"] = reported_path
    boundary = registers()
    if int(boundary["rip"], 16) != BOUNDARY:
        raise RuntimeError("bounded path did not stop at expected instruction")
    report["boundary_registers"] = boundary
    report["boundary_data_hex"] = memory(DATA_START, DATA_LENGTH).hex()
    report["boundary_stack_hex"] = memory(sp - STACK_BELOW, STACK_BELOW + STACK_ABOVE).hex()
    output.write_text(json.dumps(report, indent=2) + "\n")
    print("[chernobog][packed-boundary-memory] reached", boundary["rip"])


main()
