"""Capture one protected Morok process immediately before an input branch."""

import hashlib
import json
import os
from pathlib import Path

import gdb

ROOT = 0x430000
COMPARE = 0x430315
BRANCH = 0x43031A
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
    output = Path(os.environ["CHERNOBOG_PACKED_BRANCH_OUTPUT"])
    binary = Path(os.environ["CHERNOBOG_PACKED_BINARY"])
    stdin = Path(os.environ["CHERNOBOG_PACKED_STDIN"])
    gdb.execute("set pagination off", to_string=True)
    gdb.execute("set architecture i386:x86-64", to_string=True)
    gdb.execute("target remote :1234", to_string=True)
    entry = gdb.Breakpoint(f"*{ROOT:#x}")
    gdb.execute("continue", to_string=True)
    entry.delete()
    if int(registers()["rip"], 16) != ROOT:
        raise RuntimeError("unpacked entry breakpoint did not stop at root")
    packed_hash = hashlib.sha256(memory(ROOT, 65536)).hexdigest()
    breakpoint = gdb.Breakpoint(f"*{COMPARE:#x}")
    gdb.execute("continue", to_string=True)
    breakpoint.delete()
    before = registers()
    if int(before["rip"], 16) != COMPARE:
        raise RuntimeError("compare breakpoint did not stop at expected site")
    sp = int(before["rsp"], 16)
    report = {
        "schema": 1,
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
    }
    gdb.execute("stepi", to_string=True)
    report["branch_registers"] = registers()
    if int(report["branch_registers"]["rip"], 16) != BRANCH:
        raise RuntimeError("compare successor is not the expected branch")
    gdb.execute("stepi", to_string=True)
    report["successor_registers"] = registers()
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"[chernobog][packed-branch] {COMPARE:#x} -> {report['successor_registers']['rip']}")


main()
