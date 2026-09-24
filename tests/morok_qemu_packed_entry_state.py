"""Record one Morok packed entry stack and bounded instruction register states."""

import hashlib
import json
import os
import time
from pathlib import Path

import gdb

ROOT = 0x430000
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
    output = Path(os.environ["CHERNOBOG_PACKED_ENTRY_STATE_OUTPUT"])
    binary = Path(os.environ["CHERNOBOG_PACKED_BINARY"])
    stdin = Path(os.environ["CHERNOBOG_PACKED_STDIN"])
    limit = int(os.environ["CHERNOBOG_PACKED_ENTRY_STATE_LIMIT"])
    if not 1 <= limit <= 4096:
        raise ValueError("instruction limit must be in [1, 4096]")
    gdb.execute("set pagination off", to_string=True)
    gdb.execute("set architecture i386:x86-64", to_string=True)
    gdb.execute("target remote :1234", to_string=True)
    breakpoint = gdb.Breakpoint(f"*{ROOT:#x}")
    gdb.execute("continue", to_string=True)
    breakpoint.delete()
    entry = registers()
    if int(entry["rip"], 16) != ROOT:
        raise RuntimeError("packed-entry breakpoint did not stop at expected root")
    report = {
        "schema": 1,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "input_sha256": hashlib.sha256(stdin.read_bytes()).hexdigest(),
        "entry_packed_65536_sha256": hashlib.sha256(memory(ROOT, 65536)).hexdigest(),
        "entry_registers": entry,
        "entry_stack_128_hex": memory(int(entry["rsp"], 16), 128).hex(),
        "instruction_limit": limit,
        "entries": [],
    }
    begin = time.monotonic_ns()
    for _ in range(limit):
        state = registers()
        pc = int(state["rip"], 16)
        report["entries"].append(
            {"pc": hex(pc), "bytes_16_hex": memory(pc, 16).hex(), "registers": state}
        )
        try:
            gdb.execute("stepi", to_string=True)
        except gdb.error as error:
            report["stop"] = type(error).__name__ + ": " + str(error)
            break
    else:
        report["stop"] = "instruction-limit"
        report["next_pc"] = hex(int(gdb.parse_and_eval("$rip")) & 0xFFFFFFFFFFFFFFFF)
    report["elapsed_ns"] = time.monotonic_ns() - begin
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"[chernobog][packed-entry-state] {len(report['entries'])} entries; {report['stop']}")


main()
