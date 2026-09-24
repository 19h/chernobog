"""Record an entered instruction prefix from the keygen's packed-code entry."""

import hashlib
import json
import os
from pathlib import Path

import gdb

ROOT = 0x430000
REGISTERS = (
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
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


def memory(address, size):
    return gdb.selected_inferior().read_memory(address, size).tobytes()


def main():
    output = Path(os.environ["CHERNOBOG_PACKED_PREFIX_OUTPUT"])
    binary = Path(os.environ["CHERNOBOG_PACKED_BINARY"])
    stdin = Path(os.environ["CHERNOBOG_PACKED_STDIN"])
    limit = int(os.environ["CHERNOBOG_PACKED_PREFIX_LIMIT"])
    if not 1 <= limit <= 4096:
        raise ValueError("instruction limit must be in [1, 4096]")
    gdb.execute("set pagination off", to_string=True)
    gdb.execute("set architecture i386:x86-64", to_string=True)
    gdb.execute("target remote :1234", to_string=True)
    breakpoint = gdb.Breakpoint(f"*{ROOT:#x}")
    gdb.execute("continue", to_string=True)
    breakpoint.delete()
    if int(gdb.parse_and_eval("$rip")) != ROOT:
        raise RuntimeError("packed-entry breakpoint did not stop at expected root")
    registers = {name: hex(int(gdb.parse_and_eval("$" + name))) for name in REGISTERS}
    report = {
        "schema": 1,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "input_sha256": hashlib.sha256(stdin.read_bytes()).hexdigest(),
        "entry_registers": registers,
        "entry_stack_128_hex": memory(int(registers["rsp"], 16), 128).hex(),
        "entry_packed_65536_sha256": hashlib.sha256(memory(ROOT, 65536)).hexdigest(),
        "instruction_limit": limit,
        "instructions": [],
    }
    for _ in range(limit):
        pc = int(gdb.parse_and_eval("$rip"))
        report["instructions"].append({"pc": hex(pc), "bytes_16_hex": memory(pc, 16).hex()})
        try:
            gdb.execute("stepi", to_string=True)
        except gdb.error as error:
            report["stop"] = type(error).__name__ + ": " + str(error)
            break
    else:
        report["stop"] = "instruction-limit"
        report["next_pc"] = hex(int(gdb.parse_and_eval("$rip")))
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"[chernobog][packed-prefix] {len(report['instructions'])} entries; {report['stop']}")


main()
