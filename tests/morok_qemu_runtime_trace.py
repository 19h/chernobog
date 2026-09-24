"""GDB/QEMU process-state and instruction-prefix probe for the paired keygen."""

import hashlib
import json
import os
from pathlib import Path

import gdb

ROOT = 0x418440
PACKED = 0x430000
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


def registers():
    return {name: hex(int(gdb.parse_and_eval("$" + name))) for name in REGISTERS}


def memory(address, size):
    return gdb.selected_inferior().read_memory(address, size).tobytes()


def snapshot():
    state = registers()
    stack = int(state["rsp"], 16)
    return {
        "registers": state,
        "stack_128_hex": memory(stack, 128).hex(),
        "root_4096_sha256": hashlib.sha256(memory(ROOT, 4096)).hexdigest(),
        "root_16_hex": memory(ROOT, 16).hex(),
        "packed_65536_sha256": hashlib.sha256(memory(PACKED, 65536)).hexdigest(),
        "packed_16_hex": memory(PACKED, 16).hex(),
    }


def main():
    limit = int(os.environ["CHERNOBOG_RUNTIME_TRACE_LIMIT"])
    if not 1 <= limit <= 4096:
        raise ValueError("instruction limit must be in [1, 4096]")
    output = Path(os.environ["CHERNOBOG_RUNTIME_TRACE_OUTPUT"])
    gdb.execute("set pagination off", to_string=True)
    gdb.execute("set architecture i386:x86-64", to_string=True)
    gdb.execute("target remote :1234", to_string=True)
    report = {
        "schema": 1,
        "root": hex(ROOT),
        "packed_region": [hex(PACKED), hex(PACKED + 65536)],
        "instruction_limit": limit,
        "initial": snapshot(),
        "instructions": [],
    }
    gdb.execute(f"break *{ROOT:#x}", to_string=True)
    gdb.execute("continue", to_string=True)
    if int(gdb.parse_and_eval("$rip")) != ROOT:
        raise RuntimeError("callback breakpoint did not stop at expected root")
    report["callback"] = snapshot()
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
    print(f"[chernobog][runtime-trace] {len(report['instructions'])} entries; {report['stop']}")


main()
