"""Capture the Morok keygen's mapped packed code at first execution."""

import hashlib
import json
import os
from pathlib import Path

import gdb

CALLBACK = 0x418440
PACKED = 0x430000
PACKED_SIZE = 65536
REGISTERS = ("rip", "rsp", "rax", "rdi", "rsi", "rdx", "eflags")


def memory(address, size):
    return gdb.selected_inferior().read_memory(address, size).tobytes()


def snapshot():
    registers = {name: hex(int(gdb.parse_and_eval("$" + name))) for name in REGISTERS}
    packed = memory(PACKED, PACKED_SIZE)
    return {
        "registers": registers,
        "stack_128_hex": memory(int(registers["rsp"], 16), 128).hex(),
        "callback_4096_sha256": hashlib.sha256(memory(CALLBACK, 4096)).hexdigest(),
        "packed_65536_sha256": hashlib.sha256(packed).hexdigest(),
        "packed_first_32_hex": packed[:32].hex(),
    }


def stop_at(address):
    breakpoint = gdb.Breakpoint(f"*{address:#x}")
    gdb.execute("continue", to_string=True)
    breakpoint.delete()
    if int(gdb.parse_and_eval("$rip")) != address:
        raise RuntimeError(f"breakpoint did not stop at {address:#x}")


def main():
    output = Path(os.environ["CHERNOBOG_PACKED_TRACE_OUTPUT"])
    dump = Path(os.environ["CHERNOBOG_PACKED_DUMP_OUTPUT"])
    binary = Path(os.environ["CHERNOBOG_PACKED_BINARY"])
    stdin = Path(os.environ["CHERNOBOG_PACKED_STDIN"])
    gdb.execute("set pagination off", to_string=True)
    gdb.execute("set architecture i386:x86-64", to_string=True)
    gdb.execute("target remote :1234", to_string=True)
    report = {
        "schema": 1,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "input_sha256": hashlib.sha256(stdin.read_bytes()).hexdigest(),
        "packed_region": [hex(PACKED), hex(PACKED + PACKED_SIZE)],
        "initial": snapshot(),
    }
    stop_at(CALLBACK)
    report["callback"] = snapshot()
    stop_at(PACKED)
    report["packed_entry"] = snapshot()
    unpacked = memory(PACKED, PACKED_SIZE)
    dump.write_bytes(unpacked)
    report["dump_sha256"] = hashlib.sha256(unpacked).hexdigest()
    output.write_text(json.dumps(report, indent=2) + "\n")
    print("[chernobog][packed-entry] reached " + hex(PACKED))


main()
