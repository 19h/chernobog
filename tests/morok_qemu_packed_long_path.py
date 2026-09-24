"""Capture a bounded protected Morok instruction path after unpacked entry."""

import hashlib
import json
import os
import time
from pathlib import Path

import gdb

ROOT = 0x430000
MAX_BUDGET = 65536


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pc():
    return int(gdb.parse_and_eval("$rip")) & 0xFFFFFFFFFFFFFFFF


def main():
    output = Path(os.environ["CHERNOBOG_PACKED_LONG_PATH_OUTPUT"])
    binary = Path(os.environ["CHERNOBOG_PACKED_BINARY"])
    stdin = Path(os.environ["CHERNOBOG_PACKED_STDIN"])
    budget = int(os.environ.get("CHERNOBOG_PACKED_LONG_PATH_BUDGET", "16384"))
    if not 1 <= budget <= MAX_BUDGET:
        raise ValueError("invalid path budget")
    gdb.execute("set pagination off", to_string=True)
    gdb.execute("set architecture i386:x86-64", to_string=True)
    gdb.execute("target remote :1234", to_string=True)
    entry = gdb.Breakpoint(f"*{ROOT:#x}")
    gdb.execute("continue", to_string=True)
    entry.delete()
    if pc() != ROOT:
        raise RuntimeError("unpacked entry breakpoint did not stop at root")
    memory = gdb.selected_inferior().read_memory
    report = {
        "schema": 1,
        "binary_sha256": sha(binary),
        "input_sha256": sha(stdin),
        "entry_packed_65536_sha256": hashlib.sha256(memory(ROOT, 65536).tobytes()).hexdigest(),
        "entry_pc": hex(ROOT),
        "budget": budget,
    }
    entries = []
    start = time.monotonic_ns()
    for _ in range(budget):
        address = pc()
        entries.append({"pc": hex(address), "bytes_16_hex": memory(address, 16).tobytes().hex()})
        gdb.execute("stepi", to_string=True)
    report["elapsed_ns"] = time.monotonic_ns() - start
    report["entries"] = entries
    report["next_pc"] = hex(pc())
    output.write_text(json.dumps(report, separators=(",", ":")) + "\n")
    print(f"[chernobog][packed-long-path] {len(entries)} entries; next={report['next_pc']}")


main()
