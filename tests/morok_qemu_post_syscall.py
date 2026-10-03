"""Capture an observed Morok continuation after an owned syscall helper."""

import hashlib
import json
import os
from pathlib import Path

import gdb

gdb.execute("source /probe/morok_qemu_owned_call_checkpoint.py", to_string=True)

ROOT = 0x41D797
FUNCTION_START = 0x41D6C9
FUNCTION_END = 0x41D7C4
NEXT_SYSCALL = 0x41D78D
DATA_START = 0x444000
DATA_LENGTH = 4096
STACK_BELOW = 1024
STACK_ABOVE = 256
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


def digest(data):
    return hashlib.sha256(data).hexdigest()


def registers():
    return {
        name: hex(int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFFFFFFFFFF) for name in REGISTERS
    }


def memory(address, size):
    return gdb.selected_inferior().read_memory(address, size).tobytes()


owned = Path(os.environ["CHERNOBOG_OWNED_CHECKPOINT_OUTPUT"])
prior = json.loads(owned.read_text())
if registers() != prior["exit_registers"] or int(registers()["rip"], 16) != 0x41D364:
    raise RuntimeError("owned helper entry differs from preceding capture")
helper = []
for _ in range(16):
    state = registers()
    if int(state["rip"], 16) == ROOT:
        break
    helper.append(
        {
            "pc": state["rip"],
            "bytes_16_hex": memory(int(state["rip"], 16), 16).hex(),
            "registers": state,
        }
    )
    gdb.execute("stepi", to_string=True)
else:
    raise RuntimeError("owned helper did not return to caller")
entry = registers()
sp = int(entry["rsp"], 16)
shadow = memory(ROOT, 256)
Path(os.environ["CHERNOBOG_POST_SYSCALL_SHADOW_OUTPUT"]).write_bytes(shadow)
report = {
    "schema": 1,
    "source_sha256": digest(Path(__file__).read_bytes()),
    "owned_capture_sha256": digest(owned.read_bytes()),
    "binary_sha256": prior["binary_sha256"],
    "input_sha256": prior["input_sha256"],
    "owner": hex(FUNCTION_START),
    "root": hex(ROOT),
    "shadow_sha256": digest(shadow),
    "helper_entries": helper,
    "entry_registers": entry,
    "entry_data_hex": memory(DATA_START, DATA_LENGTH).hex(),
    "entry_stack_hex": memory(sp - STACK_BELOW, STACK_BELOW + STACK_ABOVE).hex(),
    "data_start": hex(DATA_START),
    "stack_base": hex(sp - STACK_BELOW),
    "stack_below": STACK_BELOW,
    "stack_above": STACK_ABOVE,
}
entries = []
for _ in range(512):
    state = registers()
    pc = int(state["rip"], 16)
    if pc == NEXT_SYSCALL or not FUNCTION_START <= pc < FUNCTION_END:
        break
    entries.append({"pc": hex(pc), "bytes_16_hex": memory(pc, 16).hex(), "registers": state})
    gdb.execute("stepi", to_string=True)
else:
    raise RuntimeError("post-syscall continuation exceeded instruction budget")
report["entries"] = entries
report["boundary_registers"] = registers()
report["boundary_data_hex"] = memory(DATA_START, DATA_LENGTH).hex()
report["boundary_stack_hex"] = memory(sp - STACK_BELOW, STACK_BELOW + STACK_ABOVE).hex()
Path(os.environ["CHERNOBOG_POST_SYSCALL_OUTPUT"]).write_text(
    json.dumps(report, separators=(",", ":")) + "\n"
)
print("[chernobog][post-syscall]", len(helper), len(entries), report["boundary_registers"]["rip"])
