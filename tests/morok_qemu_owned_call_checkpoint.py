"""Capture the first owned callee entered at the Morok branch boundary."""

import hashlib
import json
import os
from pathlib import Path

import gdb

TARGET = 0x41D6C9
FUNCTION_END = 0x41D7C4
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


gdb.execute("source /probe/morok_qemu_packed_branch_continuation.py", to_string=True)
prior_path = Path(os.environ["CHERNOBOG_PACKED_BRANCH_CONTINUATION_OUTPUT"])
prior = json.loads(prior_path.read_text())
entry = registers()
if entry != prior["boundary_registers"] or int(entry["rip"], 16) != TARGET:
    raise RuntimeError("owned call checkpoint differs from branch boundary")
sp = int(entry["rsp"], 16)
shadow = memory(TARGET, 256)
shadow_path = Path(os.environ["CHERNOBOG_OWNED_SHADOW_OUTPUT"])
shadow_path.write_bytes(shadow)
report = {
    "schema": 1,
    "source_sha256": digest(Path(__file__).read_bytes()),
    "branch_capture_sha256": digest(prior_path.read_bytes()),
    "binary_sha256": prior["binary_sha256"],
    "input_sha256": prior["input_sha256"],
    "shadow_sha256": digest(shadow),
    "shadow_start": hex(TARGET),
    "function_end": hex(FUNCTION_END),
    "entry_registers": entry,
    "entry_data_hex": memory(DATA_START, DATA_LENGTH).hex(),
    "entry_stack_hex": memory(sp - STACK_BELOW, STACK_BELOW + STACK_ABOVE).hex(),
    "data_start": hex(DATA_START),
    "stack_base": hex(sp - STACK_BELOW),
    "stack_below": STACK_BELOW,
    "stack_above": STACK_ABOVE,
}
entries = []
for _ in range(128):
    state = registers()
    pc = int(state["rip"], 16)
    if not TARGET <= pc < FUNCTION_END:
        break
    if pc == 0x41D78D:
        report["replay_stop_registers"] = state
        report["replay_stop_data_hex"] = memory(DATA_START, DATA_LENGTH).hex()
        report["replay_stop_stack_hex"] = memory(sp - STACK_BELOW, STACK_BELOW + STACK_ABOVE).hex()
    entries.append({"pc": hex(pc), "bytes_16_hex": memory(pc, 16).hex(), "registers": state})
    gdb.execute("stepi", to_string=True)
else:
    raise RuntimeError("owned callee did not leave within 128 steps")
report["entries"] = entries
if "replay_stop_registers" not in report:
    raise RuntimeError("owned callee did not reach syscall frontier")
report["exit_registers"] = registers()
report["exit_data_hex"] = memory(DATA_START, DATA_LENGTH).hex()
report["exit_stack_hex"] = memory(sp - STACK_BELOW, STACK_BELOW + STACK_ABOVE).hex()
Path(os.environ["CHERNOBOG_OWNED_CHECKPOINT_OUTPUT"]).write_text(
    json.dumps(report, separators=(",", ":")) + "\n"
)
print(
    "[chernobog][owned-call-checkpoint]",
    len(entries),
    hex(int(report["exit_registers"]["rip"], 16)),
)
