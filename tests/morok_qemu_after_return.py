"""Capture the protected caller's actual entries after the owned return."""

import hashlib
import json
import os
from pathlib import Path
import time

import gdb

gdb.execute("source /probe/morok_qemu_post_syscall.py", to_string=True)

ROOT = 0x41B885
CALLER_END = 0x41B8D0
DATA_START = 0x444000
DATA_LENGTH = 4096
STACK_BELOW = 1024
STACK_ABOVE = 256
MAX_STEPS = 64
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


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def registers():
    return {
        name: hex(int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFFFFFFFFFF) for name in REGISTERS
    }


def memory(address, size):
    return gdb.selected_inferior().read_memory(address, size).tobytes()


post_path = Path(os.environ["CHERNOBOG_POST_SYSCALL_OUTPUT"])
post_bytes = post_path.read_bytes()
post = json.loads(post_bytes)
owned_path = Path(os.environ["CHERNOBOG_OWNED_CHECKPOINT_OUTPUT"])
owned_bytes = owned_path.read_bytes()
owned = json.loads(owned_bytes)
branch_path = Path(os.environ["CHERNOBOG_PACKED_BRANCH_CONTINUATION_OUTPUT"])
branch_bytes = branch_path.read_bytes()
branch = json.loads(branch_bytes)
if post["owned_capture_sha256"] != hashlib.sha256(owned_bytes).hexdigest():
    raise RuntimeError("preceding post-syscall receipt differs from owned capture")
if owned["branch_capture_sha256"] != hashlib.sha256(branch_bytes).hexdigest():
    raise RuntimeError("preceding owned-call receipt differs from branch capture")
if not post["binary_sha256"] == owned["binary_sha256"] == branch["binary_sha256"]:
    raise RuntimeError("preceding protected binary identity differs")
if not post["input_sha256"] == owned["input_sha256"] == branch["input_sha256"]:
    raise RuntimeError("preceding protected input identity differs")
entry = registers()
if entry != post["boundary_registers"] or int(entry["rip"], 16) != ROOT:
    raise RuntimeError("caller entry differs from preceding process checkpoint")
stack_base = int(post["stack_base"], 16)
if stack_base + STACK_BELOW != int(post["entry_registers"]["rsp"], 16):
    raise RuntimeError("preceding process stack window has a different origin")
if not stack_base <= int(entry["rsp"], 16) < stack_base + STACK_BELOW + STACK_ABOVE:
    raise RuntimeError("caller stack is outside preceding process window")
source = Path("/probe/morok_qemu_after_return.py")
chain = (
    "morok_qemu_packed_branch_continuation.py",
    "morok_qemu_owned_call_checkpoint.py",
    "morok_qemu_post_syscall.py",
    "morok_qemu_after_return.py",
)
report = {
    "schema": 1,
    "source_sha256": digest(source),
    "source_chain_sha256": {name: digest(Path("/probe") / name) for name in chain},
    "post_sha256": hashlib.sha256(post_bytes).hexdigest(),
    "owned_sha256": hashlib.sha256(owned_bytes).hexdigest(),
    "branch_sha256": hashlib.sha256(branch_bytes).hexdigest(),
    "binary_sha256": post["binary_sha256"],
    "input_sha256": post["input_sha256"],
    "qemu_executable_sha256": branch["qemu_executable_sha256"],
    "gdb_executable_sha256": branch["gdb_executable_sha256"],
    "gdb_version": branch["gdb_version"],
    "container_image_id": os.environ["CHERNOBOG_CONTAINER_IMAGE_ID"],
    "root": hex(ROOT),
    "caller_end": hex(CALLER_END),
    "maximum_steps": MAX_STEPS,
    "data_start": hex(DATA_START),
    "stack_base": hex(stack_base),
    "entry_registers": entry,
    "entry_code_75_hex": memory(ROOT, 75).hex(),
    "entry_data_hex": memory(DATA_START, DATA_LENGTH).hex(),
    "entry_stack_hex": memory(stack_base, STACK_BELOW + STACK_ABOVE).hex(),
    "entries": [],
}
begin = time.monotonic_ns()
for _ in range(MAX_STEPS):
    state = registers()
    pc = int(state["rip"], 16)
    if not ROOT <= pc < CALLER_END:
        report["stop_reason"] = "left bounded caller"
        break
    rbx = int(state["rbx"], 16)
    report["entries"].append(
        {
            "pc": hex(pc),
            "bytes_16_hex": memory(pc, 16).hex(),
            "registers": state,
            "rbx_data_64_hex": (
                memory(rbx, 64).hex()
                if DATA_START <= rbx and rbx + 64 <= DATA_START + DATA_LENGTH
                else None
            ),
            "stack_32_hex": memory(int(state["rsp"], 16), 32).hex(),
        }
    )
    gdb.execute("stepi", to_string=True)
else:
    report["stop_reason"] = "instruction budget"
report["elapsed_ns"] = time.monotonic_ns() - begin
report["boundary_registers"] = registers()
report["boundary_data_hex"] = memory(DATA_START, DATA_LENGTH).hex()
report["boundary_stack_hex"] = memory(stack_base, STACK_BELOW + STACK_ABOVE).hex()
Path(os.environ["CHERNOBOG_AFTER_RETURN_OUTPUT"]).write_text(
    json.dumps(report, separators=(",", ":")) + "\n"
)
print(
    "[chernobog][after-return]",
    len(report["entries"]),
    report["boundary_registers"]["rip"],
    report["stop_reason"],
)
if report["stop_reason"] != "left bounded caller":
    raise RuntimeError("caller observation exceeded instruction budget")
