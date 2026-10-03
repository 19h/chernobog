"""Check an observed-state Morok caller replay with a bounded x86 transfer model.

The process state is observed before the caller executes. The subsequent
eighteen instructions are independently derived from pinned file bytes; no
post-return process trace is claimed.
"""

import argparse
import copy
import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from verify_native_candidate_trace import elf64_load_segments, file_bytes
from verify_native_shadow_boundary_memory import translate
from verify_native_shadow_states import REGISTER_NAMES, register_values

ROOT = 0x41B885
OWNER = 0x41B855
DATA_START = 0x444000
DATA_SIZE = 4096
STACK_SIZE = 1280
ZF = 1 << 6
DEFINED_STATUS = (1 << 0) | (1 << 2) | ZF | (1 << 7) | (1 << 11)
ZERO_STATUS = ZF | (1 << 2)
PATH = (
    0x41B885,
    0x41B88A,
    0x41B890,
    0x41B894,
    0x41B898,
    0x41B89B,
    0x41B8AB,
    0x41B8AF,
    0x41B8B7,
    0x41B8BB,
    0x41B8BF,
    0x41B8C1,
    0x41B8C7,
    0x41B8C9,
    0x41B8CB,
    0x41B8CC,
    0x41B8CD,
    0x41B8CF,
)
MNEMONICS = (
    "cmp",
    "je",
    "mov",
    "mov",
    "cmp",
    "je",
    "pxor",
    "mov",
    "movups",
    "movups",
    "test",
    "jne",
    "xor",
    "mov",
    "pop",
    "pop",
    "pop",
    "ret",
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def qword(data, offset):
    assert 0 <= offset and offset + 8 <= len(data)
    return struct.unpack_from("<Q", data, offset)[0]


def check_case(binary, segments, input_path, post_path, ida_path, post=None, ida=None):
    post = json.loads(post_path.read_text()) if post is None else post
    ida = json.loads(ida_path.read_text()) if ida is None else ida
    run = json.loads((ida_path.parent / "run.json").read_text())
    trace = ida["capture"]
    assert sha(input_path) == post["input_sha256"]
    assert sha(Path(__file__).with_name("morok_qemu_post_syscall.py")) == post["source_sha256"]
    assert hashlib.sha256(binary).hexdigest() == post["binary_sha256"] == run["input_sha256"]
    assert run["runner_return_code"] == 0 and run["plugin_unchanged"]
    assert run["script_unchanged"] and run["artifacts_unchanged"]
    assert run["script_sha256"] == sha(Path(__file__).with_name("ida_native_after_return_probe.py"))
    assert not ida["errors"] and ida["inventory_before"] == ida["inventory_after"]
    assert ida["root_info"] == {
        "owner": hex(OWNER),
        "code_head": True,
        "loaded": True,
        "segment_execute": True,
    }
    for name in ("interior_byte", "wrong_observed_pc", "missing_observed_pc", "missing_budget"):
        assert not ida[name]["available"]
    assert ida["shadow_origin"] == "current IDB loaded bytes at selected caller head"
    assert (ida_path.parent / "after_return_shadow.bin").read_bytes() == file_bytes(
        binary, segments, ROOT, 256
    )
    assert trace["available"] and trace["ran"] and trace["observed_function_checkpoint"]
    assert trace["checkpoint_owner"] == hex(OWNER) and trace["function"] == hex(ROOT)
    assert trace["entry_state_replay"] and trace["runtime_shadow"] and trace["runtime_data"]
    assert trace["native_state_capture_complete"] and trace["data_trace_complete"]
    assert trace["instruction_count"] == len(trace["execution"]) == len(PATH)
    assert trace["planned_heads"] == len(trace["heads"]) == 43
    assert trace["instruction_budget"] == 128 and not trace["plan_truncated"]
    assert trace["stop"] == "native-region-boundary"
    assert trace["boundary_source"] == hex(PATH[-1])
    assert not trace["function_evidence_published"] and not trace["vm_identity_proved"]
    assert post["boundary_registers"]["rip"] == hex(ROOT)
    assert post["data_start"] == hex(DATA_START)
    assert len(bytes.fromhex(post["boundary_data_hex"])) == DATA_SIZE
    assert len(bytes.fromhex(post["boundary_stack_hex"])) == STACK_SIZE
    assert trace["observed_entry_sp"] == post["boundary_registers"]["rsp"]
    assert trace["entry_stack_below_bytes"] == ida["stack_below_bytes"]
    assert trace["entry_stack_bytes"] == ida["stack_above_bytes"]

    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    heads = {int(row["site"], 16): row for row in trace["heads"]}
    assert len(heads) == len(trace["heads"])
    decoded = {}
    for address, row in heads.items():
        data = bytes.fromhex(row["bytes"])
        assert data and data == file_bytes(binary, segments, address, len(data))
        instruction = next(decoder.disasm(data, address, count=1), None)
        assert instruction and instruction.size == len(data) == int(row["size"])
        decoded[address] = instruction.mnemonic
    assert tuple(decoded[address] for address in PATH) == MNEMONICS
    assert tuple(int(row["site"], 16) for row in trace["execution"]) == PATH

    observed_sp = int(post["boundary_registers"]["rsp"], 16)
    synthetic_sp = int(trace["entry_sp"], 16)
    stack_base = int(post["stack_base"], 16)
    stack = bytes.fromhex(post["boundary_stack_hex"])
    data = bytearray.fromhex(post["boundary_data_hex"])
    original_data = data[:]
    registers = {name: int(post["boundary_registers"][name], 16) for name in REGISTER_NAMES}
    assert registers["rsp"] == observed_sp and stack_base <= observed_sp < stack_base + len(stack)
    base_rbx = registers["rbx"]
    data_offset = base_rbx - DATA_START
    assert 0 <= data_offset and data_offset + 0x40 <= len(data)
    states = {}
    sequence = {row["sequence"]: index for index, row in enumerate(trace["execution"])}
    for row in trace["states"]:
        if row["kind"] == "native instruction entry":
            index = sequence[row["sequence"]]
            assert index not in states and int(row["site"], 16) == PATH[index]
            states[index] = register_values(row)
    assert set(states) == set(range(len(PATH)))
    expected_writes = []
    zf = bool(int(post["boundary_registers"]["eflags"], 16) & ZF)
    xmm_zero = False
    for index, address in enumerate(PATH):
        actual = states[index]
        assert actual[16] == address
        for reg, name in enumerate(REGISTER_NAMES):
            value, _ = translate(actual[256 + reg], synthetic_sp, observed_sp)
            assert value == registers[name], (index, name, hex(value), hex(registers[name]))
        if address in (0x41B88A, 0x41B89B, 0x41B8C1):
            assert bool(actual[18] & ZF) == zf
        if address == 0x41B885:
            zf = qword(data, data_offset + 0x28) == 0
        elif address == 0x41B88A:
            assert not zf
        elif address == 0x41B890:
            registers["rsi"] = qword(data, data_offset + 8)
        elif address == 0x41B894:
            registers["rax"] = qword(data, data_offset + 0x10)
        elif address == 0x41B898:
            zf = registers["rsi"] == registers["rax"]
        elif address == 0x41B89B:
            assert zf
        elif address == 0x41B8AB:
            xmm_zero = True
        elif address in (0x41B8AF, 0x41B8B7, 0x41B8BB):
            assert xmm_zero
            offset, size = {
                0x41B8AF: (0x38, 8),
                0x41B8B7: (0x20, 16),
                0x41B8BB: (8, 16),
            }[address]
            start = data_offset + offset
            data[start : start + size] = bytes(size)
            expected_writes.append((base_rbx + offset, bytes(size)))
        elif address == 0x41B8BF:
            zf = registers["rbp"] & 0xFFFFFFFF == 0
        elif address == 0x41B8C1:
            assert zf
        elif address == 0x41B8C7:
            registers["rbp"] = 0
            zf = True
        elif address == 0x41B8C9:
            registers["rax"] = registers["rbp"] & 0xFFFFFFFF
        elif address in (0x41B8CB, 0x41B8CC, 0x41B8CD, 0x41B8CF):
            value = qword(stack, registers["rsp"] - stack_base)
            registers["rsp"] += 8
            if address == 0x41B8CB:
                registers["rbx"] = value
            elif address == 0x41B8CC:
                registers["rbp"] = value
            elif address == 0x41B8CD:
                registers["r12"] = value
            else:
                target = value
    assert zf and xmm_zero
    assert registers["rsp"] == observed_sp + 32
    assert trace["boundary_target"] == trace["stop_pc"] == hex(target)
    actual_final = {int(row["reg"]): int(row["value"], 16) for row in trace["final_registers"]}
    assert set(actual_final) == {16, 18} | set(range(256, 272))
    for reg, name in enumerate(REGISTER_NAMES):
        value, _ = translate(actual_final[256 + reg], synthetic_sp, observed_sp)
        assert value == registers[name], (name, hex(value), hex(registers[name]))
    assert actual_final[16] == target
    assert actual_final[18] & DEFINED_STATUS == ZERO_STATUS
    actual_writes = sorted(
        (int(row["address"], 16), bytes.fromhex(row["bytes"])) for row in trace["final_writes"]
    )
    assert actual_writes == sorted(expected_writes)
    return {
        "input_sha256": sha(input_path),
        "post_sha256": sha(post_path),
        "ida_sha256": sha(ida_path),
        "run_sha256": sha(ida_path.parent / "run.json"),
        "shadow_sha256": sha(ida_path.parent / "after_return_shadow.bin"),
        "plugin_sha256": run["plugin_sha256"],
        "ida_executable_sha256": run["ida_sha256"],
        "entered": len(PATH),
        "planned_heads": len(heads),
        "derived_gpr_entry_comparisons": len(PATH) * len(REGISTER_NAMES),
        "derived_final_gpr_comparisons": len(REGISTER_NAMES),
        "source_derived_return_target": hex(target),
        "written_bytes": sum(len(value) for _, value in expected_writes),
        "changed_data_bytes": sum(a != b for a, b in zip(original_data, data)),
        "inventory_unchanged": True,
    }


def rejects(action):
    try:
        action()
    except (AssertionError, IndexError, KeyError, ValueError):
        return True
    return False


def mutation_checks(binary, segments, input_path, post_path, ida_path):
    post = json.loads(post_path.read_text())
    ida = json.loads(ida_path.read_text())
    checks = {}

    def altered_post(label, mutate):
        altered = copy.deepcopy(post)
        mutate(altered)
        checks[label] = rejects(
            lambda: check_case(binary, segments, input_path, post_path, ida_path, altered, ida)
        )

    def altered_ida(label, mutate):
        altered = copy.deepcopy(ida)
        mutate(altered)
        checks[label] = rejects(
            lambda: check_case(binary, segments, input_path, post_path, ida_path, post, altered)
        )

    def change_data(record):
        data = bytearray.fromhex(record["boundary_data_hex"])
        rbx = int(record["boundary_registers"]["rbx"], 16)
        struct.pack_into("<Q", data, rbx + 0x28 - DATA_START, 0)
        record["boundary_data_hex"] = data.hex()

    def change_return(record):
        stack = bytearray.fromhex(record["boundary_stack_hex"])
        sp = int(record["boundary_registers"]["rsp"], 16)
        base = int(record["stack_base"], 16)
        stack[sp + 24 - base] ^= 1
        record["boundary_stack_hex"] = stack.hex()

    altered_post("branch_input", change_data)
    altered_post("stack_return", change_return)
    altered_ida("head_byte", lambda record: record["capture"]["heads"][0].update(bytes="90"))
    altered_ida(
        "final_register",
        lambda record: record["capture"]["final_registers"][0].update(value="0x0"),
    )
    altered_ida(
        "final_write", lambda record: record["capture"]["final_writes"][0].update(bytes="01")
    )
    assert all(checks.values()), checks
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--first-input", type=Path, required=True)
    parser.add_argument("--second-input", type=Path, required=True)
    parser.add_argument("--first-post", type=Path, required=True)
    parser.add_argument("--second-post", type=Path, required=True)
    parser.add_argument("--first-ida", type=Path, required=True)
    parser.add_argument("--second-ida", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    segments = elf64_load_segments(binary)
    cases = [
        check_case(binary, segments, input_path, post_path, ida_path)
        for input_path, post_path, ida_path in (
            (args.first_input, args.first_post, args.first_ida),
            (args.second_input, args.second_post, args.second_ida),
        )
    ]
    assert cases[0]["plugin_sha256"] == cases[1]["plugin_sha256"]
    assert cases[0]["ida_executable_sha256"] == cases[1]["ida_executable_sha256"]
    assert cases[0]["source_derived_return_target"] != cases[1]["source_derived_return_target"]
    checks = mutation_checks(binary, segments, args.first_input, args.first_post, args.first_ida)
    result = {
        "schema": 1,
        "passed": True,
        "scope": "source-derived 18-entry caller transfer from observed pre-caller state; no observed post-return process trace",
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
        "cases": cases,
        "mutations_rejected": checks,
    }
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print("Morok observed-state caller transfer verification: pass")


if __name__ == "__main__":
    main()
