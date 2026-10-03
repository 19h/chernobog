#!/usr/bin/env python3
"""Compare fresh protected caller entries with the prior exact IDA replay."""

import argparse
import copy
import hashlib
import json
from pathlib import Path

from verify_native_after_return import (
    DATA_SIZE,
    DATA_START,
    DEFINED_STATUS,
    PATH,
    ROOT,
    STACK_SIZE,
    ZF,
    check_case as check_source_derived,
)
from verify_native_candidate_trace import elf64_load_segments, file_bytes
from verify_native_shadow_boundary_memory import translate
from verify_native_shadow_states import REGISTER_NAMES, register_values

WRITES = {0x41B8AF: (0x38, 8), 0x41B8B7: (0x20, 16), 0x41B8BB: (8, 16)}
BRANCHES = {0x41B88A, 0x41B89B, 0x41B8C1}
CALLER_END = 0x41B8D0
CONTAINER_IMAGE_ID = "sha256:b27cd74d026e02bdcdd8bac7c97447fe0d598174f76e252f106239aeb9722cfa"
CAPTURE_CHAIN = (
    "morok_qemu_packed_branch_continuation.py",
    "morok_qemu_owned_call_checkpoint.py",
    "morok_qemu_post_syscall.py",
    "morok_qemu_after_return.py",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def states(trace):
    by_sequence = {row["sequence"]: index for index, row in enumerate(trace["execution"])}
    values = {}
    for row in trace["states"]:
        if row["kind"] == "native instruction entry":
            index = by_sequence[row["sequence"]]
            require(index not in values, "duplicate IDA entry state")
            values[index] = register_values(row)
    require(set(values) == set(range(len(PATH))), "incomplete IDA entry states")
    return values


def check_case(
    binary,
    segments,
    input_path,
    old_post_path,
    new_branch_path,
    new_owned_path,
    new_post_path,
    ida_path,
    observed_path,
    observed=None,
):
    old_post = json.loads(old_post_path.read_text())
    new_branch = json.loads(new_branch_path.read_text())
    new_owned = json.loads(new_owned_path.read_text())
    new_post = json.loads(new_post_path.read_text())
    ida = json.loads(ida_path.read_text())
    observed = json.loads(observed_path.read_text()) if observed is None else observed
    previous = check_source_derived(binary, segments, input_path, old_post_path, ida_path)
    binary_sha = hashlib.sha256(binary).hexdigest()
    require(new_branch["binary_sha256"] == binary_sha, "fresh branch binary identity")
    require(new_owned["binary_sha256"] == binary_sha, "fresh owned binary identity")
    require(new_post["binary_sha256"] == binary_sha, "fresh protected binary identity")
    require(new_branch["input_sha256"] == digest(input_path), "fresh branch input identity")
    require(new_owned["input_sha256"] == digest(input_path), "fresh owned input identity")
    require(new_post["input_sha256"] == digest(input_path), "fresh protected input identity")
    require(observed["binary_sha256"] == binary_sha, "observed binary identity")
    require(observed["input_sha256"] == digest(input_path), "observed input identity")
    require(
        observed["source_chain_sha256"]
        == {name: digest(Path(__file__).with_name(name)) for name in CAPTURE_CHAIN},
        "explicit GDB source chain",
    )
    require(
        observed["source_sha256"] == digest(Path(__file__).with_name("morok_qemu_after_return.py")),
        "GDB capture source identity",
    )
    require(observed["post_sha256"] == digest(new_post_path), "preceding process receipt")
    require(observed["owned_sha256"] == digest(new_owned_path), "preceding owned receipt")
    require(observed["branch_sha256"] == digest(new_branch_path), "preceding branch receipt")
    require(
        new_post["owned_capture_sha256"] == digest(new_owned_path),
        "post-syscall to owned receipt",
    )
    require(
        new_owned["branch_capture_sha256"] == digest(new_branch_path),
        "owned to branch receipt",
    )
    require(
        new_branch["boundary_registers"] == new_owned["entry_registers"],
        "branch to owned register boundary",
    )
    require(
        new_branch["boundary_data_hex"] == new_owned["entry_data_hex"],
        "branch to owned data boundary",
    )
    require(
        new_owned["exit_registers"] == new_post["helper_entries"][0]["registers"],
        "owned to helper register boundary",
    )
    prior_code_entries = old_post["helper_entries"] + old_post["entries"]
    fresh_code_entries = new_post["helper_entries"] + new_post["entries"]
    require(
        len(new_post["helper_entries"]) == 4
        and len(new_post["entries"]) == 19
        and tuple(row["pc"] for row in fresh_code_entries)
        == tuple(row["pc"] for row in prior_code_entries),
        "fresh helper and post-syscall path",
    )
    for index, row in enumerate(fresh_code_entries):
        require(
            bytes.fromhex(row["bytes_16_hex"])
            == file_bytes(binary, segments, int(row["pc"], 16), 16),
            f"fresh pre-caller code {index}",
        )
    require(
        new_branch["capture_source_sha256"]
        == digest(Path(__file__).with_name("morok_qemu_packed_branch_continuation.py")),
        "branch capture source identity",
    )
    for name in ("qemu_executable_sha256", "gdb_executable_sha256"):
        require(
            observed[name] == new_branch[name]
            and len(new_branch[name]) == 64
            and all(character in "0123456789abcdef" for character in new_branch[name]),
            "guest debugger tool identity: " + name,
        )
    require(observed["gdb_version"] == new_branch["gdb_version"], "guest debugger version")
    require(observed["container_image_id"] == CONTAINER_IMAGE_ID, "container image identity")
    require(new_post["root"] == old_post["root"], "fresh caller origin")
    require(new_post["data_start"] == old_post["data_start"], "fresh data origin")
    require(new_post["boundary_registers"]["rip"] == hex(ROOT), "fresh caller boundary")
    require(len(bytes.fromhex(new_post["boundary_data_hex"])) == DATA_SIZE, "fresh data size")
    require(len(bytes.fromhex(new_post["boundary_stack_hex"])) == STACK_SIZE, "fresh stack size")
    require(
        int(new_post["stack_base"], 16) == int(new_post["entry_registers"]["rsp"], 16) - 1024,
        "fresh stack origin",
    )
    caller_stack_offset = int(new_post["boundary_registers"]["rsp"], 16) - int(
        new_post["stack_base"], 16
    )
    require(0 <= caller_stack_offset <= STACK_SIZE - 32, "fresh caller stack range")
    require(observed["entry_registers"] == new_post["boundary_registers"], "GDB caller entry")
    require(observed["entry_data_hex"] == new_post["boundary_data_hex"], "GDB entry data")
    require(observed["entry_stack_hex"] == new_post["boundary_stack_hex"], "GDB entry stack")
    require(observed["stack_base"] == new_post["stack_base"], "GDB entry stack origin")
    require(
        observed["root"] == hex(ROOT) and observed["caller_end"] == hex(CALLER_END), "caller bounds"
    )
    require(observed["stop_reason"] == "left bounded caller", "protected caller stop")
    require(observed["maximum_steps"] == 64, "capture instruction budget")
    require(observed["data_start"] == hex(DATA_START), "data window base")
    require(len(bytes.fromhex(observed["entry_data_hex"])) == DATA_SIZE, "data window size")
    require(len(bytes.fromhex(observed["entry_stack_hex"])) == STACK_SIZE, "stack window size")
    require(
        bytes.fromhex(observed["entry_code_75_hex"]) == file_bytes(binary, segments, ROOT, 75),
        "live caller code vs ELF",
    )
    entries = observed["entries"]
    require(len(entries) == len(PATH), "protected caller instruction count")
    require(tuple(int(row["pc"], 16) for row in entries) == PATH, "protected caller path")
    trace = ida["capture"]
    expected_states = states(trace)
    synthetic_sp = int(trace["entry_sp"], 16)
    observed_sp = int(observed["entry_registers"]["rsp"], 16)
    stack_base = int(observed["stack_base"], 16)
    entry_stack = bytes.fromhex(observed["entry_stack_hex"])
    data = bytearray.fromhex(observed["entry_data_hex"])
    original_rbx = int(observed["entry_registers"]["rbx"], 16)
    data_offset = original_rbx - DATA_START
    require(0 <= data_offset and data_offset + 64 <= len(data), "RBX data window")
    code_bytes = stack_bytes = data_bytes = gpr_values = branch_flags = 0
    for index, (pc, row) in enumerate(zip(PATH, entries)):
        actual = row["registers"]
        expected = expected_states[index]
        require(set(actual) == set(REGISTER_NAMES) | {"rip", "eflags"}, "GDB register inventory")
        require(int(actual["rip"], 16) == expected[16] == pc, "GDB/IDA entry RIP")
        for register, name in enumerate(REGISTER_NAMES):
            modeled, _ = translate(expected[256 + register], synthetic_sp, observed_sp)
            require(int(actual[name], 16) == modeled, f"entry {index} GPR {name}")
            gpr_values += 1
        if pc in BRANCHES:
            require(
                (int(actual["eflags"], 16) ^ expected[18]) & ZF == 0,
                f"entry {index} branch ZF",
            )
            branch_flags += 1
        live = bytes.fromhex(row["bytes_16_hex"])
        require(
            len(live) == 16 and live == file_bytes(binary, segments, pc, 16),
            f"entry {index} live code",
        )
        code_bytes += len(live)
        rsp = int(actual["rsp"], 16)
        offset = rsp - stack_base
        stack = bytes.fromhex(row["stack_32_hex"])
        require(
            0 <= offset
            and offset + 32 <= len(entry_stack)
            and stack == entry_stack[offset : offset + 32],
            f"entry {index} stack",
        )
        stack_bytes += len(stack)
        if int(actual["rbx"], 16) == original_rbx:
            window = bytes.fromhex(row["rbx_data_64_hex"])
            require(window == data[data_offset : data_offset + 64], f"entry {index} data window")
            data_bytes += len(window)
        if pc in WRITES:
            relative, size = WRITES[pc]
            data[data_offset + relative : data_offset + relative + size] = bytes(size)
    final = {int(row["reg"]): int(row["value"], 16) for row in trace["final_registers"]}
    require(set(final) == {16, 18} | set(range(256, 272)), "IDA final register inventory")
    boundary = observed["boundary_registers"]
    require(int(boundary["rip"], 16) == final[16], "observed return target")
    for register, name in enumerate(REGISTER_NAMES):
        modeled, _ = translate(final[256 + register], synthetic_sp, observed_sp)
        require(int(boundary[name], 16) == modeled, "observed final GPR " + name)
        gpr_values += 1
    require(
        (int(boundary["eflags"], 16) ^ final[18]) & DEFINED_STATUS == 0,
        "observed defined final status",
    )
    require(bytes.fromhex(observed["boundary_data_hex"]) == data, "observed final data")
    require(
        bytes.fromhex(observed["boundary_stack_hex"]) == entry_stack, "observed final stack bytes"
    )
    return {
        "input_sha256": digest(input_path),
        "old_post_sha256": digest(old_post_path),
        "new_branch_sha256": digest(new_branch_path),
        "new_owned_sha256": digest(new_owned_path),
        "new_post_sha256": digest(new_post_path),
        "observed_sha256": digest(observed_path),
        "ida_sha256": digest(ida_path),
        "qemu_executable_sha256": new_branch["qemu_executable_sha256"],
        "gdb_executable_sha256": new_branch["gdb_executable_sha256"],
        "gdb_version": new_branch["gdb_version"],
        "container_image_id": observed["container_image_id"],
        "source_derived_return_target": previous["source_derived_return_target"],
        "observed_return_target": boundary["rip"],
        "instruction_entries": len(entries),
        "compared_gpr_values": gpr_values,
        "compared_branch_zf_bits": branch_flags,
        "compared_code_bytes": code_bytes,
        "compared_pre_caller_code_bytes": len(fresh_code_entries) * 16,
        "compared_stack_bytes": stack_bytes,
        "compared_live_data_bytes": data_bytes,
        "compared_final_data_bytes": len(data),
        "compared_final_stack_bytes": len(entry_stack),
        "compared_defined_final_status_bits": DEFINED_STATUS.bit_count(),
        "raw_final_rflags_xor": hex(int(boundary["eflags"], 16) ^ final[18]),
    }


def rejects(action):
    try:
        action()
    except (AssertionError, IndexError, KeyError, TypeError, ValueError):
        return True
    return False


def mutation_checks(
    binary,
    segments,
    input_path,
    old_post_path,
    new_branch_path,
    new_owned_path,
    new_post_path,
    ida_path,
    observed_path,
):
    original = json.loads(observed_path.read_text())
    checks = {}

    def altered(label, mutate):
        candidate = copy.deepcopy(original)
        mutate(candidate)
        checks[label] = rejects(
            lambda: check_case(
                binary,
                segments,
                input_path,
                old_post_path,
                new_branch_path,
                new_owned_path,
                new_post_path,
                ida_path,
                observed_path,
                candidate,
            )
        )

    def flip_hex(value):
        return hex(int(value, 16) ^ 1)

    def flip_first_byte(value):
        data = bytearray.fromhex(value)
        data[0] ^= 1
        return data.hex()

    altered("capture_source", lambda row: row.update(source_sha256="0" * 64))
    altered(
        "capture_chain",
        lambda row: row["source_chain_sha256"].update({"morok_qemu_post_syscall.py": "0" * 64}),
    )
    altered("post_receipt", lambda row: row.update(post_sha256="0" * 64))
    altered("owned_receipt", lambda row: row.update(owned_sha256="0" * 64))
    altered("branch_receipt", lambda row: row.update(branch_sha256="0" * 64))
    altered("qemu_identity", lambda row: row.update(qemu_executable_sha256="0" * 64))
    altered("gdb_identity", lambda row: row.update(gdb_executable_sha256="0" * 64))
    altered("container_identity", lambda row: row.update(container_image_id="sha256:" + "0" * 64))
    altered(
        "stack_origin",
        lambda row: row.update(stack_base=hex(int(row["stack_base"], 16) + 8)),
    )
    altered("first_pc", lambda row: row["entries"][0].update(pc=hex(ROOT + 1)))
    altered(
        "first_gpr",
        lambda row: row["entries"][0]["registers"].update(
            rax=flip_hex(row["entries"][0]["registers"]["rax"])
        ),
    )
    altered(
        "branch_flag",
        lambda row: row["entries"][1]["registers"].update(
            eflags=hex(int(row["entries"][1]["registers"]["eflags"], 16) ^ ZF)
        ),
    )
    altered(
        "first_code",
        lambda row: row["entries"][0].update(
            bytes_16_hex=flip_first_byte(row["entries"][0]["bytes_16_hex"])
        ),
    )
    altered(
        "first_stack",
        lambda row: row["entries"][0].update(
            stack_32_hex=flip_first_byte(row["entries"][0]["stack_32_hex"])
        ),
    )
    altered(
        "first_data",
        lambda row: row["entries"][0].update(
            rbx_data_64_hex=flip_first_byte(row["entries"][0]["rbx_data_64_hex"])
        ),
    )
    altered(
        "return_target",
        lambda row: row["boundary_registers"].update(
            rip=flip_hex(row["boundary_registers"]["rip"])
        ),
    )
    altered(
        "defined_final_flag",
        lambda row: row["boundary_registers"].update(
            eflags=flip_hex(row["boundary_registers"]["eflags"])
        ),
    )
    altered(
        "final_data",
        lambda row: row.update(boundary_data_hex=flip_first_byte(row["boundary_data_hex"])),
    )
    require(all(checks.values()), "counterfactual observations accepted")
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    for label in ("first", "second"):
        for name in (
            "input",
            "old-post",
            "new-branch",
            "new-owned",
            "new-post",
            "ida",
            "observed",
        ):
            parser.add_argument("--" + label + "-" + name, type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    segments = elf64_load_segments(binary)
    cases = []
    first_paths = None
    for label in ("first", "second"):
        paths = tuple(
            getattr(args, label + "_" + name)
            for name in (
                "input",
                "old_post",
                "new_branch",
                "new_owned",
                "new_post",
                "ida",
                "observed",
            )
        )
        if label == "first":
            first_paths = paths
        cases.append(check_case(binary, segments, *paths))
    require(
        cases[0]["observed_return_target"] != cases[1]["observed_return_target"],
        "input-dependent return targets",
    )
    mutations = mutation_checks(binary, segments, *first_paths)
    args.output.write_text(
        json.dumps(
            {"schema": 1, "cases": cases, "mutations_rejected": mutations}, sort_keys=True, indent=2
        )
        + "\n"
    )
    print("Morok protected after-return observation: pass")


if __name__ == "__main__":
    main()
