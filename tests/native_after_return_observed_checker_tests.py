#!/usr/bin/env python3
"""Synthetic-only format and counterfactual checks for the GDB comparator.

This file does not produce protected-process evidence. It projects the archived
IDA states into the proposed GDB report format, then tests rejection gates.
"""

import hashlib
import json
from pathlib import Path
import tempfile

from prepare_native_after_return_observation import prepare
from verify_native_after_return_observed import (
    CAPTURE_CHAIN,
    CALLER_END,
    CONTAINER_IMAGE_ID,
    DATA_START,
    PATH,
    ROOT,
    WRITES,
    check_case,
    mutation_checks,
    states,
)
from verify_native_candidate_trace import elf64_load_segments, file_bytes
from verify_native_shadow_boundary_memory import translate
from verify_native_shadow_states import REGISTER_NAMES


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def synthetic(binary, segments, input_path, branch_path, owned_path, post_path, ida_path):
    branch = json.loads(branch_path.read_text())
    post = json.loads(post_path.read_text())
    trace = json.loads(ida_path.read_text())["capture"]
    synthetic_sp = int(trace["entry_sp"], 16)
    observed_sp = int(post["boundary_registers"]["rsp"], 16)
    stack_base = int(post["stack_base"], 16)
    stack = bytes.fromhex(post["boundary_stack_hex"])
    data = bytearray.fromhex(post["boundary_data_hex"])
    rbx = int(post["boundary_registers"]["rbx"], 16)
    data_offset = rbx - DATA_START
    samples = states(trace)
    entries = []
    for index, pc in enumerate(PATH):
        expected = samples[index]
        registers = {
            name: hex(translate(expected[256 + j], synthetic_sp, observed_sp)[0])
            for j, name in enumerate(REGISTER_NAMES)
        }
        registers.update(rip=hex(pc), eflags=hex(expected[18]))
        rsp = int(registers["rsp"], 16)
        entries.append(
            {
                "pc": hex(pc),
                "registers": registers,
                "bytes_16_hex": file_bytes(binary, segments, pc, 16).hex(),
                "rbx_data_64_hex": (
                    data[data_offset : data_offset + 64].hex()
                    if int(registers["rbx"], 16) == rbx
                    else None
                ),
                "stack_32_hex": stack[rsp - stack_base : rsp - stack_base + 32].hex(),
            }
        )
        if pc in WRITES:
            relative, size = WRITES[pc]
            data[data_offset + relative : data_offset + relative + size] = bytes(size)
    final = {int(row["reg"]): int(row["value"], 16) for row in trace["final_registers"]}
    boundary = {
        name: hex(translate(final[256 + j], synthetic_sp, observed_sp)[0])
        for j, name in enumerate(REGISTER_NAMES)
    }
    boundary.update(rip=hex(final[16]), eflags=hex(final[18]))
    return {
        "schema": 1,
        "source_sha256": digest(Path(__file__).with_name("morok_qemu_after_return.py")),
        "source_chain_sha256": {
            name: digest(Path(__file__).with_name(name)) for name in CAPTURE_CHAIN
        },
        "post_sha256": digest(post_path),
        "owned_sha256": digest(owned_path),
        "branch_sha256": digest(branch_path),
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
        "input_sha256": digest(input_path),
        "qemu_executable_sha256": branch["qemu_executable_sha256"],
        "gdb_executable_sha256": branch["gdb_executable_sha256"],
        "gdb_version": branch["gdb_version"],
        "container_image_id": CONTAINER_IMAGE_ID,
        "root": hex(ROOT),
        "caller_end": hex(CALLER_END),
        "maximum_steps": 64,
        "data_start": hex(DATA_START),
        "stack_base": post["stack_base"],
        "entry_registers": post["boundary_registers"],
        "entry_code_75_hex": file_bytes(binary, segments, ROOT, 75).hex(),
        "entry_data_hex": post["boundary_data_hex"],
        "entry_stack_hex": post["boundary_stack_hex"],
        "entries": entries,
        "stop_reason": "left bounded caller",
        "boundary_registers": boundary,
        "boundary_data_hex": data.hex(),
        "boundary_stack_hex": stack.hex(),
    }


def main():
    with tempfile.TemporaryDirectory(prefix="chernobog-after-return-checker-") as directory:
        root = Path(directory)
        prepare(
            Path("docs/VMP_NATIVE_POST_SYSCALL_CAPTURE.json.gz"),
            Path("docs/VMP_NATIVE_POST_SYSCALL_EVIDENCE.json"),
            Path("docs/VMP_NATIVE_AFTER_RETURN_CAPTURE.json.gz.b64"),
            Path("docs/VMP_NATIVE_AFTER_RETURN_EVIDENCE.json"),
            root,
        )
        binary = (root / "protected-keygen").read_bytes()
        segments = elf64_load_segments(binary)
        observed_path = root / "synthetic.json"
        fresh_path = root / "synthetic-post.json"
        for version in ("v14-1", "v14-0"):
            input_path = Path(
                "tests/vmp_native/morok_keygen_" + version.replace("-", "_") + ".stdin"
            )
            post_path = root / "archive" / version / "post.json"
            branch_path = root / "archive" / version / "branch.json"
            owned_path = root / "archive" / version / "owned.json"
            ida_path = root / "archive" / version / "after_return_probe.json"
            current_post = post_path
            if version == "v14-1":
                fresh = json.loads(post_path.read_text())
                data = bytearray.fromhex(fresh["boundary_data_hex"])
                stack = bytearray.fromhex(fresh["boundary_stack_hex"])
                data[-1] ^= 1
                stack[0] ^= 1
                fresh["boundary_data_hex"] = data.hex()
                fresh["boundary_stack_hex"] = stack.hex()
                fresh_path.write_text(json.dumps(fresh, separators=(",", ":")) + "\n")
                current_post = fresh_path
            report = synthetic(
                binary, segments, input_path, branch_path, owned_path, current_post, ida_path
            )
            observed_path.write_text(json.dumps(report, separators=(",", ":")) + "\n")
            checked = check_case(
                binary,
                segments,
                input_path,
                post_path,
                branch_path,
                owned_path,
                current_post,
                ida_path,
                observed_path,
            )
            assert checked["instruction_entries"] == 18
            assert checked["compared_gpr_values"] == 18 * 16 + 16
            assert checked["compared_branch_zf_bits"] == 3
            assert checked["compared_code_bytes"] == 18 * 16
            assert checked["compared_pre_caller_code_bytes"] == 23 * 16
            assert checked["compared_stack_bytes"] == 18 * 32
            assert checked["compared_live_data_bytes"] == 15 * 64
            assert checked["compared_final_data_bytes"] == 4096
            assert checked["compared_final_stack_bytes"] == 1280
            assert checked["compared_defined_final_status_bits"] == 5
            expected_target = {
                "v14-1": "0x430584",
                "v14-0": "0x43068f",
            }[version]
            assert checked["observed_return_target"] == expected_target
            if version == "v14-1":
                assert checked["old_post_sha256"] != checked["new_post_sha256"]
                mutations = mutation_checks(
                    binary,
                    segments,
                    input_path,
                    post_path,
                    branch_path,
                    owned_path,
                    current_post,
                    ida_path,
                    observed_path,
                )
                assert len(mutations) == 18 and all(mutations.values())
                altered_post = json.loads(current_post.read_text())
                code = bytearray.fromhex(altered_post["helper_entries"][0]["bytes_16_hex"])
                code[0] ^= 1
                altered_post["helper_entries"][0]["bytes_16_hex"] = code.hex()
                altered_post_path = root / "altered-post.json"
                altered_post_path.write_text(json.dumps(altered_post, separators=(",", ":")) + "\n")
                altered_observation = json.loads(observed_path.read_text())
                altered_observation["post_sha256"] = digest(altered_post_path)
                try:
                    check_case(
                        binary,
                        segments,
                        input_path,
                        post_path,
                        branch_path,
                        owned_path,
                        altered_post_path,
                        ida_path,
                        observed_path,
                        altered_observation,
                    )
                except AssertionError as error:
                    assert str(error) == "fresh pre-caller code 0"
                else:
                    raise AssertionError("altered pre-caller code accepted")
    print("synthetic after-return checker controls: pass; no protected-process claim")


if __name__ == "__main__":
    main()
