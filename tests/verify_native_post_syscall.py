"""Verify two protected post-syscall owned-tail replays against live QEMU states."""

import argparse
import copy
import gzip
import hashlib
import json
from pathlib import Path

import capstone
from capstone import CS_ARCH_X86, CS_MODE_64, Cs, __version__ as capstone_version

from verify_native_branch_continuation import (
    PRESERVE_EXTRA,
    compare_states,
    final_registers,
    head_checks,
    project_memory,
)
from verify_native_candidate_trace import elf64_load_segments, file_bytes

ROOT = Path(__file__).resolve().parent.parent
ENTRY = 0x41D797
OWNER = 0x41D6C9
BOUNDARY = 0x41B885
ENTERED = 19
DATA_LENGTH = 4096
STACK_LENGTH = 1280
PRESERVE_EXTRA.add("movsxd")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def check_case(
    binary, segments, label, input_path, branch_path, owned_path, post_path, shadow_path, ida_path
):
    branch, owned, post, ida = (
        read(path) for path in (branch_path, owned_path, post_path, ida_path)
    )
    run = read(ida_path.parent / "run.json")
    trace = ida["capture"]
    assert sha(binary) == branch["binary_sha256"] == owned["binary_sha256"] == post["binary_sha256"]
    assert (
        sha(input_path) == branch["input_sha256"] == owned["input_sha256"] == post["input_sha256"]
    )
    assert post["source_sha256"] == sha(Path(__file__).with_name("morok_qemu_post_syscall.py"))
    # GDB's nested `source` executes in the wrapper's Python namespace, so
    # the older capture's __file__ field identifies this wrapper. Pin the
    # older script separately in sources_sha256 below.
    assert owned["source_sha256"] == post["source_sha256"]
    assert branch["capture_source_sha256"] == sha(
        Path(__file__).with_name("morok_qemu_packed_branch_continuation.py")
    )
    assert post["owned_capture_sha256"] == sha(owned_path)
    assert owned["branch_capture_sha256"] == sha(branch_path)
    assert post["shadow_sha256"] == sha(shadow_path)
    assert shadow_path.read_bytes() == file_bytes(binary.read_bytes(), segments, ENTRY, 256)
    assert post["owner"] == hex(OWNER) and post["root"] == hex(ENTRY)
    assert post["stack_below"] == 1024 and post["stack_above"] == 256
    assert post["data_start"] == hex(0x444000)
    assert len(bytes.fromhex(post["entry_data_hex"])) == DATA_LENGTH
    assert len(bytes.fromhex(post["boundary_data_hex"])) == DATA_LENGTH
    assert len(bytes.fromhex(post["entry_stack_hex"])) == STACK_LENGTH
    assert len(bytes.fromhex(post["boundary_stack_hex"])) == STACK_LENGTH
    assert len(post["helper_entries"]) == 4 and len(post["entries"]) == ENTERED
    assert post["helper_entries"][0]["registers"] == owned["exit_registers"]
    assert post["entry_registers"]["rip"] == hex(ENTRY)
    assert post["boundary_registers"]["rip"] == hex(BOUNDARY)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    helper_mnemonics = []
    for row in post["helper_entries"]:
        address = int(row["pc"], 16)
        encoded = bytes.fromhex(row["bytes_16_hex"])
        instruction = next(decoder.disasm(encoded, address, count=1), None)
        assert instruction and encoded[: instruction.size] == file_bytes(
            binary.read_bytes(), segments, address, instruction.size
        )
        helper_mnemonics.append(instruction.mnemonic)
    assert helper_mnemonics == ["cmp", "ja", "mov", "ret"]
    assert [row["pc"] for row in post["helper_entries"]] == [
        hex(address) for address in (0x41D364, 0x41D36B, 0x41D36D, 0x41D370)
    ]
    assert not ida["errors"] and all(row["passed"] for row in ida["checks"])
    assert ida["inventory_before"] == ida["inventory_after"]
    assert ida["root_info"] == {
        "owner": hex(OWNER),
        "code_head": True,
        "loaded": True,
        "segment_execute": True,
    }
    assert not ida["interior_byte"]["available"] and not ida["missing_budget"]["available"]
    assert not ida["missing_observed_pc"]["available"]
    assert not ida["wrong_observed_pc"]["available"]
    assert run["runner_return_code"] == 0 and run["plugin_unchanged"]
    assert run["script_unchanged"] and run["artifacts_unchanged"]
    assert run["script_sha256"] == sha(Path(__file__).with_name("ida_native_post_syscall_probe.py"))
    assert run["input_sha256"] == sha(binary)
    assert trace["available"] and trace["ran"] and trace["observed_function_checkpoint"]
    assert trace["checkpoint_owner"] == hex(OWNER) and trace["function"] == hex(ENTRY)
    assert trace["entry_state_replay"] and trace["runtime_shadow"] and trace["runtime_data"]
    assert trace["native_state_capture_complete"] and trace["data_trace_complete"]
    assert trace["instruction_count"] == len(trace["execution"]) == ENTERED
    assert trace["planned_heads"] == 48 and trace["instruction_budget"] == 128
    assert trace["stop"] == "native-region-boundary" and trace["stop_pc"] == hex(BOUNDARY)
    assert trace["boundary_source"] == hex(0x41D74D) and trace["boundary_target"] == hex(BOUNDARY)
    assert trace["shadow_start"] == hex(ENTRY) and trace["shadow_bytes"] == 256
    assert trace["data_bytes"] == DATA_LENGTH and trace["entry_stack_below_bytes"] == 1024
    assert trace["entry_stack_bytes"] == 256
    assert not trace["function_evidence_published"] and not trace["vm_identity_proved"]
    heads, mismatched_heads = head_checks(trace, binary.read_bytes(), segments, b"", decoder)
    assert len(heads) == 48 and not mismatched_heads
    runtime = dict(
        post,
        compare_registers=post["entry_registers"],
        compare_data_hex=post["entry_data_hex"],
        compare_stack_hex=post["entry_stack_hex"],
    )
    comparisons = compare_states(trace, runtime, heads, decoder)
    counts = comparisons["counts"]
    assert not comparisons["first_scalar_mismatches"]
    assert counts["exact_gprs"] == ENTERED * 16
    assert counts["exact_rip"] == ENTERED
    assert counts["exact_defined_bits"] == counts["defined_bits"]
    final = final_registers(trace, runtime)
    assert not final["gpr_mismatches"] and final["rip_exact"] and final["rflags_exact"]
    memory = project_memory(trace, runtime, trace["final_writes"])
    assert memory["data_exact"] and memory["stack_exact"]
    altered = copy.deepcopy(runtime)
    altered["entries"][0]["registers"]["rax"] = "0x0"
    assert compare_states(trace, altered, heads, decoder)["first_scalar_mismatches"]
    altered_heads = copy.deepcopy(trace)
    altered_heads["heads"][0]["bytes"] = "90"
    assert head_checks(altered_heads, binary.read_bytes(), segments, b"", decoder)[1]
    altered_writes = copy.deepcopy(trace["final_writes"])
    assert altered_writes
    value = bytearray.fromhex(altered_writes[0]["bytes"])
    value[0] ^= 1
    altered_writes[0]["bytes"] = value.hex()
    changed_memory = project_memory(trace, runtime, altered_writes)
    assert not (changed_memory["data_exact"] and changed_memory["stack_exact"])
    return {
        "variant": label,
        "input_sha256": sha(input_path),
        "branch_sha256": sha(branch_path),
        "owned_sha256": sha(owned_path),
        "post_sha256": sha(post_path),
        "shadow_sha256": sha(shadow_path),
        "ida_sha256": sha(ida_path),
        "ida_run_sha256": sha(ida_path.parent / "run.json"),
        "plugin_sha256": run["plugin_sha256"],
        "ida_executable_sha256": run["ida_sha256"],
        "qemu_executable_sha256": branch["qemu_executable_sha256"],
        "gdb_executable_sha256": branch["gdb_executable_sha256"],
        "gdb_version": branch["gdb_version"],
        "entered": ENTERED,
        "exact_gprs": counts["exact_gprs"],
        "exact_rip": counts["exact_rip"],
        "exact_raw_rflags": counts["exact_raw_rflags"],
        "exact_defined_flag_bits": counts["exact_defined_bits"],
        "boundary_bytes": DATA_LENGTH + STACK_LENGTH,
        "memory": memory,
        "mnemonics": comparisons["instruction_mnemonics"],
        "mutations_rejected": True,
    }, {
        "variant": label,
        "input_hex": input_path.read_bytes().hex(),
        "branch_hex": branch_path.read_bytes().hex(),
        "owned_hex": owned_path.read_bytes().hex(),
        "post_hex": post_path.read_bytes().hex(),
        "shadow_hex": shadow_path.read_bytes().hex(),
        "ida_hex": ida_path.read_bytes().hex(),
        "run_hex": (ida_path.parent / "run.json").read_bytes().hex(),
    }


def check_regression(ida_path, binary_sha256, plugin_sha256):
    report = read(ida_path)
    run_path = ida_path.parent / "run.json"
    run = read(run_path)
    capture = report["capture"]
    assert not report["errors"] and all(row["passed"] for row in report["checks"])
    assert report["inventory_before"] == report["inventory_after"]
    assert report["root_info"]["function_start"] == hex(OWNER)
    assert capture["available"] and capture["ran"]
    assert capture["function"] == capture["checkpoint_owner"] == hex(OWNER)
    assert capture["instruction_count"] == 26 and capture["stop_pc"] == hex(0x41D78D)
    assert not report["wrong_root"]["available"]
    assert not report["missing_budget"]["available"]
    assert run["runner_return_code"] == 0 and run["plugin_unchanged"]
    assert run["script_unchanged"] and run["artifacts_unchanged"]
    assert run["script_sha256"] == sha(Path(__file__).with_name("ida_native_owned_call_probe.py"))
    assert run["input_sha256"] == binary_sha256 and run["plugin_sha256"] == plugin_sha256
    return {
        "ida_sha256": sha(ida_path),
        "run_sha256": sha(run_path),
        "entered": 26,
        "wrong_root_rejected": True,
        "inventory_unchanged": True,
    }, {"ida_hex": ida_path.read_bytes().hex(), "run_hex": run_path.read_bytes().hex()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    for label in ("first", "second"):
        for kind in ("input", "branch", "owned", "post", "shadow", "ida"):
            parser.add_argument("--" + label + "-" + kind, type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--regression-ida", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    segments = elf64_load_segments(binary)
    results = [
        check_case(
            args.binary,
            segments,
            label,
            *[
                getattr(args, label + "_" + kind)
                for kind in ("input", "branch", "owned", "post", "shadow", "ida")
            ],
        )
        for label in ("first", "second")
    ]
    cases, captures = zip(*results)
    assert cases[0]["plugin_sha256"] == cases[1]["plugin_sha256"]
    assert cases[0]["ida_executable_sha256"] == cases[1]["ida_executable_sha256"]
    regression, regression_capture = check_regression(
        args.regression_ida, sha(args.binary), cases[0]["plugin_sha256"]
    )
    payload = {
        "schema": 1,
        "binary_sha256": sha(args.binary),
        "binary_hex": binary.hex(),
        "captures": captures,
        "regression": regression_capture,
    }
    archive = gzip.compress(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(), mtime=0
    )
    args.archive.parent.mkdir(parents=True, exist_ok=True)
    args.archive.write_bytes(archive)
    report = {
        "schema": 1,
        "binary_sha256": sha(args.binary),
        "plugin_sha256": cases[0]["plugin_sha256"],
        "ida_executable_sha256": cases[0]["ida_executable_sha256"],
        "capstone_version": capstone_version,
        "capstone_binding_sha256": sha(Path(capstone.__file__)),
        "capstone_library_sha256": sha(Path(capstone._cs._name)),
        "nested_gdb_source_file_binding": "owned capture __file__ resolves to the post-syscall wrapper; the owned script is pinned separately",
        "sources_sha256": {
            str(path.relative_to(ROOT)): sha(path)
            for path in [
                Path(__file__),
                Path(__file__).with_name("ida_native_post_syscall_probe.py"),
                Path(__file__).with_name("ida_native_owned_call_probe.py"),
                Path(__file__).with_name("morok_qemu_post_syscall.py"),
                Path(__file__).with_name("morok_qemu_owned_call_checkpoint.py"),
                Path(__file__).with_name("morok_qemu_packed_branch_continuation.py"),
                Path(__file__).with_name("verify_native_branch_continuation.py"),
                Path(__file__).with_name("verify_native_post_syscall_archive.py"),
            ]
        },
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "cases": cases,
        "regression": regression,
        "totals": {
            "entered": sum(case["entered"] for case in cases),
            "exact_gprs": sum(case["exact_gprs"] for case in cases),
            "exact_rip": sum(case["exact_rip"] for case in cases),
            "exact_defined_flag_bits": sum(case["exact_defined_flag_bits"] for case in cases),
            "boundary_bytes": sum(case["boundary_bytes"] for case in cases),
        },
        "passed": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("Morok post-syscall owned-tail verification: pass")


if __name__ == "__main__":
    main()
