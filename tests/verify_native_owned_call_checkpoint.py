"""Verify an observed owned Morok callee prefix against QEMU/GDB."""

import argparse
import copy
import hashlib
import json
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, __version__ as capstone_version

from verify_native_branch_continuation import (
    PRESERVE_EXTRA,
    compare_states,
    final_registers,
    head_checks,
    project_memory,
)
from verify_native_candidate_trace import elf64_load_segments, file_bytes

TARGET = 0x41D6C9
FRONTIER = 0x41D78D
ENTERED = 26
DATA_LENGTH = 4096
STACK_LENGTH = 1280
PRESERVE_EXTRA.add("movsxd")  # Sign extension preserves all six x86 status flags.


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def check_case(binary, segments, input_path, branch_path, observed_path, shadow_path, ida_path):
    branch, observed, ida = (read(path) for path in (branch_path, observed_path, ida_path))
    run = read(ida_path.parent / "run.json")
    trace = ida["capture"]
    assert not ida["errors"] and all(row["passed"] for row in ida["checks"])
    assert ida["inventory_before"] == ida["inventory_after"]
    assert not ida["wrong_root"]["available"] and not ida["missing_budget"]["available"]
    assert run["runner_return_code"] == 0 and run["plugin_unchanged"]
    assert run["script_unchanged"] and run["artifacts_unchanged"]
    assert run["script_sha256"] == sha(Path(__file__).with_name("ida_native_owned_call_probe.py"))
    assert run["input_sha256"] == observed["binary_sha256"] == sha(binary)
    assert observed["input_sha256"] == branch["input_sha256"] == sha(input_path)
    assert observed["binary_sha256"] == branch["binary_sha256"]
    assert observed["source_sha256"] == sha(
        Path(__file__).with_name("morok_qemu_owned_call_checkpoint.py")
    )
    assert branch["capture_source_sha256"] == sha(
        Path(__file__).with_name("morok_qemu_packed_branch_continuation.py")
    )
    assert observed["branch_capture_sha256"] == sha(branch_path)
    assert observed["entry_registers"] == branch["boundary_registers"]
    assert observed["shadow_sha256"] == sha(shadow_path)
    assert observed["shadow_start"] == hex(TARGET)
    assert shadow_path.read_bytes() == file_bytes(binary.read_bytes(), segments, TARGET, 256)
    assert observed["stack_below"] == 1024 and observed["stack_above"] == 256
    assert observed["data_start"] == hex(0x444000)
    assert len(bytes.fromhex(observed["entry_data_hex"])) == DATA_LENGTH
    assert len(bytes.fromhex(observed["entry_stack_hex"])) == STACK_LENGTH
    assert len(observed["entries"]) == 28
    assert observed["entries"][ENTERED]["registers"] == observed["replay_stop_registers"]
    assert observed["replay_stop_registers"]["rip"] == hex(FRONTIER)
    assert trace["available"] and trace["ran"] and trace["observed_function_checkpoint"]
    assert trace["entry_state_replay"] and trace["runtime_shadow"] and trace["runtime_data"]
    assert trace["native_state_capture_complete"] and trace["data_trace_complete"]
    assert trace["instruction_count"] == len(trace["execution"]) == ENTERED
    assert trace["planned_heads"] == ENTERED and trace["instruction_budget"] == 128
    assert trace["stop"] == "native-region-boundary" and trace["stop_pc"] == hex(FRONTIER)
    assert trace["boundary_source"] == hex(0x41D78A)
    assert trace["boundary_target"] == hex(FRONTIER)
    assert trace["function"] == trace["shadow_start"] == hex(TARGET)
    assert trace["shadow_bytes"] == 256 and trace["data_bytes"] == DATA_LENGTH
    assert trace["entry_stack_below_bytes"] == 1024
    assert trace["entry_stack_bytes"] == 256
    assert trace["observed_entry_sp"] == observed["entry_registers"]["rsp"]
    assert int(trace["entry_sp"], 16) & 0xFFF == int(observed["entry_registers"]["rsp"], 16) & 0xFFF
    assert not trace["function_evidence_published"] and not trace["vm_identity_proved"]
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    heads, mismatched_heads = head_checks(trace, binary.read_bytes(), segments, b"", decoder)
    assert len(heads) == ENTERED and not mismatched_heads
    runtime = dict(
        observed,
        compare_registers=observed["entry_registers"],
        boundary_registers=observed["replay_stop_registers"],
        compare_data_hex=observed["entry_data_hex"],
        boundary_data_hex=observed["replay_stop_data_hex"],
        compare_stack_hex=observed["entry_stack_hex"],
        boundary_stack_hex=observed["replay_stop_stack_hex"],
    )
    comparisons = compare_states(trace, runtime, heads, decoder)
    counts = comparisons["counts"]
    assert not comparisons["first_scalar_mismatches"]
    assert counts["exact_gprs"] == ENTERED * 16
    assert counts["exact_rip"] == counts["exact_raw_rflags"] == ENTERED
    assert counts["exact_defined_bits"] == counts["defined_bits"] == ENTERED * 6
    final = final_registers(trace, runtime)
    assert not final["gpr_mismatches"] and final["rip_exact"] and final["rflags_exact"]
    memory = project_memory(trace, runtime, trace["final_writes"])
    assert memory["data_exact"] and memory["stack_exact"]
    altered = copy.deepcopy(runtime)
    altered["entries"][0]["registers"]["rax"] = "0x0"
    assert compare_states(trace, altered, heads, decoder)["first_scalar_mismatches"]
    altered_writes = copy.deepcopy(trace["final_writes"])
    changed = bytearray.fromhex(altered_writes[0]["bytes"])
    changed[0] ^= 1
    altered_writes[0]["bytes"] = changed.hex()
    altered_memory = project_memory(trace, runtime, altered_writes)
    assert not (altered_memory["data_exact"] and altered_memory["stack_exact"])
    altered_trace = copy.deepcopy(trace)
    altered_trace["heads"][0]["bytes"] = "90"
    assert head_checks(altered_trace, binary.read_bytes(), segments, b"", decoder)[1]
    return {
        "input_sha256": sha(input_path),
        "branch_capture_sha256": sha(branch_path),
        "runtime_report_sha256": sha(observed_path),
        "shadow_sha256": sha(shadow_path),
        "ida_report_sha256": sha(ida_path),
        "ida_run_sha256": sha(ida_path.parent / "run.json"),
        "entered_instructions": ENTERED,
        "exact_gprs": counts["exact_gprs"],
        "exact_rip": counts["exact_rip"],
        "exact_rflags": counts["exact_raw_rflags"],
        "exact_defined_flag_bits": counts["exact_defined_bits"],
        "exact_boundary_data_bytes": DATA_LENGTH,
        "exact_boundary_stack_bytes": STACK_LENGTH,
        "memory": memory,
        "plugin_sha256": run["plugin_sha256"],
        "ida_sha256": run["ida_sha256"],
        "instruction_mnemonics": comparisons["instruction_mnemonics"],
        "mutations_rejected": True,
        "database_inventory_unchanged": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "binary",
        "first_input",
        "second_input",
        "first_branch",
        "second_branch",
        "first_runtime",
        "second_runtime",
        "first_shadow",
        "second_shadow",
        "first_ida",
        "second_ida",
        "output",
    ):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    segments = elf64_load_segments(binary)
    cases = [
        check_case(
            args.binary,
            segments,
            getattr(args, label + "_input"),
            getattr(args, label + "_branch"),
            getattr(args, label + "_runtime"),
            getattr(args, label + "_shadow"),
            getattr(args, label + "_ida"),
        )
        for label in ("first", "second")
    ]
    assert cases[0]["plugin_sha256"] == cases[1]["plugin_sha256"]
    assert cases[0]["ida_sha256"] == cases[1]["ida_sha256"]
    result = {
        "schema": 1,
        "binary_sha256": sha(args.binary),
        "capture_source_sha256": sha(
            Path(__file__).with_name("morok_qemu_owned_call_checkpoint.py")
        ),
        "ida_probe_source_sha256": sha(Path(__file__).with_name("ida_native_owned_call_probe.py")),
        "verifier_source_sha256": sha(Path(__file__)),
        "dependency_sources_sha256": {
            name: sha(Path(__file__).with_name(name))
            for name in (
                "verify_native_branch_continuation.py",
                "verify_native_candidate_trace.py",
                "verify_native_shadow_boundary_memory.py",
                "verify_native_shadow_defined_flags.py",
                "verify_native_shadow_states.py",
            )
        },
        "capstone_version": capstone_version,
        "cases": cases,
        "total_entered_instructions": sum(case["entered_instructions"] for case in cases),
        "total_exact_gprs": sum(case["exact_gprs"] for case in cases),
        "total_exact_defined_flag_bits": sum(case["exact_defined_flag_bits"] for case in cases),
        "total_exact_boundary_bytes": sum(
            case["exact_boundary_data_bytes"] + case["exact_boundary_stack_bytes"] for case in cases
        ),
        "passed": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Morok owned call checkpoint verification: pass")


if __name__ == "__main__":
    main()
