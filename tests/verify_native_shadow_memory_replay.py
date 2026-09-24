"""Verify observed-memory replay against protected QEMU entry and boundary reports."""

import argparse
import copy
import hashlib
import json
from pathlib import Path

from verify_native_shadow_boundary_memory import (
    DATA_LENGTH,
    DATA_START,
    STACK_ABOVE,
    STACK_BELOW,
    final_register_comparison,
    memory_projection,
    translate,
)
from verify_native_shadow_states import REGISTER_NAMES, align, register_values

BOUNDARY = 0x40C89B


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_run(ida_path, runtime_path, boundary_path, binary_hash, input_hash, shadow_hash):
    ida = json.loads(ida_path.read_text())
    trace = ida["capture"]
    runtime = json.loads(runtime_path.read_text())
    boundary = json.loads(boundary_path.read_text())
    assert not ida["errors"] and all(row["passed"] for row in ida["checks"])
    assert ida["inventory_before"] == ida["inventory_after"]
    assert boundary["binary_sha256"] == runtime["binary_sha256"] == binary_hash
    assert boundary["input_sha256"] == runtime["input_sha256"] == input_hash
    assert boundary["entry_packed_65536_sha256"] == shadow_hash
    assert runtime["entry_packed_65536_sha256"] == shadow_hash
    assert ida["shadow_sha256"] == shadow_hash
    assert ida["boundary_report_sha256"] == sha(boundary_path)
    assert trace["available"] and trace["ran"] and trace["entry_state_replay"]
    assert trace["runtime_shadow"] and trace["runtime_data"]
    assert trace["shadow_instruction_states"] and trace["native_state_capture_complete"]
    assert trace["stop"] == "instruction-budget" and trace["stop_pc"] == hex(BOUNDARY)
    assert trace["instruction_count"] == 4096 and trace["plan_truncated"]
    assert trace["final_registers_complete"] and trace["data_trace_complete"]
    assert not trace["data_trace_truncated"] and not trace["region_code_changed"]
    assert not trace["function_evidence_published"] and not trace["vm_identity_proved"]
    assert trace["data_start"] == boundary["data_start"] == hex(DATA_START)
    assert trace["data_bytes"] == boundary["data_length"] == DATA_LENGTH
    assert trace["data_newly_loaded_bytes"] == 128
    assert trace["entry_stack_below_bytes"] == boundary["stack_below"] == STACK_BELOW
    assert trace["entry_stack_bytes"] == boundary["stack_above"] == STACK_ABOVE
    assert (
        ida["request_summary"]["data_sha256"]
        == hashlib.sha256(bytes.fromhex(boundary["entry_data_hex"])).hexdigest()
    )
    assert (
        ida["request_summary"]["below_sha256"]
        == hashlib.sha256(bytes.fromhex(boundary["entry_stack_hex"][: STACK_BELOW * 2])).hexdigest()
    )
    assert (
        ida["request_summary"]["above_sha256"]
        == hashlib.sha256(bytes.fromhex(boundary["entry_stack_hex"][STACK_BELOW * 2 :])).hexdigest()
    )
    assert ida["data_mutation"]["offset"] == 0x684
    assert ida["data_mutation"]["first_read_value"] == "0x1"
    assert ida["data_mutation"]["stop_pc"] != trace["stop_pc"]
    original_read = next(
        row
        for row in trace["data"]
        if row["kind"] == "read" and row["address"] == hex(DATA_START + 0x684)
    )
    assert original_read["value"] == "0x0"
    assert len(boundary["reported_path"]) == 4094
    assert boundary["reported_path"] == [
        {"pc": row["pc"], "bytes_16_hex": row["bytes_16_hex"]} for row in runtime["entries"][:4094]
    ]
    assert runtime["entries"][4094]["pc"] == hex(BOUNDARY)
    assert boundary["entry_registers"]["eflags"] == runtime["entry_registers"]["eflags"]
    heads = {int(row["site"], 16): row for row in trace["heads"]}
    mapping, skipped, complete = align(
        trace["execution"], runtime["entries"], heads, trace["stop_pc"]
    )
    assert complete and len(mapping) == 4094
    assert skipped == ["0x40d63f", "0x40c1a2"]
    states = {
        row["sequence"]: register_values(row)
        for row in trace["states"]
        if row["kind"] == "native instruction entry"
    }
    assert len(states) == len(trace["execution"]) == 4096
    synthetic_sp = int(trace["entry_sp"], 16)
    observed_sp = int(boundary["entry_registers"]["rsp"], 16)
    assert (synthetic_sp & 0xFFF) == (observed_sp & 0xFFF)
    assert trace["observed_entry_sp"] == boundary["entry_registers"]["rsp"]
    entry_state = states[trace["execution"][0]["sequence"]]
    assert entry_state[18] == int(boundary["entry_registers"]["eflags"], 16)
    for index, name in enumerate(REGISTER_NAMES):
        value, _ = translate(entry_state[256 + index], synthetic_sp, observed_sp)
        assert value == int(boundary["entry_registers"][name], 16)
        earlier = int(runtime["entry_registers"][name], 16)
        if index in (4, 5, 13):
            assert value - observed_sp == earlier - int(runtime["entry_registers"]["rsp"], 16)
        else:
            assert value == earlier
    exact_gpr = 0
    exact_flags = 0
    for candidate_index, runtime_index in mapping.items():
        visit = trace["execution"][candidate_index]
        state = states[visit["sequence"]]
        observed = runtime["entries"][runtime_index]["registers"]
        assert state[16] == int(observed["rip"], 16)
        for index, name in enumerate(REGISTER_NAMES):
            value, _ = translate(
                state[256 + index], synthetic_sp, int(runtime["entry_registers"]["rsp"], 16)
            )
            exact_gpr += value == int(observed[name], 16)
        exact_flags += state[18] == int(observed["eflags"], 16)
    assert exact_gpr == 4094 * 16
    assert exact_flags == 3401
    registers = final_register_comparison(trace, boundary)
    assert registers["gpr_exact"] == 16 and registers["rip_exact"] and registers["rflags_exact"]
    projection = memory_projection(trace, boundary, trace["final_writes"])
    assert projection["data_exact"] and projection["stack_exact"]
    assert projection["candidate_written_bytes"] == 142
    assert projection["translated_stack_pointer_words"] == 3
    assert projection["observed_data_changed_bytes"] == 50
    assert projection["observed_stack_changed_bytes"] == 41
    assert len(trace["final_writes"]) == 7
    modified = copy.deepcopy(trace["final_writes"])
    changed = bytearray.fromhex(modified[0]["bytes"])
    changed[0] ^= 1
    modified[0]["bytes"] = changed.hex()
    assert not memory_projection(trace, boundary, modified)["data_exact"]
    changed_boundary = copy.deepcopy(boundary)
    changed_boundary["boundary_registers"]["rax"] = hex(
        int(changed_boundary["boundary_registers"]["rax"], 16) ^ 1
    )
    assert final_register_comparison(trace, changed_boundary)["gpr_exact"] == 15
    return {
        "ida_sha256": sha(ida_path),
        "runtime_sha256": sha(runtime_path),
        "boundary_sha256": sha(boundary_path),
        "candidate_entry_sp_page_offset": hex(synthetic_sp & 0xFFF),
        "observed_entry_sp_page_offset": hex(observed_sp & 0xFFF),
        "aligned_entries": len(mapping),
        "omitted_gdb_entry_sites": skipped,
        "exact_intermediate_gprs": exact_gpr,
        "intermediate_gpr_comparisons": len(mapping) * 16,
        "exact_intermediate_rflags": exact_flags,
        "intermediate_rflags_comparisons": len(mapping),
        "exact_boundary_registers": 18,
        "exact_boundary_window_bytes": DATA_LENGTH + STACK_BELOW + STACK_ABOVE,
        "data_changed_from_ida_snapshot": trace["data_changed_bytes"],
        "newly_loaded_data_bytes": trace["data_newly_loaded_bytes"],
        "first_read_data_mutation_observed": True,
        "data_mutation_changes_path": True,
        "final_write_mutation_rejected": True,
        "boundary_register_mutation_rejected": True,
        "database_inventory_unchanged": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "binary",
        "second_binary",
        "input",
        "shadow",
        "second_shadow",
        "first_ida",
        "second_ida",
        "first_runtime",
        "second_runtime",
        "first_boundary",
        "second_boundary",
        "output",
    ):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args()
    assert args.binary.read_bytes() == args.second_binary.read_bytes()
    assert args.shadow.read_bytes() == args.second_shadow.read_bytes()
    binary_hash, input_hash, shadow_hash = sha(args.binary), sha(args.input), sha(args.shadow)
    runs = [
        verify_run(
            getattr(args, label + "_ida"),
            getattr(args, label + "_runtime"),
            getattr(args, label + "_boundary"),
            binary_hash,
            input_hash,
            shadow_hash,
        )
        for label in ("first", "second")
    ]
    boundaries = [
        json.loads(getattr(args, label + "_boundary").read_text()) for label in ("first", "second")
    ]
    assert boundaries[0]["entry_data_hex"] == boundaries[1]["entry_data_hex"]
    assert boundaries[0]["boundary_data_hex"] == boundaries[1]["boundary_data_hex"]
    report = {
        "schema": 1,
        "source_sha256": sha(Path(__file__)),
        "binary_sha256": binary_hash,
        "input_sha256": input_hash,
        "shadow_sha256": shadow_hash,
        "runs": runs,
        "total_exact_intermediate_gprs": 2 * 4094 * 16,
        "total_exact_intermediate_rflags": 2 * 3401,
        "total_exact_boundary_registers": 2 * 18,
        "total_exact_boundary_window_bytes": 2 * (DATA_LENGTH + STACK_BELOW + STACK_ABOVE),
        "scope": "two observed entry windows replayed through one protected 4096-instruction boundary",
        "not_established": [
            "intermediate RFLAGS equivalence at 693 aligned entries per run",
            "intermediate memory equivalence outside recorded entry and final windows",
            "behavior beyond the instruction boundary or on other inputs",
            "logical VM state identity or ordinary function evidence",
        ],
        "passed": True,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": True, "runs": runs}, indent=2))


if __name__ == "__main__":
    main()
