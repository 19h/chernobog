"""Verify protected Morok boundary registers and selected memory effects."""

import argparse
import copy
import hashlib
import json
import struct
from pathlib import Path

from verify_native_candidate_trace import elf64_load_segments
from verify_native_shadow_states import REGISTER_NAMES, align

DATA_START = 0x444000
DATA_LENGTH = 0x6A0
STACK_BELOW = 1024
STACK_ABOVE = 128
BOUNDARY = 0x40C89B
MASK64 = (1 << 64) - 1


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def translate(value, synthetic_sp, observed_sp):
    offset = value - synthetic_sp
    if -0x8000 <= offset <= 0x8000:
        return (observed_sp + offset) & MASK64, True
    return value, False


def final_register_comparison(trace, boundary):
    observed_sp = int(boundary["entry_registers"]["rsp"], 16)
    synthetic_sp = int(trace["entry_sp"], 16)
    final = {}
    for row in trace["final_registers"]:
        register = int(row["reg"])
        assert register not in final and int(row["width"]) == 8
        final[register] = int(row["value"], 16)
    assert set(final) == {16, 18} | set(range(256, 272))
    mismatches = {}
    for index, name in enumerate(REGISTER_NAMES):
        value, _ = translate(final[256 + index], synthetic_sp, observed_sp)
        actual = int(boundary["boundary_registers"][name], 16)
        if value != actual:
            mismatches[name] = {"candidate": hex(value), "runtime": hex(actual)}
    return {
        "gpr_mismatches": mismatches,
        "gpr_exact": 16 - len(mismatches),
        "rip_exact": final[16] == int(boundary["boundary_registers"]["rip"], 16),
        "rflags_exact": final[18] == int(boundary["boundary_registers"]["eflags"], 16),
    }


def memory_projection(trace, boundary, writes, translate_stack_pointers=True):
    observed_sp = int(boundary["entry_registers"]["rsp"], 16)
    synthetic_sp = int(trace["entry_sp"], 16)
    entry_data = bytes.fromhex(boundary["entry_data_hex"])
    final_data = bytes.fromhex(boundary["boundary_data_hex"])
    entry_stack = bytes.fromhex(boundary["entry_stack_hex"])
    final_stack = bytes.fromhex(boundary["boundary_stack_hex"])
    assert len(entry_data) == len(final_data) == DATA_LENGTH
    assert len(entry_stack) == len(final_stack) == STACK_BELOW + STACK_ABOVE
    projected_data = bytearray(entry_data)
    projected_stack = bytearray(entry_stack)
    covered = set()
    translated_words = 0
    for row in writes:
        address = int(row["address"], 16)
        value = bytearray.fromhex(row["bytes"])
        assert value and len(value) <= 65536
        cells = set(range(address, address + len(value)))
        assert not covered.intersection(cells)
        covered.update(cells)
        if DATA_START <= address and address + len(value) <= DATA_START + DATA_LENGTH:
            start = address - DATA_START
            projected_data[start : start + len(value)] = value
        else:
            start = address - synthetic_sp + STACK_BELOW
            assert 0 <= start and start + len(value) <= len(projected_stack)
            assert address % 8 == 0 and len(value) % 8 == 0
            for offset in range(0, len(value), 8):
                word = struct.unpack_from("<Q", value, offset)[0]
                if translate_stack_pointers:
                    translated, is_pointer = translate(word, synthetic_sp, observed_sp)
                    translated_words += is_pointer
                    struct.pack_into("<Q", value, offset, translated)
            projected_stack[start : start + len(value)] = value
    return {
        "data_exact": projected_data == final_data,
        "stack_exact": projected_stack == final_stack,
        "data_first_mismatch": next(
            (
                index
                for index, (left, right) in enumerate(zip(projected_data, final_data))
                if left != right
            ),
            None,
        ),
        "stack_first_mismatch": next(
            (
                index
                for index, (left, right) in enumerate(zip(projected_stack, final_stack))
                if left != right
            ),
            None,
        ),
        "candidate_written_bytes": len(covered),
        "translated_stack_pointer_words": translated_words,
        "observed_data_changed_bytes": sum(a != b for a, b in zip(entry_data, final_data)),
        "observed_stack_changed_bytes": sum(a != b for a, b in zip(entry_stack, final_stack)),
        "covered_addresses": covered,
    }


def verify_run(
    ida_path, previous_path, runtime_path, boundary_path, binary, input_hash, shadow_hash
):
    ida = json.loads(ida_path.read_text())
    previous = json.loads(previous_path.read_text())
    runtime = json.loads(runtime_path.read_text())
    boundary = json.loads(boundary_path.read_text())
    trace = ida["capture"]
    assert not ida["errors"] and all(item["passed"] for item in ida["checks"])
    assert ida["inventory_before"] == ida["inventory_after"]
    assert trace["available"] and trace["ran"] and trace["entry_state_replay"]
    assert trace["stop"] == "instruction-budget" and trace["stop_pc"] == hex(BOUNDARY)
    assert trace["instruction_count"] == 4096 and trace["final_registers_complete"]
    assert trace["data_trace_complete"] and not trace["data_trace_truncated"]
    assert trace["plan_truncated"] and not trace["region_code_changed"]
    assert trace["heads"] == previous["shadow"]["heads"]
    assert trace["execution"] == previous["shadow"]["execution"]
    assert trace["edges"] == previous["shadow"]["edges"]
    assert BOUNDARY not in {int(row["site"], 16) for row in trace["execution"]}
    assert (
        boundary["binary_sha256"] == runtime["binary_sha256"] == hashlib.sha256(binary).hexdigest()
    )
    assert boundary["input_sha256"] == runtime["input_sha256"] == input_hash
    assert (
        boundary["entry_packed_65536_sha256"] == runtime["entry_packed_65536_sha256"] == shadow_hash
    )
    assert boundary["data_start"] == hex(DATA_START) and boundary["data_length"] == DATA_LENGTH
    assert boundary["stack_below"] == STACK_BELOW and boundary["stack_above"] == STACK_ABOVE
    assert boundary["stack_base_observed"] == hex(
        int(boundary["entry_registers"]["rsp"], 16) - STACK_BELOW
    )
    data_segments = [
        (address, file_offset, file_size)
        for address, file_offset, file_size in elf64_load_segments(binary)
        if address <= DATA_START < address + file_size
    ]
    assert len(data_segments) == 1
    segment_address, file_offset, file_size = data_segments[0]
    file_backed = min(DATA_LENGTH, segment_address + file_size - DATA_START)
    file_start = file_offset + DATA_START - segment_address
    entry_data = bytes.fromhex(boundary["entry_data_hex"])
    initial_data_file_mismatches = sum(
        left != right
        for left, right in zip(
            entry_data[:file_backed], binary[file_start : file_start + file_backed]
        )
    )
    initial_unbacked_nonzero = sum(value != 0 for value in entry_data[file_backed:])
    assert len(boundary["reported_path"]) == 4094
    assert boundary["reported_path"] == [
        {"pc": row["pc"], "bytes_16_hex": row["bytes_16_hex"]} for row in runtime["entries"][:4094]
    ]
    assert runtime["entries"][4094]["pc"] == hex(BOUNDARY)
    for index, name in enumerate(REGISTER_NAMES):
        entry_value = int(boundary["entry_registers"][name], 16)
        earlier_value = int(runtime["entry_registers"][name], 16)
        if index in (4, 5, 13):
            assert entry_value - int(boundary["entry_registers"]["rsp"], 16) == (
                earlier_value - int(runtime["entry_registers"]["rsp"], 16)
            )
        else:
            assert entry_value == earlier_value
    assert boundary["entry_registers"]["eflags"] == runtime["entry_registers"]["eflags"]
    heads = {int(row["site"], 16): row for row in trace["heads"]}
    mapping, skipped, complete = align(
        trace["execution"], runtime["entries"], heads, trace["stop_pc"]
    )
    assert complete and len(mapping) == 4094 and skipped == ["0x40d63f", "0x40c1a2"]
    observed_sp = int(boundary["entry_registers"]["rsp"], 16)
    registers = final_register_comparison(trace, boundary)
    projected = memory_projection(trace, boundary, trace["final_writes"])
    event_bytes = set()
    write_events = 0
    for row in trace["data"]:
        if row["kind"] != "write":
            continue
        address = int(row["address"], 16)
        size = int(row["size"])
        assert 1 <= size <= 8
        event_bytes.update(range(address, address + size))
        write_events += 1
    assert projected["covered_addresses"] == event_bytes
    assert len(trace["final_writes"]) == 7 and write_events == 68
    assert projected["candidate_written_bytes"] == 142
    assert projected["translated_stack_pointer_words"] == 3
    assert projected["observed_data_changed_bytes"] == 50
    assert projected["observed_stack_changed_bytes"] == 41
    assert file_backed == 1568 and initial_data_file_mismatches == 608
    assert initial_unbacked_nonzero == 15
    assert registers["gpr_exact"] == 16 and registers["rip_exact"] and registers["rflags_exact"]
    assert projected["data_exact"] and projected["stack_exact"]
    changed = copy.deepcopy(trace["final_writes"])
    changed[0]["bytes"] = (
        hex(int(changed[0]["bytes"][:2], 16) ^ 1)[2:].zfill(2) + changed[0]["bytes"][2:]
    )
    mutation_rejected = not memory_projection(trace, boundary, changed)["data_exact"]
    removal_rejected = not memory_projection(trace, boundary, trace["final_writes"][1:])[
        "data_exact"
    ]
    changed_boundary = copy.deepcopy(boundary)
    changed_boundary["boundary_registers"]["rax"] = hex(
        int(changed_boundary["boundary_registers"]["rax"], 16) ^ 1
    )
    register_mutation_rejected = (
        final_register_comparison(trace, changed_boundary)["gpr_exact"] == 15
    )
    untranslated_rejected = not memory_projection(trace, boundary, trace["final_writes"], False)[
        "stack_exact"
    ]
    assert mutation_rejected and removal_rejected and register_mutation_rejected
    assert untranslated_rejected
    del projected["covered_addresses"]
    return {
        "ida_sha256": digest(ida_path),
        "runtime_sha256": digest(runtime_path),
        "boundary_sha256": digest(boundary_path),
        "gdb_reported_entries_to_boundary": len(boundary["reported_path"]),
        "gdb_omitted_sites": skipped,
        "boundary_registers": registers,
        "observed_entry_sp_page_offset": hex(observed_sp & 0xFFF),
        "candidate_entry_sp_page_offset": hex(int(trace["entry_sp"], 16) & 0xFFF),
        "memory": projected,
        "initial_data_file_mismatches": initial_data_file_mismatches,
        "file_backed_data_window_bytes": file_backed,
        "initial_unbacked_nonzero_bytes": initial_unbacked_nonzero,
        "write_events": write_events,
        "final_write_ranges": len(trace["final_writes"]),
        "data_window_bytes": DATA_LENGTH,
        "stack_window_bytes": STACK_BELOW + STACK_ABOVE,
        "final_byte_mutation_rejected": mutation_rejected,
        "missing_write_rejected": removal_rejected,
        "boundary_gpr_mutation_rejected": register_mutation_rejected,
        "missing_stack_translation_rejected": untranslated_rejected,
        "gdb_step_loop_elapsed_ns": boundary["elapsed_ns"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "binary",
        "second_binary",
        "input",
        "shadow",
        "second_shadow",
        "old_first_ida",
        "old_second_ida",
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
    binary = args.binary.read_bytes()
    input_hash = digest(args.input)
    shadow_hash = digest(args.shadow)
    assert binary == args.second_binary.read_bytes()
    assert args.shadow.read_bytes() == args.second_shadow.read_bytes()
    runs = [
        verify_run(
            getattr(args, label + "_ida"),
            getattr(args, "old_" + label + "_ida"),
            getattr(args, label + "_runtime"),
            getattr(args, label + "_boundary"),
            binary,
            input_hash,
            shadow_hash,
        )
        for label in ("first", "second")
    ]
    boundary_reports = [
        json.loads(getattr(args, label + "_boundary").read_text()) for label in ("first", "second")
    ]
    assert boundary_reports[0]["entry_data_hex"] == boundary_reports[1]["entry_data_hex"]
    assert boundary_reports[0]["boundary_data_hex"] == boundary_reports[1]["boundary_data_hex"]
    report = {
        "schema": 1,
        "binary_sha256": digest(args.binary),
        "input_sha256": input_hash,
        "shadow_sha256": shadow_hash,
        "runs": runs,
        "total_exact_boundary_scalar_registers": 2 * 18,
        "total_exact_reconstructed_window_bytes": 2 * (DATA_LENGTH + STACK_BELOW + STACK_ABOVE),
        "scope": "observed entry windows plus candidate final writes, compared at one protected boundary",
        "not_established": [
            "candidate execution from all observed initial memory",
            "writes outside the captured data and stack windows",
            "full planned region or other inputs",
            "VM state identity or ordinary function evidence",
        ],
        "passed": True,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("[chernobog][boundary-memory] PASS")


if __name__ == "__main__":
    main()
