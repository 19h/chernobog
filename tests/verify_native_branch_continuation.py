"""Verify Morok branch continuation against same-process QEMU states."""

import argparse
import copy
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, __version__ as capstone_version

from verify_native_candidate_trace import elf64_load_segments, file_bytes
from verify_native_shadow_boundary_memory import translate
from verify_native_shadow_defined_flags import (
    AF,
    CF,
    OF,
    PF,
    SF,
    STATUS_MASK,
    ZF,
    next_defined_mask,
)
from verify_native_shadow_states import REGISTER_NAMES, register_values

ROOT = 0x430000
COMPARE = 0x430315
BOUNDARY = 0x41D6C9
DATA_START = 0x444000
DATA_LENGTH = 4096
STACK_BELOW = 1024
STACK_ABOVE = 256
MAX_BUDGET = 4096
PRESERVE_EXTRA = {
    "movdqa",
    "movups",
    "movq",
    "pxor",
    "punpcklqdq",
    "cmova",
    "js",
    "jns",
    "jle",
    "cdqe",
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def mapped_bytes(binary, segments, suffix, address, size):
    if COMPARE <= address and address + size <= ROOT + 65536:
        offset = address - COMPARE
        return suffix[offset : offset + size]
    if address < ROOT + 65536 and address + size > COMPARE:
        return None
    return file_bytes(binary, segments, address, size)


def head_checks(trace, binary, segments, suffix, decoder):
    mismatches = []
    heads = {}
    for row in trace["heads"]:
        address = int(row["site"], 16)
        encoded = bytes.fromhex(row["bytes"])
        instruction = next(decoder.disasm(encoded, address, count=1), None)
        if (
            address in heads
            or encoded != mapped_bytes(binary, segments, suffix, address, len(encoded))
            or len(encoded) != int(row["size"])
            or instruction is None
            or instruction.size != len(encoded)
        ):
            mismatches.append(hex(address))
        heads[address] = row
    return heads, mismatches


def next_mask(mask, instruction):
    mnemonic = instruction.mnemonic
    if mnemonic == "inc":
        return (mask & CF) | (STATUS_MASK & ~CF)
    if mnemonic == "or":
        return STATUS_MASK & ~AF
    if mnemonic in PRESERVE_EXTRA:
        return mask
    return next_defined_mask(mask, instruction)


def states_by_execution(trace):
    sequence = {row["sequence"]: index for index, row in enumerate(trace["execution"])}
    assert len(sequence) == len(trace["execution"])
    states = {}
    for row in trace["states"]:
        if row["kind"] != "native instruction entry":
            continue
        index = sequence[row["sequence"]]
        assert index not in states and row["site"] == trace["execution"][index]["site"]
        states[index] = register_values(row)
    assert set(states) == set(range(len(trace["execution"])))
    return states


def compare_states(trace, runtime, heads, decoder):
    states = states_by_execution(trace)
    sp = int(runtime["compare_registers"]["rsp"], 16)
    synthetic_sp = int(trace["entry_sp"], 16)
    defined_mask = STATUS_MASK
    counts = Counter()
    mnemonics = Counter()
    mismatches = []
    for index, (visit, observed) in enumerate(zip(trace["execution"], runtime["entries"])):
        address = int(visit["site"], 16)
        encoded = bytes.fromhex(heads[address]["bytes"])
        actual = bytes.fromhex(observed["bytes_16_hex"])
        assert address == int(observed["pc"], 16)
        assert encoded == actual[: len(encoded)]
        instruction = next(decoder.disasm(encoded, address, count=1), None)
        assert instruction is not None and instruction.size == len(encoded)
        mnemonics[instruction.mnemonic] += 1
        if instruction.mnemonic in {"je", "jne"}:
            assert defined_mask & ZF
        elif instruction.mnemonic == "jle":
            assert defined_mask & (ZF | SF | OF) == ZF | SF | OF
        elif instruction.mnemonic in {"js", "jns"}:
            assert defined_mask & SF
        elif instruction.mnemonic == "cmova":
            assert defined_mask & (CF | ZF) == CF | ZF
        candidate = states[index]
        if candidate[16] != address:
            mismatches.append((index, "rip", hex(candidate[16]), hex(address)))
        else:
            counts["exact_rip"] += 1
        for reg, name in enumerate(REGISTER_NAMES):
            value, _ = translate(candidate[256 + reg], synthetic_sp, sp)
            actual_value = int(observed["registers"][name], 16)
            if value != actual_value:
                mismatches.append((index, name, hex(value), hex(actual_value)))
            else:
                counts["exact_gprs"] += 1
        difference = candidate[18] ^ int(observed["registers"]["eflags"], 16)
        assert not difference & ~STATUS_MASK
        counts["exact_raw_rflags"] += difference == 0
        counts["exact_defined_states"] += (difference & defined_mask) == 0
        counts["defined_bits"] += defined_mask.bit_count()
        counts["exact_defined_bits"] += (
            defined_mask.bit_count() - (difference & defined_mask).bit_count()
        )
        counts["undefined_differing_bits"] += (difference & STATUS_MASK & ~defined_mask).bit_count()
        defined_mask = next_mask(defined_mask, instruction)
    return {
        "counts": dict(counts),
        "first_scalar_mismatches": mismatches[:8],
        "instruction_mnemonics": dict(sorted(mnemonics.items())),
        "boundary_defined_flag_mask": hex(defined_mask),
    }


def final_registers(trace, runtime):
    final = {int(row["reg"]): int(row["value"], 16) for row in trace["final_registers"]}
    assert len(final) == len(trace["final_registers"]) == 18
    assert set(final) == {16, 18} | set(range(256, 272))
    sp = int(runtime["compare_registers"]["rsp"], 16)
    synthetic_sp = int(trace["entry_sp"], 16)
    mismatches = {}
    for index, name in enumerate(REGISTER_NAMES):
        value, _ = translate(final[256 + index], synthetic_sp, sp)
        actual = int(runtime["boundary_registers"][name], 16)
        if value != actual:
            mismatches[name] = (hex(value), hex(actual))
    return {
        "gpr_mismatches": mismatches,
        "rip_exact": final[16] == int(runtime["boundary_registers"]["rip"], 16),
        "rflags_exact": final[18] == int(runtime["boundary_registers"]["eflags"], 16),
    }


def project_memory(trace, runtime, writes):
    entry_data = bytes.fromhex(runtime["compare_data_hex"])
    boundary_data = bytes.fromhex(runtime["boundary_data_hex"])
    entry_stack = bytes.fromhex(runtime["compare_stack_hex"])
    boundary_stack = bytes.fromhex(runtime["boundary_stack_hex"])
    assert len(entry_data) == len(boundary_data) == DATA_LENGTH
    assert len(entry_stack) == len(boundary_stack) == STACK_BELOW + STACK_ABOVE
    data = bytearray(entry_data)
    stack = bytearray(entry_stack)
    synthetic_sp = int(trace["entry_sp"], 16)
    observed_sp = int(runtime["compare_registers"]["rsp"], 16)
    covered = set()
    translated_words = 0
    for row in writes:
        address = int(row["address"], 16)
        value = bytearray.fromhex(row["bytes"])
        cells = set(range(address, address + len(value)))
        assert value and not covered.intersection(cells)
        covered.update(cells)
        if DATA_START <= address and address + len(value) <= DATA_START + DATA_LENGTH:
            offset = address - DATA_START
            data[offset : offset + len(value)] = value
        else:
            offset = address - synthetic_sp + STACK_BELOW
            assert 0 <= offset and offset + len(value) <= len(stack)
            if address % 8 == 0:
                for part in range(0, len(value) - 7, 8):
                    word = struct.unpack_from("<Q", value, part)[0]
                    translated, is_pointer = translate(word, synthetic_sp, observed_sp)
                    if is_pointer:
                        struct.pack_into("<Q", value, part, translated)
                        translated_words += 1
            stack[offset : offset + len(value)] = value
    first = lambda left, right: next(
        (index for index, (a, b) in enumerate(zip(left, right)) if a != b), None
    )
    return {
        "data_exact": data == boundary_data,
        "stack_exact": stack == boundary_stack,
        "first_data_mismatch": first(data, boundary_data),
        "first_stack_mismatch": first(stack, boundary_stack),
        "written_bytes": len(covered),
        "translated_stack_pointer_words": translated_words,
        "observed_data_changed_bytes": sum(a != b for a, b in zip(entry_data, boundary_data)),
        "observed_stack_changed_bytes": sum(a != b for a, b in zip(entry_stack, boundary_stack)),
    }


def verify_case(
    binary,
    segments,
    full_shadow,
    suffix,
    input_path,
    long_path_path,
    runtime_path,
    ida_path,
    expected,
):
    long_path, runtime, ida = (read_json(path) for path in (long_path_path, runtime_path, ida_path))
    trace = ida["capture"]
    run = read_json(ida_path.parent / "run.json")
    binary_hash, input_hash = hashlib.sha256(binary).hexdigest(), sha(input_path)
    assert not ida["errors"] and all(row["passed"] for row in ida["checks"])
    assert ida["inventory_before"] == ida["inventory_after"] == ida["inventory_final"]
    assert ida["root_info"]["is_tail"] and ida["root_info"]["is_loaded"]
    assert ida["root_info"]["segment_execute"] and not ida["root_info"]["has_function"]
    assert ida["observation_sha256"] == sha(runtime_path)
    assert ida["shadow_sha256"] == hashlib.sha256(suffix).hexdigest()
    assert run["input_sha256"] == binary_hash and run["plugin_unchanged"]
    assert run["script_unchanged"] and run["runner_return_code"] == 0
    assert runtime["binary_sha256"] == long_path["binary_sha256"] == binary_hash
    assert runtime["input_sha256"] == long_path["input_sha256"] == input_hash
    assert runtime["capture_source_sha256"] == sha(
        Path(__file__).with_name("morok_qemu_packed_branch_continuation.py")
    )
    assert (
        runtime["entry_packed_65536_sha256"]
        == runtime["branch_packed_65536_sha256"]
        == long_path["entry_packed_65536_sha256"]
        == hashlib.sha256(full_shadow).hexdigest()
    )
    assert runtime["data_start"] == hex(DATA_START) and runtime["data_length"] == DATA_LENGTH
    assert runtime["stack_below"] == STACK_BELOW and runtime["stack_above"] == STACK_ABOVE
    assert runtime["compare_registers"] == runtime["entries"][0]["registers"]
    assert runtime["boundary_pc"] == runtime["boundary_registers"]["rip"] == hex(BOUNDARY)
    assert runtime["maximum_steps"] == MAX_BUDGET
    assert len(runtime["entries"]) == expected
    assert long_path["budget"] == len(long_path["entries"]) == 32768
    assert long_path["entries"][21977]["pc"] == hex(COMPARE)
    assert long_path["entries"][21977 : 21977 + expected] == [
        {"pc": row["pc"], "bytes_16_hex": row["bytes_16_hex"]} for row in runtime["entries"]
    ]
    assert long_path["entries"][21977 + expected]["pc"] == hex(BOUNDARY)
    assert trace["available"] and trace["ran"] and trace["observed_tail_checkpoint"]
    assert trace["entry_state_replay"] and trace["runtime_shadow"] and trace["runtime_data"]
    assert trace["native_state_capture_complete"] and trace["data_trace_complete"]
    assert trace["instruction_budget"] == MAX_BUDGET
    assert trace["instruction_count"] == len(trace["execution"]) == expected
    assert trace["stop"] == "native-region-boundary" and trace["stop_pc"] == hex(BOUNDARY)
    assert trace["boundary_source"] == "0x41b882" and trace["boundary_target"] == hex(BOUNDARY)
    assert trace["shadow_start"] == hex(COMPARE) and trace["shadow_bytes"] == len(suffix)
    assert trace["data_start"] == hex(DATA_START) and trace["data_bytes"] == DATA_LENGTH
    assert trace["entry_stack_below_bytes"] == STACK_BELOW
    assert trace["entry_stack_bytes"] == STACK_ABOVE
    assert trace["observed_entry_sp"] == runtime["compare_registers"]["rsp"]
    assert (int(trace["entry_sp"], 16) & 0xFFF) == (
        int(runtime["compare_registers"]["rsp"], 16) & 0xFFF
    )
    assert not trace["function_evidence_published"] and not trace["vm_identity_proved"]
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    heads, mismatched_heads = head_checks(trace, binary, segments, suffix, decoder)
    assert len(heads) == trace["planned_heads"] and not mismatched_heads
    comparisons = compare_states(trace, runtime, heads, decoder)
    counts = comparisons["counts"]
    assert not comparisons["first_scalar_mismatches"]
    assert counts["exact_gprs"] == expected * 16
    assert counts["exact_rip"] == counts["exact_defined_states"] == expected
    assert counts["exact_defined_bits"] == counts["defined_bits"]
    assert counts["exact_raw_rflags"] < expected
    final = final_registers(trace, runtime)
    assert not final["gpr_mismatches"] and final["rip_exact"] and final["rflags_exact"]
    memory = project_memory(trace, runtime, trace["final_writes"])
    assert memory["data_exact"] and memory["stack_exact"]
    assert ida["narrow_data_control"]["wide_first_rng_read"] == "0x6553f0ff"
    assert ida["narrow_data_control"]["narrow_first_rng_read"] == "0x0"
    altered = copy.deepcopy(runtime)
    altered["entries"][16]["registers"]["rax"] = "0x0"
    assert compare_states(trace, altered, heads, decoder)["first_scalar_mismatches"]
    altered_writes = copy.deepcopy(trace["final_writes"])
    value = bytearray.fromhex(altered_writes[0]["bytes"])
    value[0] ^= 1
    altered_writes[0]["bytes"] = value.hex()
    assert not project_memory(trace, runtime, altered_writes)["data_exact"]
    altered_trace = copy.deepcopy(trace)
    altered_trace["heads"][0]["bytes"] = "90"
    assert head_checks(altered_trace, binary, segments, suffix, decoder)[1]
    return {
        "input_sha256": input_hash,
        "runtime_report_sha256": sha(runtime_path),
        "ida_report_sha256": sha(ida_path),
        "ida_run_sha256": sha(ida_path.parent / "run.json"),
        "long_report_sha256": sha(long_path_path),
        "entered_instructions": expected,
        "planned_heads": len(heads),
        "counts": counts,
        "final_registers_exact": 18,
        "boundary_data_bytes_exact": DATA_LENGTH,
        "boundary_stack_bytes_exact": STACK_BELOW + STACK_ABOVE,
        "memory": memory,
        "instruction_mnemonics": comparisons["instruction_mnemonics"],
        "boundary_defined_flag_mask": comparisons["boundary_defined_flag_mask"],
        "narrow_data_control": ida["narrow_data_control"],
        "plugin_sha256": run["plugin_sha256"],
        "ida_sha256": run["ida_sha256"],
        "qemu_executable_sha256": runtime["qemu_executable_sha256"],
        "gdb_executable_sha256": runtime["gdb_executable_sha256"],
        "gdb_version": runtime["gdb_version"],
        "gdb_step_loop_elapsed_ns": runtime["elapsed_ns"],
        "ida_process_elapsed_ns": run["process_elapsed_ns"],
        "database_inventory_unchanged": True,
        "mutations_rejected": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "binary",
        "second_binary",
        "full_shadow",
        "suffix",
        "first_input",
        "second_input",
        "first_long",
        "second_long",
        "first_runtime",
        "second_runtime",
        "first_ida",
        "second_ida",
        "output",
    ):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    assert binary == args.second_binary.read_bytes()
    full_shadow = args.full_shadow.read_bytes()
    suffix = args.suffix.read_bytes()
    assert len(full_shadow) == 65536
    assert len(suffix) == 65536 - (COMPARE - ROOT)
    assert full_shadow[COMPARE - ROOT :] == suffix
    segments = elf64_load_segments(binary)
    cases = [
        verify_case(
            binary,
            segments,
            full_shadow,
            suffix,
            getattr(args, label + "_input"),
            getattr(args, label + "_long"),
            getattr(args, label + "_runtime"),
            getattr(args, label + "_ida"),
            expected,
        )
        for label, expected in (("first", 1181), ("second", 785))
    ]
    assert cases[0]["plugin_sha256"] == cases[1]["plugin_sha256"]
    assert cases[0]["ida_sha256"] == cases[1]["ida_sha256"]
    assert cases[0]["qemu_executable_sha256"] == cases[1]["qemu_executable_sha256"]
    assert cases[0]["gdb_executable_sha256"] == cases[1]["gdb_executable_sha256"]
    assert cases[0]["gdb_version"] == cases[1]["gdb_version"]
    assert cases[0]["planned_heads"] == cases[1]["planned_heads"]
    result = {
        "schema": 1,
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
        "full_shadow_sha256": hashlib.sha256(full_shadow).hexdigest(),
        "suffix_sha256": hashlib.sha256(suffix).hexdigest(),
        "capture_source_sha256": sha(
            Path(__file__).with_name("morok_qemu_packed_branch_continuation.py")
        ),
        "ida_probe_source_sha256": sha(
            Path(__file__).with_name("ida_native_branch_continuation_probe.py")
        ),
        "verifier_source_sha256": sha(Path(__file__)),
        "capstone_version": capstone_version,
        "cases": cases,
        "total_entered_instructions": sum(row["entered_instructions"] for row in cases),
        "total_exact_gprs": sum(row["counts"]["exact_gprs"] for row in cases),
        "total_exact_rip": sum(row["counts"]["exact_rip"] for row in cases),
        "total_exact_defined_flag_bits": sum(row["counts"]["exact_defined_bits"] for row in cases),
        "total_exact_boundary_bytes": sum(
            row["boundary_data_bytes_exact"] + row["boundary_stack_bytes_exact"] for row in cases
        ),
        "passed": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Morok branch continuation verification: pass")


if __name__ == "__main__":
    main()
