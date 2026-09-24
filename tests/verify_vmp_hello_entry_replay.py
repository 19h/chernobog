"""Compare observed protected hello main-entry states with native shadow replay."""

import argparse
import copy
import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, __version__ as capstone_version

from run_vmp_hello_runtime import INPUT_HASHES, section_map

ROOT = 0x100001440
GPRS = (
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
)
MASK64 = (1 << 64) - 1
PCS = (ROOT, ROOT + 1, ROOT + 4, ROOT + 11, ROOT + 13, ROOT + 22)
SIZES = (1, 3, 7, 2, 5, 6)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def registers(row):
    values = {}
    for fragment in row["registers"].split(";"):
        name, width, value = fragment.split(":")
        index = int(name)
        assert index not in values and int(width) == 8
        values[index] = int(value, 16)
    assert set(values) == {16, 18} | set(range(256, 272))
    return values


def candidate_states(trace):
    visits = trace["execution"]
    sequence = {row["sequence"]: index for index, row in enumerate(visits)}
    assert len(sequence) == len(visits) == 6
    states = {}
    for row in trace["states"]:
        if row["kind"] != "native instruction entry":
            continue
        index = sequence[row["sequence"]]
        assert index not in states and row["site"] == visits[index]["site"]
        states[index] = registers(row)
    assert set(states) == set(range(6))
    return states


def compare(runtime, trace, relative_gprs):
    states = candidate_states(trace)
    observed_sp = int(runtime["entry_registers"]["rsp"], 16)
    scratch_sp = int(trace["entry_sp"], 16)
    mismatches = []
    for index, sample in enumerate(runtime["samples"]):
        observed = sample["registers"]
        actual = states[index]
        for reg, name in enumerate(GPRS):
            value = actual[256 + reg]
            if reg in relative_gprs:
                displacement = value - scratch_sp
                if not -0x8000 <= displacement <= 0x8000:
                    mismatches.append((index, name, "outside translated stack window"))
                    continue
                value = (observed_sp + displacement) & MASK64
            if value != int(observed[name], 16):
                mismatches.append((index, name, hex(value), observed[name]))
        for reg, name in ((16, "rip"), (18, "eflags")):
            if actual[reg] != int(observed[name], 16):
                mismatches.append((index, name, hex(actual[reg]), observed[name]))
    return mismatches


def final_stack_matches(runtime, trace):
    writes = trace["final_writes"]
    if len(writes) != 1:
        return False
    scratch_sp = int(trace["entry_sp"], 16)
    observed_sp = int(runtime["entry_registers"]["rsp"], 16)
    write = writes[0]
    raw = bytes.fromhex(write["bytes"])
    actual = bytes.fromhex(runtime["samples"][5]["stack_16_hex"])
    if len(raw) != 16 or len(actual) != 16 or int(write["address"], 16) != scratch_sp - 16:
        return False
    return (
        struct.unpack_from("<Q", raw)[0] == struct.unpack_from("<Q", actual)[0] == ROOT + 18
        and (struct.unpack_from("<Q", raw, 8)[0] - scratch_sp) & MASK64
        == (struct.unpack_from("<Q", actual, 8)[0] - observed_sp) & MASK64
    )


def inspect(runtime, runtime_hash, ida, run, prior, window, decoder, script_hash):
    trace = ida["capture"]
    entry = runtime["entry_registers"]
    stack = bytes.fromhex(runtime["entry_stack_above_hex"])
    observed_sp = int(entry["rsp"], 16)
    near = lambda value: abs(value - observed_sp) <= 0x8000
    relative_gprs = [index for index, name in enumerate(GPRS) if near(int(entry[name], 16))]
    relative_words = [
        offset
        for offset in range(0, len(stack), 8)
        if near(struct.unpack_from("<Q", stack, offset)[0])
    ]
    samples = runtime["samples"]
    predecessor = prior["reports"]["protected"][0]["snapshot"]
    checks = {
        "runtime_identity": runtime["schema"] == 1
        and runtime["binary_sha256"] == INPUT_HASHES["protected"]
        and runtime["runtime_window_hex"] == window.hex()
        and int(runtime["preferred_base"], 16) == 0x100000000
        and int(runtime["loaded_base"], 16) == 0x100000000 + int(runtime["slide"], 16)
        and int(runtime["entry_stub_pc"], 16) == ROOT - 10 + int(runtime["slide"], 16)
        and int(runtime["main_pc"], 16) == ROOT + int(runtime["slide"], 16)
        and len(stack) == 128
        and observed_sp % 16 == 8
        and len(samples) == 6
        and samples[0]["registers"] == entry,
        "paired_runtime_uses_same_debugger_and_call": prior["passed"]
        and all(prior["checks"].values())
        and runtime["debugger_version"].startswith(prior["lldb_version"])
        and predecessor["window_hex"] == window.hex()
        and predecessor["pc"] == runtime["successor_registers"]["rip"]
        and predecessor["format_pointer"] == runtime["successor_registers"]["rdi"],
        "ida_runner_identity": run["input_sha256"] == INPUT_HASHES["protected"]
        and run["source_input_sha256"] == INPUT_HASHES["protected"]
        and run["source_script_sha256"] == script_hash
        and run["plugin_unchanged"]
        and run["script_unchanged"]
        and run["ida_unchanged"]
        and run["enable_rax"]
        and run["runner_return_code"] == 0
        and run["expected_log_found"]
        and not run["internal_error_found"],
        "ida_probe_and_inventory": not ida["errors"]
        and all(row["passed"] for row in ida["checks"])
        and ida["inventory_before"] == ida["inventory_after"]
        and ida["runtime_sha256"] == runtime_hash
        and ida["shadow_sha256"] == digest(window)
        and ida["request_summary"]["relative_gprs"] == relative_gprs
        and ida["request_summary"]["relative_words"] == relative_words
        and ida["request_summary"]["stack_sha256"] == digest(stack),
        "bounded_native_trace": trace["available"]
        and trace["ran"]
        and trace["entry_state_replay"]
        and trace["runtime_shadow"]
        and trace["native_state_capture_complete"]
        and trace["stop"] == "environment-model-failure"
        and int(trace["stop_pc"], 16) == ROOT + 22
        and trace["instruction_count"] == 6
        and len(trace["execution"]) == 6
        and not trace["function_evidence_published"]
        and not trace["vm_identity_proved"]
        and (int(trace["entry_sp"], 16) & 0xFFF) == (observed_sp & 0xFFF)
        and trace["observed_entry_sp"] == entry["rsp"],
    }
    checks["runtime_instruction_bytes_and_decode"] = all(
        int(sample["registers"]["rip"], 16) == pc + int(runtime["slide"], 16)
        and bytes.fromhex(sample["bytes_16_hex"]) == window[pc - ROOT : pc - ROOT + 16]
        and (instruction := next(decoder.disasm(window[pc - ROOT :], pc, count=1), None))
        is not None
        and instruction.size == size
        for sample, pc, size in zip(samples, PCS, SIZES)
    )
    checks["ida_instruction_bytes_and_edges"] = (
        [int(row["site"], 16) for row in trace["execution"]] == list(PCS)
        and [int(row["size"]) for row in trace["execution"]] == list(SIZES)
        and any(
            row["kind"] == "call"
            and row["source"] == hex(ROOT + 13)
            and row["target"] == hex(ROOT + 22)
            for row in trace["edges"]
        )
    )
    checks["runtime_stack_before_and_after"] = (
        bytes.fromhex(samples[0]["stack_16_hex"]) == stack[:16]
        and samples[5]["stack_16_hex"] == runtime["successor_stack_16_hex"]
        and int(samples[5]["registers"]["rsp"], 16) == observed_sp - 16
        and int(runtime["successor_registers"]["rsp"], 16) == observed_sp - 16
    )
    mismatches = compare(runtime, trace, relative_gprs)
    checks["all_108_scalar_states_match"] = not mismatches
    checks["call_and_frame_stack_writes_match"] = final_stack_matches(runtime, trace)
    altered_runtime = copy.deepcopy(runtime)
    altered_runtime["samples"][3]["registers"]["rdi"] = hex(ROOT + 29)
    checks["runtime_register_mutation_rejected"] = bool(
        compare(altered_runtime, trace, relative_gprs)
    )
    altered_trace = copy.deepcopy(trace)
    state = next(
        row for row in altered_trace["states"] if row["kind"] == "native instruction entry"
    )
    state["registers"] = state["registers"].replace("16:8:0x100001440", "16:8:0x100001441")
    checks["candidate_pc_mutation_rejected"] = bool(compare(runtime, altered_trace, relative_gprs))
    altered_trace = copy.deepcopy(trace)
    altered_trace["final_writes"][0]["bytes"] = "00" + altered_trace["final_writes"][0]["bytes"][2:]
    checks["stack_write_mutation_rejected"] = not final_stack_matches(runtime, altered_trace)
    return {
        "checks": checks,
        "scalar_matches": 108 - len(mismatches),
        "first_scalar_mismatches": mismatches[:5],
        "observed_sp_page_offset": observed_sp & 0xFFF,
        "translated_sp_page_offset": int(trace["entry_sp"], 16) & 0xFFF,
        "relative_gpr_indices": relative_gprs,
        "relative_stack_word_offsets": relative_words,
        "entered_instructions": len(samples),
        "environment_stop": trace["stop"],
        "debugger_version": runtime["debugger_version"],
        "plugin_sha256": run["plugin_sha256"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--protected", type=Path, required=True)
    parser.add_argument("--window", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, action="append", required=True)
    parser.add_argument("--ida", type=Path, action="append", required=True)
    parser.add_argument("--paired-runtime", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if any(len(rows) != 2 for rows in (args.runtime, args.ida, args.paired_runtime)):
        parser.error("exactly two reports are required for each repeated input")
    original, protected = args.original.read_bytes(), args.protected.read_bytes()
    assert digest(original) == INPUT_HASHES["original"]
    assert digest(protected) == INPUT_HASHES["protected"]
    sections = section_map(original)
    start = sections["__text"]["file_offset"]
    end = sections["__cstring"]["file_offset"] + sections["__cstring"]["size"]
    window = args.window.read_bytes()
    assert len(window) == 40 and original[start:end] == window
    runtimes = [read_json(path) for path in args.runtime]
    idas = [read_json(path) for path in args.ida]
    paired = [read_json(path) for path in args.paired_runtime]
    runs = [read_json(path.parent / "run.json") for path in args.ida]
    script_hash = digest(
        Path(__file__).with_name("ida_vmp_hello_entry_replay_probe.py").read_bytes()
    )
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    comparisons = [
        inspect(
            runtime,
            digest(runtime_path.read_bytes()),
            ida,
            run,
            prior,
            window,
            decoder,
            script_hash,
        )
        for runtime, runtime_path, ida, run, prior in zip(
            runtimes, args.runtime, idas, runs, paired
        )
    ]
    checks = {
        "both_debuggers_and_ida_runs_pass": all(all(row["checks"].values()) for row in comparisons),
        "debugger_versions_distinct": comparisons[0]["debugger_version"]
        != comparisons[1]["debugger_version"],
        "same_plugin_artifact": comparisons[0]["plugin_sha256"] == comparisons[1]["plugin_sha256"],
        "same_shadow_trace_geometry": all(
            idas[0]["capture"][key] == idas[1]["capture"][key]
            for key in ("heads", "execution", "edges", "frontiers", "stop", "stop_pc")
        ),
    }
    result = {
        "schema": 1,
        "input_sha256": INPUT_HASHES,
        "window_sha256": digest(window),
        "runtime_report_sha256": [digest(path.read_bytes()) for path in args.runtime],
        "ida_report_sha256": [digest(path.read_bytes()) for path in args.ida],
        "ida_run_sha256": [digest((path.parent / "run.json").read_bytes()) for path in args.ida],
        "paired_runtime_report_sha256": [digest(path.read_bytes()) for path in args.paired_runtime],
        "capture_source_sha256": digest(
            Path(__file__).with_name("lldb_vmp_hello_main_states.py").read_bytes()
        ),
        "ida_probe_source_sha256": script_hash,
        "verifier_source_sha256": digest(Path(__file__).read_bytes()),
        "capstone_version": capstone_version,
        "comparisons": comparisons,
        "checks": checks,
        "passed": all(checks.values()),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not result["passed"]:
        raise AssertionError("VMP hello observed entry replay verification failed")
    print("VMP hello observed entry replay verification: pass")


if __name__ == "__main__":
    main()
