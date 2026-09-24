"""Verify a synthetic VMP call-argument snapshot against protected LLDB uses."""

import argparse
import copy
import hashlib
import json
from pathlib import Path

import capstone
from capstone.x86 import X86_OP_IMM

ROOT = 0x100001440
SOURCE = 0x10000144D
TARGET = 0x100001456
LITERAL = 0x10000145C
INPUT_HASHES = {
    "original": "443b0a464d7de68c5a26a3e31a92e694356ccd1eef3127d522309ac672ecc7c7",
    "protected": "c61935fe4f8a66a6d36e8c0027341a55b816833005dc0006dc0fdbdb342938a5",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def valid_use(report, window):
    if report["errors"] or not all(row["passed"] for row in report["checks"]):
        return False
    if report["window_sha256"] != digest(window):
        return False
    selected = report["selected"]
    use = selected.get("shadow_use", {})
    if not selected["available"] or not use.get("available"):
        return False
    if (
        use["source"] != hex(SOURCE)
        or use["target"] != hex(TARGET)
        or use["register"] != "rdi"
        or use["pointer"] != hex(LITERAL)
        or use["sequence"] != 7
        or bytes.fromhex(use["bytes"]) != window[28:]
        or use["payload_bytes"] != 11
        or not use["synthetic_state"]
        or use["callee_semantics_proved"]
    ):
        return False
    if report["inventory_before"] != report["inventory_after"]:
        return False
    return (
        all(
            selected[key] == report["baseline"][key]
            for key in ("heads", "execution", "edges", "states", "data", "frontiers")
        )
        and report["mutated_shadow"]["shadow_use"]["bytes"] != use["bytes"]
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, action="append", required=True)
    parser.add_argument("--ida", type=Path, action="append", required=True)
    parser.add_argument("--prior", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.runtime) != 2 or len(args.ida) != 2:
        parser.error("exactly two debugger and two IDA reports are required")
    runtime = [read_json(path) for path in args.runtime]
    ida = [read_json(path) for path in args.ida]
    prior = read_json(args.prior)
    window = bytes.fromhex(runtime[0]["reports"]["protected"][0]["snapshot"]["window_hex"])
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    call = next(decoder.disasm(window[SOURCE - ROOT : TARGET - ROOT], SOURCE, count=1), None)
    stub = next(decoder.disasm(window[TARGET - ROOT : LITERAL - ROOT], TARGET, count=1), None)
    checks = {
        "pinned_pair_and_debugger_checks": all(
            row["passed"] and all(row["checks"].values()) and row["input_sha256"] == INPUT_HASHES
            for row in runtime
        ),
        "one_restored_window": len(window) == 40
        and window[28:] == b"Hello World\0"
        and all(
            all(
                bytes.fromhex(run["snapshot"]["window_hex"]) == window
                for run in row["reports"][target]
            )
            for row in runtime
            for target in ("original", "protected")
        ),
        "direct_call_and_import_jump_decode": call is not None
        and call.size == 5
        and call.mnemonic == "call"
        and len(call.operands) == 1
        and call.operands[0].type == X86_OP_IMM
        and call.operands[0].imm == TARGET
        and stub is not None
        and stub.size == 6
        and stub.mnemonic == "jmp",
        "protected_printf_argument_matches_image_pointer": all(
            int(run["snapshot"]["format_pointer"], 16) - int(run["snapshot"]["slide"], 16)
            == LITERAL
            and bytes.fromhex(run["snapshot"]["string_hex"]) == window[28:]
            for row in runtime
            for run in row["reports"]["protected"]
        ),
        "ida_use_and_trace_checks": all(valid_use(row, window) for row in ida),
        "ida_runs_agree": ida[0]["selected"] == ida[1]["selected"],
        "prior_plugin_has_no_use_query": not prior["errors"]
        and all(row["passed"] for row in prior["checks"]),
    }
    mutated = copy.deepcopy(ida[0])
    mutated["selected"]["shadow_use"]["pointer"] = hex(LITERAL + 1)
    checks["pointer_mutation_rejected"] = not valid_use(mutated, window)
    mutated = copy.deepcopy(ida[0])
    mutated["selected"]["shadow_use"]["bytes"] = (
        "00" + mutated["selected"]["shadow_use"]["bytes"][2:]
    )
    checks["byte_mutation_rejected"] = not valid_use(mutated, window)
    mutated = copy.deepcopy(ida[0])
    mutated["selected"]["shadow_use"]["source"] = hex(SOURCE - 2)
    checks["source_mutation_rejected"] = not valid_use(mutated, window)
    result = {
        "schema": 1,
        "input_sha256": INPUT_HASHES,
        "window_sha256": digest(window),
        "runtime_report_sha256": [digest(path.read_bytes()) for path in args.runtime],
        "ida_report_sha256": [digest(path.read_bytes()) for path in args.ida],
        "prior_report_sha256": digest(args.prior.read_bytes()),
        "capstone_version": capstone.__version__,
        "checks": checks,
        "passed": all(checks.values()),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not result["passed"]:
        raise AssertionError("VMP hello use-site verification failed")
    print("VMP hello use-site verification: pass")


if __name__ == "__main__":
    main()
