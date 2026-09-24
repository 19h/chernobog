"""Cross-check the supplied VMP hello runtime window and IDA shadow reports."""

import argparse
import copy
import hashlib
import json
from pathlib import Path

import capstone

ROOT = 0x100001440
INPUT_HASHES = {
    "original": "443b0a464d7de68c5a26a3e31a92e694356ccd1eef3127d522309ac672ecc7c7",
    "protected": "c61935fe4f8a66a6d36e8c0027341a55b816833005dc0006dc0fdbdb342938a5",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def check_heads(report, window, decoder):
    heads = report["shadow"]["heads"]
    if len(heads) != 9 or report["shadow"]["planned_heads"] != len(heads):
        return False
    for head in heads:
        address = int(head["site"], 16)
        size = int(head["size"])
        offset = address - ROOT
        if offset < 0 or offset + size > 28:
            return False
        recorded = bytes.fromhex(head["bytes"])
        if recorded != window[offset : offset + size]:
            return False
        instruction = next(decoder.disasm(recorded, address, count=1), None)
        if instruction is None or instruction.size != size or instruction.bytes != recorded:
            return False
    entered = {row["site"] for row in report["shadow"]["execution"]}
    return len(entered) == 6 and entered <= {row["site"] for row in heads}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, action="append", required=True)
    parser.add_argument("--ida", type=Path, action="append", required=True)
    parser.add_argument("--prior", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.runtime) != 2 or len(args.ida) != 2:
        parser.error("exactly two runtime and two current IDA reports are required")

    runtime = [read_json(path) for path in args.runtime]
    current = [read_json(path) for path in args.ida]
    prior = read_json(args.prior)
    windows = [
        bytes.fromhex(row["reports"]["protected"][0]["snapshot"]["window_hex"]) for row in runtime
    ]
    window = windows[0]
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    checks = {
        "pinned_input_and_runtime_reports": all(
            row["passed"] and all(row["checks"].values()) and row["input_sha256"] == INPUT_HASHES
            for row in runtime
        ),
        "independent_debuggers_agree": windows[0] == windows[1]
        and len(window) == 40
        and all(
            all(
                run["snapshot"]["window_hex"] == window.hex()
                for target in ("original", "protected")
                for run in row["reports"][target]
            )
            for row in runtime
        ),
        "literal_at_use": all(
            run["snapshot"]["format_pointer"] == run["snapshot"]["string_address"]
            and bytes.fromhex(run["snapshot"]["string_hex"]) == b"Hello World\0"
            for row in runtime
            for run in row["reports"]["protected"]
        ),
        "current_ida_reports_pass": all(
            not row["errors"]
            and all(item["passed"] for item in row["checks"])
            and row["window_sha256"] == digest(window)
            and row["inventory_before"] == row["inventory_after"]
            and row["overlay_oracle"] == {"newly_loaded": 34, "changed_loaded": 4}
            for row in current
        ),
        "current_head_bytes_decode": all(check_heads(row, window, decoder) for row in current),
        "current_graphs_agree": all(
            current[0]["shadow"][name] == current[1]["shadow"][name]
            for name in ("heads", "execution", "edges", "states", "data", "frontiers")
        ),
        "prior_abstains": not prior["errors"]
        and all(item["passed"] for item in prior["checks"])
        and prior["window_sha256"] == digest(window)
        and not prior["shadow"]["available"]
        and prior["shadow"]["reason"] == "not_unlabeled_executable_data_head",
    }
    changed_window = bytearray(window)
    changed_window[0] ^= 1
    checks["window_mutation_rejected"] = all(
        row["window_sha256"] != digest(changed_window) for row in current
    )
    changed_head = copy.deepcopy(current[0])
    changed_head["shadow"]["heads"][0]["bytes"] = "90"
    checks["head_mutation_rejected"] = not check_heads(changed_head, window, decoder)

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
        raise AssertionError("VMP hello runtime shadow verification failed")
    print("VMP hello runtime shadow verification: pass")


if __name__ == "__main__":
    main()
