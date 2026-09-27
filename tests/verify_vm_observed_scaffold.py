"""Independently audit the exact byte spans and provenance of an observed VM scaffold."""

import argparse
import hashlib
import json
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parent.parent
SOURCE_FILES = (
    "src/vm/ida_native_trace.cpp",
    "src/vm/ida_regions.cpp",
    "src/vm/ida_regions.hpp",
    "src/vm/region.cpp",
    "src/vm/region.hpp",
    "src/vm/semantics.cpp",
    "src/vm/semantics.hpp",
    "tests/vm_region_tests.cpp",
    "tests/vm_semantics_tests.cpp",
    "tests/ida_vm_observed_scaffold_probe.py",
    "tests/verify_vm_observed_scaffold.py",
)
EXPECTED_BINARY = "f94eddb8f3430fe9e286630b47ff2c8922e7044beaa410fe4a4b65ba8b155f57"
EXPECTED_IDA = "613d9ff7cda10686fefde8fee90ec5cbd0d2dc656bb8eaf737cbd5f9b3021ffd"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def audit(probe, run, binary, plugin, ida, matrix):
    capture = json.loads(Path(probe).read_text())
    runner = json.loads(Path(run).read_text())
    assert capture["passed"] and not capture["errors"]
    assert runner["runner_return_code"] == 0 and runner["artifacts_unchanged"]
    assert runner["source_script_unchanged"] and runner["input_copy_matches_source"]
    assert runner["plugin_unchanged"] and runner["ida_unchanged"]
    assert digest(binary) == runner["input_sha256"] == EXPECTED_BINARY
    assert digest(plugin) == runner["plugin_sha256"]
    assert digest(ida) == runner["ida_sha256"] == EXPECTED_IDA
    assert digest(ROOT / "tests/ida_vm_observed_scaffold_probe.py") == runner["script_sha256"]
    assert capture["before"] == capture["after"]
    assert len(capture["before"]) == 5
    assert all(
        site["owner"] is None
        and not site["code_head"]
        and site["loaded"]
        and site["decoded_size"] > 0
        for site in capture["before"]
    )
    trace, view = capture["trace"], capture["view"]
    assert trace["available"] and trace["ran"] and trace["native_temporal_prefix_complete"]
    assert not trace["native_temporal_complete"]
    assert not trace["function_evidence_published"] and not trace["vm_identity_proved"]
    assert view["available"] and not view["reason"] and not view["limited"]
    assert view["omitted"] == 0 and len(capture["matching"]) == 1
    row = capture["matching"][0]
    assert row in view["records"] and row["region_identity"] == trace["region_identity"]
    assert row["image_hash"] == trace["image_hash"]
    assert (row["site"], row["read"], row["dispatch"], row["observed_target"]) == (
        "0x1000d64db",
        "0x1000d64ea",
        "0x10008ef17",
        "0x100007031",
    )
    assert (row["read_bits"], row["direction"]) == ("32", "backward")
    assert tuple(
        row[key]
        for key in ("vip_register", "value_register", "key_register", "dispatch_base_register")
    ) == (
        "11",
        "0",
        "8",
        "10",
    )
    assert row["truth"] == "observed local candidate"
    assert row["semantic_validation"] == "not performed"
    assert row["vm_identity"] == row["other_entries"] == "unknown"

    spans = []
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    encoded = bytes.fromhex(row["bytes"])
    offset = 0
    for spec in row["instruction_spans"].strip(";").split(";"):
        address, size = spec.split(":")
        address, size = int(address, 16), int(size)
        chunk = encoded[offset : offset + size]
        assert len(chunk) == size
        instructions = list(decoder.disasm(chunk, address))
        assert len(instructions) == 1 and instructions[0].size == size
        spans.append(
            {
                "site": hex(address),
                "size": size,
                "bytes": chunk.hex(),
                "mnemonic": instructions[0].mnemonic,
                "operands": instructions[0].op_str,
            }
        )
        offset += size
    assert offset == len(encoded) and len(spans) == 28
    by_site = {record["site"]: record for record in spans}
    assert len(by_site) == len(spans)
    for site in capture["before"]:
        assert by_site[site["site"]]["bytes"] == site["bytes"]
    expected = {
        "0x1000d64db": ("sub", "r11, 4"),
        "0x1000d64e2": ("rcl", "ax, 0xb9"),
        "0x1000d64e6": ("setb", "ah"),
        "0x1000d64e9": ("lahf", ""),
        "0x1000d64ea": ("mov", "eax, dword ptr [r11]"),
        "0x1000d6511": ("xchg", "r8b, r8b"),
        "0x1000d6520": ("movsxd", "rax, eax"),
        "0x10011eaf1": ("add", "r10, rax"),
        "0x10008ef17": ("jmp", "r10"),
    }
    for site, instruction in expected.items():
        assert (by_site[site]["mnemonic"], by_site[site]["operands"]) == instruction
    matrix_report = json.loads(Path(matrix).read_text())
    assert matrix_report["passed"] and len(matrix_report["runs"]) == 10
    assert matrix_report["plugin_sha256"] == digest(plugin)
    assert matrix_report["ida_sha256"] == digest(ida)
    counts = {}
    completed = {}
    for matrix_run in matrix_report["runs"]:
        label = matrix_run["label"]
        artifact = Path(matrix).parent / label / "region_temporal.json"
        assert digest(artifact) == matrix_run["artifact_sha256"]["region_temporal.json"]
        measured = json.loads(artifact.read_text())
        assert not measured["errors"] and len(measured["traces"]) == 4
        assert all(record["passed"] for record in measured["records"])
        views = [trace["native_vm_candidates"] for trace in measured["traces"]]
        assert all(
            view["available"] and not view["limited"] and view["omitted"] == 0 for view in views
        )
        assert all(
            not trace["function_evidence_published"] and not trace["vm_identity_proved"]
            for trace in measured["traces"]
        )
        assert all(
            row["truth"] == "observed local candidate"
            and row["semantic_validation"] == "not performed"
            and row["vm_identity"] == "unknown"
            for view in views
            for row in view["records"]
        )
        counts[label] = [len(view["records"]) for view in views]
        completed[label] = sum(trace["native_temporal_complete"] for trace in measured["traces"])
    assert counts == {
        "original": [0, 0, 0, 0],
        "mutation-0": [0, 0, 0, 0],
        "mutation-1": [0, 0, 0, 0],
        "mutation-12648430": [0, 0, 0, 0],
        "virtualization-0": [4, 3, 4, 4],
        "virtualization-1": [4, 4, 4, 4],
        "virtualization-12648430": [0, 0, 0, 0],
        "combined-0": [5, 5, 5, 5],
        "combined-1": [4, 4, 4, 4],
        "combined-12648430": [3, 3, 3, 3],
    }
    assert all(
        completed[label] == (4 if label.startswith(("original", "mutation")) else 0)
        for label in counts
    )
    witness_path = Path(matrix).parent / "virtualization-0" / "region_temporal.json"
    witness = json.loads(witness_path.read_text())["traces"][0]
    assert witness["image_hash"] == trace["image_hash"]
    heads = {head["site"]: head for head in witness["heads"]}
    entered = witness["execution"]
    start = next(
        index
        for index, event in enumerate(entered)
        if event["site"] == row["site"] and event["sequence"] == str(int(row["first_sequence"], 16))
    )
    assert len(entered) > start + len(spans)
    for index, span in enumerate(spans):
        event = entered[start + index]
        assert event["site"] == span["site"] and event["size"] == str(span["size"])
        assert event["owner"] == "none"
        assert heads[span["site"]]["bytes"] == span["bytes"]
    assert entered[start + len(spans) - 1]["sequence"] == str(int(row["last_sequence"], 16))
    following = entered[start + len(spans)]
    assert following["site"] == row["observed_target"]
    assert any(
        edge["source"] == row["dispatch"]
        and edge["target"] == row["observed_target"]
        and edge["sequence"] == following["sequence"]
        and edge["kind"] == "jump"
        for edge in witness["edges"]
    )
    return {
        "schema": 1,
        "passed": True,
        "baseline_commit": "b9bc479c282fb061e2e9f743a0d615e99428d5f0",
        "scope": "one observed local VMP-attributed candidate; VM identity and other entries unknown",
        "assumptions": {
            "input_origin": "protected strings fixture from supplied VMP tree",
            "instruction_set": "Intel x86-64 normal completion; LAHF_LM CPU feature",
            "path": "one captured fixed-seed execution prefix; no unique-input proof",
        },
        "source_sha256": {name: digest(ROOT / name) for name in SOURCE_FILES},
        "binary_sha256": digest(binary),
        "plugin_sha256": digest(plugin),
        "ida_sha256": digest(ida),
        "probe_sha256": digest(probe),
        "runner_sha256": digest(run),
        "capstone_version": capstone.__version__,
        "trace": trace,
        "view": {
            key: view[key]
            for key in (
                "available",
                "reason",
                "starts_examined",
                "path_steps",
                "limited",
                "omitted",
            )
        },
        "candidate": row,
        "idb_inventory": capture["before"],
        "independent_disassembly": spans,
        "matrix_sha256": digest(matrix),
        "matrix_candidate_counts": counts,
        "matrix_completed_counts": completed,
        "independent_trace_witness": {
            "artifact_sha256": digest(witness_path),
            "entered_spans": len(spans),
            "first_sequence": row["first_sequence"],
            "last_sequence": row["last_sequence"],
            "observed_target": row["observed_target"],
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("probe", "run", "binary", "plugin", "ida", "matrix", "output"):
        parser.add_argument("--" + option, type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.probe, args.run, args.binary, args.plugin, args.ida, args.matrix)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(
        json.dumps(
            {"passed": True, "spans": len(report["independent_disassembly"]), "candidates": 1}
        )
    )


if __name__ == "__main__":
    main()
