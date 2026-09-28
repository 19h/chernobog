#!/usr/bin/env python3
"""Independently decode the protected 97-head ownerless region from file bytes."""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import traceback

import capstone
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86_const import X86_OP_IMM

sys.dont_write_bytecode = True
from verify_vm_native_region_decode import segments

ROOT = 0x1000AB676
INPUT_SHA256 = "1c14af5156970789fd75a758cadb3cbda8248849acabd2106a2e5ba907fb6b74"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def decode_graph(raw):
    mappings = segments(raw)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    pending, decoded, edges, frontiers = [ROOT], {}, set(), set()
    while pending:
        address = pending.pop()
        if address in decoded:
            continue
        assert len(decoded) < 128, "independent node bound reached"
        locations = [
            (offset + address - va, size - (address - va))
            for va, offset, size in mappings
            if va <= address < va + size
        ]
        assert len(locations) == 1, "address has no unique file-backed mapping"
        offset, available = locations[0]
        instruction = next(
            decoder.disasm(raw[offset : offset + min(15, available)], address, count=1), None
        )
        assert instruction is not None and instruction.size <= available
        decoded[address] = instruction
        mnemonic = instruction.mnemonic
        successor = address + instruction.size
        if mnemonic.startswith("ret"):
            frontiers.add((address, "return"))
        elif mnemonic == "jmp":
            if instruction.operands[0].type != X86_OP_IMM:
                frontiers.add((address, "indirect"))
            else:
                target = instruction.operands[0].imm
                edges.add(("direct-jump", address, target))
                pending.append(target)
        elif mnemonic == "bswap" and instruction.operands[0].size == 2:
            frontiers.add((address, "bswap16"))
        elif mnemonic.startswith("j"):
            assert instruction.operands[0].type == X86_OP_IMM
            target = instruction.operands[0].imm
            edges.add(("conditional-taken", address, target))
            edges.add(("fallthrough", address, successor))
            pending.extend((target, successor))
        else:
            edges.add(("fallthrough", address, successor))
            pending.append(successor)
    return decoded, edges, frontiers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--inspection", type=Path, required=True)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    report = {
        "schema": 1,
        "passed": False,
        "errors": [],
        "input_sha256": digest(arguments.binary),
        "inspection_sha256": digest(arguments.inspection),
        "run_sha256": digest(arguments.run),
        "verifier_sha256": digest(__file__),
        "decoder_sha256": digest(Path(__file__).with_name("verify_vm_native_region_decode.py")),
        "capstone_version": capstone.__version__,
    }
    try:
        assert report["input_sha256"] == INPUT_SHA256
        capture = json.loads(arguments.inspection.read_text())
        run = json.loads(arguments.run.read_text())
        assert not capture["errors"] and all(row["passed"] for row in capture["checks"])
        assert run["runner_return_code"] == 0 and run["artifacts_unchanged"]
        assert run["input_sha256"] == INPUT_SHA256
        view = capture["inspection"]
        assert capture["root"] == ROOT and capture["owner"] is None
        assert capture["inventory_before"] == capture["inventory_after"]
        assert view["available"] and view["converged"] and not view["truncated"]
        assert view["reason"] == "complete_bounded_region" and not view["published"]
        assert view["limits"] == {"nodes": 128, "rounds": 128, "incoming_per_node": 256}
        decoded, expected_edges, frontiers = decode_graph(arguments.binary.read_bytes())
        actual_nodes = {int(row["site"], 0): row for row in view["nodes"]}
        assert len(decoded) == len(actual_nodes) == 97 and decoded.keys() == actual_nodes.keys()
        for address, instruction in decoded.items():
            row = actual_nodes[address]
            assert row["bytes"] == instruction.bytes.hex()
            assert int(row["size"]) == instruction.size
            assert row["owner"] == "unknown"
        actual_edges = {
            (row["kind"], int(row["source"], 0), int(row["target"], 0))
            for row in view["edges"]
            if row["kind"] != "frontier"
        }
        assert actual_edges == expected_edges and len(actual_edges) == 97
        assert frontiers == {(0x100081460, "return")}
        assert [
            (row["source"], row["target"], row["reason"])
            for row in view["edges"]
            if row["kind"] == "frontier"
        ] == [("0x100081460", "0x100081460", "return_target")]
        condition_sites = {
            address
            for address, instruction in decoded.items()
            if (instruction.mnemonic.startswith("j") and instruction.mnemonic != "jmp")
            or instruction.mnemonic.startswith("set")
            or instruction.mnemonic.startswith("cmov")
        }
        assert condition_sites == {0x10006E5B9, 0x10006E5FB, 0x10006E610}
        assert {
            int(row["site"], 0) for row in view["records"] if row["kind"] != "push-return"
        } == condition_sites
        assert all(row["status"] == "unresolved" for row in view["records"])
        report.update(
            {
                "node_count": len(decoded),
                "direct_edge_count": len(expected_edges),
                "frontier_count": len(frontiers),
                "condition_sites": [hex(address) for address in sorted(condition_sites)],
                "proved_condition_sites": 0,
                "read_only_inventory": True,
                "passed": True,
            }
        )
    except Exception as error:
        location = traceback.extract_tb(error.__traceback__)[-1]
        report["errors"].append(
            type(error).__name__
            + ": "
            + str(error)
            + " at "
            + location.name
            + ":"
            + str(location.lineno)
        )
    arguments.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("[chernobog][ownerless-97-verifier] " + ("PASS" if report["passed"] else "FAIL"))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
