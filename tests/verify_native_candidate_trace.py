"""Independently check packed candidate entries against ELF64 bytes and Capstone."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf64_load_segments(data):
    assert data[:6] == b"\x7fELF\x02\x01"
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    assert size >= 56 and count <= 128 and offset + size * count <= len(data)
    result = []
    for index in range(count):
        kind, _, file_offset, address, _, file_size, _ = struct.unpack_from(
            "<IIQQQQQ", data, offset + index * size
        )
        if kind == 1:
            assert file_offset + file_size <= len(data)
            result.append((address, file_offset, file_size))
    assert result
    return result


def file_bytes(data, segments, address, size):
    matches = [
        data[offset + address - va : offset + address - va + size]
        for va, offset, length in segments
        if va <= address and address + size <= va + length
    ]
    return matches[0] if len(matches) == 1 else None


def verify(report_path, expected_input_sha256, data, segments, decoder):
    report = json.loads(report_path.read_text())
    assert not report["errors"] and all(row["passed"] for row in report["checks"])
    trace = report["candidate"]
    assert trace["scope"] == "native-candidate-region"
    assert trace["candidate_decode"] and trace["synthetic_entry"]
    heads = {int(row["site"], 0): row for row in trace["heads"]}
    assert len(heads) == len(trace["heads"])
    visits = trace["execution"]
    result = {
        "report_sha256": digest(report_path),
        "input_sha256": expected_input_sha256,
        "visits": len(visits),
        "unique_entered_heads": len({row["site"] for row in visits}),
        "file_byte_mismatches": [],
        "decode_mismatches": [],
        "linear_successor_mismatches": [],
    }
    assert visits and visits[0]["site"] == trace["root"]
    for row in visits:
        address = int(row["site"], 0)
        size = int(row["size"])
        head = heads.get(address)
        encoded = None if head is None else bytes.fromhex(head["bytes"])
        actual = file_bytes(data, segments, address, size)
        if encoded != actual or head is None or int(head["size"]) != size:
            result["file_byte_mismatches"].append(hex(address))
        if encoded is None:
            result["decode_mismatches"].append(hex(address))
            continue
        decoded = next(decoder.disasm(encoded, address), None)
        if decoded is None or decoded.size != size or len(encoded) != size:
            result["decode_mismatches"].append(hex(address))
    for left, right in zip(visits, visits[1:]):
        source = int(left["site"], 0)
        target = int(right["site"], 0)
        head = heads[source]
        if int(head["flow"]) == 0 and target != source + int(left["size"]):
            result["linear_successor_mismatches"].append(
                {"source": hex(source), "target": hex(target)}
            )
    result["passed"] = (
        result["visits"] > 0
        and not result["file_byte_mismatches"]
        and not result["decode_mismatches"]
        and not result["linear_successor_mismatches"]
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--first-report", type=Path, required=True)
    parser.add_argument("--second-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.binary.read_bytes()
    segments = elf64_load_segments(raw)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    binary_hash = digest(args.binary)
    results = [
        verify(path, binary_hash, raw, segments, decoder)
        for path in (args.first_report, args.second_report)
    ]
    output = {
        "schema": 1,
        "source_sha256": digest(Path(__file__)),
        "capstone_version": capstone.__version__,
        "binary_sha256": binary_hash,
        "runs": results,
        "matching_reports": results[0] == results[1],
        "passed": all(row["passed"] for row in results) and results[0] == results[1],
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": output["passed"],
                "visits_per_run": [row["visits"] for row in results],
                "unique_heads_per_run": [row["unique_entered_heads"] for row in results],
                "mismatches_per_run": [
                    sum(
                        len(row[key])
                        for key in (
                            "file_byte_mismatches",
                            "decode_mismatches",
                            "linear_successor_mismatches",
                        )
                    )
                    for row in results
                ],
            }
        )
    )
    return 0 if output["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
