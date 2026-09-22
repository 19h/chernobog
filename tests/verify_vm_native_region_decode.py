"""Compare captured native instruction spans with Capstone and file-backed bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64


def segments(data):
    result = []
    if data[:4] == b"\xcf\xfa\xed\xfe":
        offset = 32
        for _ in range(struct.unpack_from("<I", data, 16)[0]):
            kind, size = struct.unpack_from("<II", data, offset)
            assert size >= 8 and offset + size <= len(data)
            if kind == 0x19:
                va, _, file_offset, file_size = struct.unpack_from("<QQQQ", data, offset + 24)
                result.append((va, file_offset, file_size))
            offset += size
    else:
        assert data[:6] == b"\x7fELF\x01\x01"
        offset = struct.unpack_from("<I", data, 28)[0]
        size, count = struct.unpack_from("<HH", data, 42)
        assert size >= 32
        for index in range(count):
            kind, file_offset, va, _, file_size = struct.unpack_from("<IIIII", data, offset + index * size)
            if kind == 1:
                result.append((va, file_offset, file_size))
    assert all(file_offset + size <= len(data) for _, file_offset, size in result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--corpus-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect-size-mismatches", type=int, default=0)
    parser.add_argument("--capture-artifact", choices=("vm_native_traces.json", "vm_native_inputs.json"),
                        default="vm_native_traces.json")
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    corpus = json.loads(args.corpus_report.read_text())
    digest = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
    assert report["passed"] and report["corpus_report_sha256"] == digest(args.corpus_report)
    result = {"schema": 1, "capstone_version": capstone.__version__, "report_sha256": digest(args.report),
              "source_sha256": digest(__file__), "instruction_records": 0, "size_mismatches": [],
              "linear_successor_mismatches": [], "byte_mismatches": [], "undefined_bswap16_frontiers": 0,
              "capture_sha256": {}, "passed": False}
    expected_inputs = {"original": corpus["original_sha256"], **{p["label"]: p["sha256"] for p in corpus["protection"]}}
    for run in report["runs"]:
        label = run["label"]
        binary = args.corpus_report.parent / label
        assert digest(binary) == expected_inputs[label] == run["input_sha256"]
        raw = binary.read_bytes()
        spans = segments(raw)

        def at(address, count):
            matches = [raw[offset + address - va:offset + address - va + count]
                       for va, offset, size in spans if va <= address and address + count <= va + size]
            assert len(matches) == 1
            return matches[0]

        path = args.report.parent / label / args.capture_artifact
        assert digest(path) == run["artifact_sha256"][args.capture_artifact]
        result["capture_sha256"][label] = digest(path)
        capture = json.loads(path.read_text())
        if args.capture_artifact == "vm_native_inputs.json":
            traces = [(row["name"] + ":" + str(row["case"]), row["trace"]) for row in capture["captures"]]
        else:
            traces = [(name, trace) for name, trace in capture["captures"].items() if ":" in name]
        for name, trace in traces:
            cs = Cs(CS_ARCH_X86, CS_MODE_64 if trace["address_bits"] == 64 else CS_MODE_32)
            heads = {int(h["site"], 0): h for h in trace["heads"]}
            case = label + "/" + name
            for row in trace["execution"]:
                ea, size = int(row["site"], 0), int(row["size"])
                encoded = bytes.fromhex(heads[ea]["bytes"])
                result["instruction_records"] += 1
                if encoded != at(ea, len(encoded)):
                    result["byte_mismatches"].append({"case": case, "site": hex(ea)})
                instruction = next(cs.disasm(encoded, ea), None)
                if instruction is None or instruction.size != size or len(encoded) != size:
                    result["size_mismatches"].append({"case": case, "site": hex(ea), "bytes": encoded.hex(),
                        "captured_size": size, "oracle_size": None if instruction is None else instruction.size})
            successors = [(int(a["site"], 0), int(b["site"], 0))
                          for a, b in zip(trace["execution"], trace["execution"][1:])]
            if trace["region_boundary"]:
                successors.append((int(trace["boundary_source"], 0), int(trace["boundary_target"], 0)))
                source = heads.get(int(trace["boundary_source"], 0))
                if source and int(source["flow"]) == 0:
                    target = int(trace["boundary_target"], 0)
                    instruction = next(cs.disasm(at(target, 15), target), None)
                    if instruction and instruction.mnemonic == "bswap" and instruction.op_str in {
                            "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", *[f"r{i}w" for i in range(8, 16)]}:
                        result["undefined_bswap16_frontiers"] += 1
            for source, target in successors:
                if source in heads and int(heads[source]["flow"]) == 0 and target != source + int(heads[source]["size"]):
                    result["linear_successor_mismatches"].append({"case": case, "source": hex(source), "target": hex(target)})
    result["passed"] = (not result["byte_mismatches"] and result["instruction_records"] > 0
                        and len(result["size_mismatches"]) == args.expect_size_mismatches
                        and len(result["linear_successor_mismatches"]) == args.expect_size_mismatches)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in {
        "capture_sha256", "size_mismatches", "linear_successor_mismatches", "byte_mismatches"}}, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
