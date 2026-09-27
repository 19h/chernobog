"""Check joined-quota captures against independent file-backed instruction inventories."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import capstone
from capstone.x86 import X86_INS_LEA, X86_INS_RET, X86_REG_RIP

from verify_vm_native_region_decode import segments


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(trace, raw, initial_count, added_count, complete):
    spans = segments(raw)

    def at(address, count):
        matches = [
            raw[offset + address - base : offset + address - base + count]
            for base, offset, size in spans
            if base <= address and address + count <= base + size
        ]
        assert len(matches) == 1
        return matches[0]

    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True

    def through_return(address):
        decoded = []
        for _ in range(8192):
            instruction = next(cs.disasm(at(address, 15), address), None)
            assert instruction is not None
            decoded.append(instruction)
            address += instruction.size
            if instruction.id == X86_INS_RET:
                return decoded
        raise AssertionError("fixture has no bounded return")

    initial = through_return(int(trace["function"], 0))
    assert len(initial) == initial_count
    lea = initial[2]
    assert lea.id == X86_INS_LEA and lea.operands[1].mem.base == X86_REG_RIP
    target = lea.address + lea.size + lea.operands[1].mem.disp
    addition = through_return(target)
    assert len(addition) == 4
    expected = {i.address: bytes(i.bytes) for i in initial + addition[:added_count]}
    heads = trace["heads"]
    sites = [int(row["site"], 0) for row in heads]
    assert sites == sorted(set(sites)) and set(sites) == set(expected)
    for row in heads:
        address = int(row["site"], 0)
        assert bytes.fromhex(row["bytes"]) == expected[address]
    assert trace["planned_heads"] == len(expected) <= 4096
    assert trace["plan_truncated"] == (not complete)
    path = initial[:4] + addition[:added_count]
    assert [int(row["site"], 0) for row in trace["execution"]] == [i.address for i in path]
    assert [int(row["size"]) for row in trace["execution"]] == [i.size for i in path]
    assert trace["instruction_count"] == len(path) and trace["abstract_instruction_count"] == 0
    assert trace["reached_sentinel"] == complete
    assert not trace["function_evidence_published"] and not trace["vm_identity_proved"]
    assert trace["region_boundary"] == (not complete)
    admissions = trace["native_admissions"]
    assert len(admissions) == 1
    assert admissions[0]["admitted"] == "true"
    assert int(admissions[0]["source"], 0) == initial[3].address
    assert int(admissions[0]["target"], 0) == target
    assert int(admissions[0]["added_heads"]) == added_count
    if complete:
        assert trace["final_registers_complete"] and trace["sp_valid"] and trace["sp_delta"] == 8
        assert any(
            int(row["reg"]) == 0x100 and int(row["value"], 0) == 42
            for row in trace["final_registers"]
        )
    return len(heads), len(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert capstone.__version__ == "5.0.7"
    corpus_path = args.build_dir / "native-extension-fixture-v3/corpus.json"
    corpus = json.loads(corpus_path.read_text())
    assert corpus["passed"]
    inputs = {row["label"]: row for row in corpus["binaries"]}
    cases = [
        ("prior-exact", "exact", 4092, 2, False),
        ("candidate-exact", "exact", 4092, 4, True),
        ("prior-excess", "excess", 4093, 2, False),
        ("candidate-excess", "excess", 4093, 3, False),
    ]
    result = {
        "passed": False,
        "capstone_version": capstone.__version__,
        "source_sha256": sha(Path(__file__)),
        "decoder_source_sha256": sha(Path(__file__).with_name("verify_vm_native_region_decode.py")),
        "corpus_report_sha256": sha(corpus_path),
        "head_records": 0,
        "executed_records": 0,
        "runs": [],
    }
    exact = None
    for label, binary_label, initial, added, complete in cases:
        directory = args.build_dir / ("native-extension-sdk-v3-" + label)
        binary = args.build_dir / "native-extension-fixture-v3" / binary_label
        raw = binary.read_bytes()
        assert sha(binary) == inputs[binary_label]["sha256"]
        assert inputs[binary_label]["native_exit_codes"] == [0, 0, 0]
        receipt = json.loads((directory / "run.json").read_text())
        assert receipt["runner_return_code"] == 0 and receipt["artifacts_unchanged"]
        assert receipt["input_sha256"] == sha(binary)
        capture = json.loads((directory / "native_extension_quota.json").read_text())
        assert not capture["errors"] and all(row["passed"] for row in capture["records"])
        assert len(capture["captures"]) == 2
        for trace in capture["captures"].values():
            heads, executed = audit(trace, raw, initial, added, complete)
            result["head_records"] += heads
            result["executed_records"] += executed
            if label == "candidate-exact":
                exact = trace, raw
        result["runs"].append(
            {
                "label": label,
                "input_sha256": sha(binary),
                "capture_sha256": sha(directory / "native_extension_quota.json"),
                "receipt_sha256": sha(directory / "run.json"),
                "plugin_sha256": receipt["plugin_sha256"],
                "initial_heads": initial,
                "added_heads": added,
                "complete": complete,
            }
        )
    assert exact is not None
    refuted = 0
    for control in range(4):
        trace = copy.deepcopy(exact[0])
        if control == 0:
            trace["heads"][0]["bytes"] = "90"
        elif control == 1:
            trace["heads"].pop()
        elif control == 2:
            trace["execution"][4]["site"] = trace["execution"][0]["site"]
        else:
            trace["reached_sentinel"] = False
        try:
            audit(trace, exact[1], 4092, 4, True)
        except AssertionError:
            refuted += 1
    assert refuted == 4
    result["refuted_controls"] = refuted
    result["passed"] = True
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
