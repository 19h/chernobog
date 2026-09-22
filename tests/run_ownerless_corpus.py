"""Measure fixed seed-0/1 ownerless roots; reserved protector seed is evaluation-only."""

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM
from run_vmp_corpus import digest, execute
from verify_vm_native_region_decode import segments

# Frozen before running the new API. Interior roots are separate diagnostic
# subregions; they do not replace the larger post-call graph's budget failure.
ROOTS = {
    "combined-0": (
        ("corpus_transform", 0x10001AF24, "post-call", 35),
        ("corpus_transform", 0x1000BD693, "interior direct target", 12),
        ("corpus_branch", 0x1000AB676, "post-call", 97),
        ("corpus_branch", 0x100125DE2, "interior direct target", 48),
    ),
    "combined-1": (("corpus_branch", 0x1000911BF, "post-call", 35),),
}
BASELINES = Path("build/vmp-condition-corpus-x64")
SOURCES = (
    "tests/run_ownerless_corpus.py",
    "tests/ida_ownerless_corpus_probe.py",
    "tests/run_ida_smoke.py",
    "tests/run_vmp_corpus.py",
    "tests/verify_vm_native_region_decode.py",
    "src/ida_analysis/x86_analysis.cpp",
    "src/ida_analysis/x86_analysis.hpp",
    "src/common/bounded_dataflow.h",
    "src/common/x86_abstract.h",
    "src/ida_analysis/native_engine.cpp",
    "src/plugin/idc_api.cpp",
)


def baseline(corpus_path):
    corpus = json.loads(corpus_path.read_text())
    assert corpus["passed"] and not corpus["smoke"] and corpus["architecture"] == "x86_64"
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    plan = {
        "schema": 1,
        "scope": "five fixed development roots in two archived x64 protected binaries; no held-out selection or whole-function recovery",
        "capstone_version": capstone.__version__,
        "corpus_report_sha256": digest(corpus_path),
        "protector_sha256": corpus["protector_sha256"],
        "source_build_attestation": corpus["source_build_attestation"],
        "reference_source_sha256": corpus["reference_source_sha256"],
        "baseline_traversal": "existing archived ownerless heads; decode both architectural direct successors; normal-return call continuation; stop at RET, indirect JMP or BSWAP16; no state proof or execution",
        "cases": {},
    }
    for label, requests in ROOTS.items():
        item = next(row for row in corpus["protection"] if row["label"] == label)
        assert item["protector_seed"] in (0, 1)
        binary = corpus_path.parent / label
        assert digest(binary) == item["sha256"]
        raw = binary.read_bytes()
        mappings = segments(raw)
        archived_path = BASELINES / (label + "-off") / "conditions_corpus.json"
        archived_run = archived_path.parent / "run.json"
        archived = json.loads(archived_path.read_text())
        run = json.loads(archived_run.read_text())
        assert archived["passed"] and not archived["errors"]
        assert run["input_sha256"] == item["sha256"]
        frozen = {
            "binary_sha256": item["sha256"],
            "protector_seed": item["protector_seed"],
            "baseline_capture_sha256": digest(archived_path),
            "baseline_run_sha256": digest(archived_run),
            "baseline_plugin_sha256": run["plugin_sha256"],
            "baseline_condition_lowering": sum(
                sum(owner.get("generated", {}).get("codegen_delta", {}).values())
                for owner in archived["owners"]
            ),
            "roots": [],
        }
        retained_heads = {}
        for name, root, selection, expected_nodes in requests:
            entry = archived["entries"][name]
            assert not entry["truncated"] and not entry["xref_limit_reached"]
            rows = {row["ea"]: row for row in entry["instructions"]}
            pending, seen, frontiers, conditions = [root], set(), [], []
            while pending:
                ea = pending.pop()
                if ea in seen:
                    continue
                assert len(seen) < 4096 and ea in rows
                row = rows[ea]
                encoded = bytes.fromhex(row["bytes"])
                assert row["is_code"] and row["owner"] is None
                matches = [
                    raw[offset + ea - va : offset + ea - va + len(encoded)]
                    for va, offset, size in mappings
                    if va <= ea and ea + len(encoded) <= va + size
                ]
                assert matches == [encoded]
                instruction = next(cs.disasm(encoded, ea), None)
                assert instruction and instruction.size == row["size"] == len(encoded)
                seen.add(ea)
                retained_heads[ea] = {"site": hex(ea), "size": row["size"], "bytes": row["bytes"]}
                mnemonic = instruction.mnemonic
                conditional = mnemonic.startswith("j") and mnemonic != "jmp"
                if row["kind"] or conditional:
                    conditions.append({"site": hex(ea), "kind": row["kind"] or "jcc"})
                stop = (
                    "return"
                    if mnemonic.startswith("ret")
                    else (
                        "indirect"
                        if mnemonic == "jmp" and instruction.operands[0].type != X86_OP_IMM
                        else (
                            "bswap16"
                            if mnemonic == "bswap" and instruction.operands[0].size == 2
                            else None
                        )
                    )
                )
                if stop:
                    frontiers.append({"site": hex(ea), "kind": stop, "bytes": row["bytes"]})
                elif mnemonic == "jmp":
                    pending.append(instruction.operands[0].imm)
                elif conditional:
                    assert instruction.operands[0].type == X86_OP_IMM
                    pending.extend((instruction.operands[0].imm, ea + instruction.size))
                else:
                    pending.append(ea + instruction.size)
            assert len(seen) == expected_nodes
            frozen["roots"].append(
                {
                    "root": hex(root),
                    "selected_entry": name,
                    "selection": selection,
                    "nodes": [hex(ea) for ea in sorted(seen)],
                    "node_count": len(seen),
                    "node_limit_exceeded": len(seen) > 64,
                    "condition_sites": sorted(row["site"] for row in conditions),
                    "conditions": sorted(conditions, key=lambda row: row["site"]),
                    "frontiers": sorted(frontiers, key=lambda row: row["site"]),
                }
            )
        frozen["heads"] = [retained_heads[ea] for ea in sorted(retained_heads)]
        frozen["admitted_condition_sites"] = sorted(
            {
                site
                for root in frozen["roots"]
                if not root["node_limit_exceeded"]
                for site in root["condition_sites"]
            }
        )
        assert frozen["baseline_condition_lowering"] == 0
        plan["cases"][label] = frozen
    assert sum(len(case["admitted_condition_sites"]) for case in plan["cases"].values()) == 5
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-report", type=Path, required=True)
    parser.add_argument("--ida", type=Path)
    parser.add_argument("--plugin", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--frozen-plan", type=Path)
    args = parser.parse_args()
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=False)
    plan = baseline(args.corpus_report)
    if args.frozen_plan:
        assert json.loads(args.frozen_plan.read_text()) == plan
    plan_path = output / "ownerless_corpus_plan.json"
    plan_path.write_text(json.dumps(plan, indent=2) + "\n")
    if args.prepare_only:
        print(
            json.dumps(
                {
                    "prepared": True,
                    "roots": 5,
                    "distinct_bounded_condition_sites": 5,
                    "plan_sha256": digest(plan_path),
                }
            )
        )
        return 0
    assert args.ida and args.plugin
    source_hashes = {path: digest(path) for path in SOURCES}
    report = {
        "schema": 1,
        "passed": False,
        "scope": plan["scope"],
        "plan_sha256": digest(plan_path),
        "source_sha256": source_hashes,
        "plugin_sha256": digest(args.plugin),
        "ida_sha256": digest(args.ida),
        "runs": [],
    }
    try:
        for label, frozen in plan["cases"].items():
            destination = output / label
            measurement, _, _ = execute(
                [
                    sys.executable,
                    "-B",
                    "tests/run_ida_smoke.py",
                    args.corpus_report.parent / label,
                    "tests/ida_ownerless_corpus_probe.py",
                    "--ida",
                    args.ida,
                    "--plugin",
                    args.plugin,
                    "--output-dir",
                    destination,
                    "--set",
                    "CHERNOBOG_OWNERLESS_PLAN_FILE=" + str(plan_path.resolve()),
                    "--set",
                    "CHERNOBOG_OWNERLESS_CASE=" + label,
                    "--set",
                    "CHERNOBOG_IDA_CONDITION_CODEGEN=0",
                ],
                timeout=180,
            )
            item = {"label": label, "measurement": measurement}
            report["runs"].append(item)
            assert (
                measurement["exit_code"] == 0
                and not measurement["timed_out"]
                and not measurement["output_exceeded"]
            )
            run = json.loads((destination / "run.json").read_text())
            capture = json.loads((destination / "ownerless_corpus.json").read_text())
            assert (
                run["runner_return_code"] == 0
                and run["artifacts_unchanged"]
                and run["source_script_unchanged"]
            )
            assert (
                run["input_sha256"] == frozen["binary_sha256"]
                and run["plugin_sha256"] == report["plugin_sha256"]
                and run["ida_sha256"] == report["ida_sha256"]
            )
            assert capture["passed"] and not capture["errors"]
            rows = [row for root in capture["roots"] for row in root["current"]["records"]]
            item.update(
                checks=len(capture["checks"]),
                records=len(rows),
                status_counts=dict(Counter(row["status"] for row in rows)),
                kind_counts=dict(Counter(row["kind"] for row in rows)),
                distinct_proved_conditions=sorted(
                    {
                        row["site"]
                        for row in rows
                        if row["status"] == "proved" and row["kind"] != "push-return"
                    }
                ),
                graph_reasons=dict(Counter(root["current"]["reason"] for root in capture["roots"])),
                frontiers=dict(
                    Counter(
                        edge["reason"]
                        for root in capture["roots"]
                        for edge in root["current"]["edges"]
                        if edge["kind"] == "frontier"
                    )
                ),
                microcode_lowering_delta=capture["codegen_delta"],
                artifact_sha256={
                    name: digest(destination / name)
                    for name in ("run.json", "ownerless_corpus.json")
                },
            )
            print(
                json.dumps(
                    {
                        key: item[key]
                        for key in (
                            "label",
                            "checks",
                            "status_counts",
                            "graph_reasons",
                            "distinct_proved_conditions",
                        )
                    }
                ),
                flush=True,
            )
        assert all(digest(path) == expected for path, expected in source_hashes.items())
        assert (
            digest(args.plugin) == report["plugin_sha256"]
            and digest(args.ida) == report["ida_sha256"]
        )
        assert baseline(args.corpus_report) == plan
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__
    finally:
        (output / "ownerless_corpus_analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "runs": len(report["runs"]),
                "failure": report.get("failure"),
            }
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(type(error).__name__, file=sys.stderr)
        sys.exit(1)
