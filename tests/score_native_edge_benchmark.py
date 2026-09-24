"""Score bounded native transfer reports against a frozen assembly fixture oracle.

The oracle is deliberately independent of plugin target fields. Any edit to its
assembly or execution driver requires a manual contract review and new pins.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SOURCE_PINS = {
    "tests/vmp_native/dataflow.S": "3333784f179140a7a09293266b8b0071dad45d3d03474817be83c9608f9632d5",
    "tests/vmp_native/dataflow_main.c": "bab6c278426898917bbf892c51ce15791b66c43c9b846bf1b4ed6fff1eac4a1a",
}
PROBE_PINS = {
    "tests/ida_dataflow_probe.py": "29e27cd97ce9621a3638dd384721f606c280abd3f5b958cd9aa98fa1ad1e6b1c",
    "tests/ida_ownerless_dataflow_probe.py": "4160f480e4e2462935742f8c8b1c6869117d9415eeaa5b112e624c15e1be7d69",
}

# Targets are globally named labels in dataflow.S. Each edge is one distinct
# source/target pair. These targets are fixed across the admitted input domain.
FIXED = {
    "df_stack_top_transfer": "df_stack_top_destination",
    "df_stack_top_overwrite": "df_stack_top_overwritten_destination",
    "df_memory_store_transfer": "df_memory_target",
    "df_memory_direct_store": "df_memory_target",
    "df_memory_split_store": "df_memory_target",
    "df_memory_known_byte_overwrite": "df_memory_target",
    "df_memory_repaired_byte": "df_memory_target",
    "df_memory_xchg_store": "df_memory_target",
    "df_memory_xchg_partial": "df_memory_target",
    "df_memory_xchg_byte": "df_memory_target",
    "df_memory_equal_stores": "df_memory_target",
    "df_memory_disjoint_store": "df_memory_target",
    "df_memory_overlapping_store": "df_memory_target",
    "df_memory_alu_add": "df_memory_target",
    "df_memory_alu_xor_byte": "df_memory_target",
    "df_memory_alu_source": "df_memory_target",
    "df_lods_memory_target": "df_memory_target",
    "df_memory_xchg_load": "df_memory_target",
    "df_memory_mov_load": "df_memory_target",
    "df_memory_mov_load_byte": "df_memory_target",
    "df_memory_movzx_byte": "df_memory_target",
    "df_memory_movsx_byte": "df_memory_target",
    "df_memory_movzx_word": "df_memory_target",
    "df_memory_movsx_word": "df_memory_target",
    "df_rep_movs_register_target": "df_memory_target",
    "df_movs_plain_count_target": "df_memory_target",
    "df_rep_movs_count_unknown": "df_memory_target",
    "df_stos_register_target": "df_memory_target",
    "df_rep_stos_count_target": "df_memory_target",
    "df_rep_lods_count_target": "df_memory_target",
}

# Both targets occur in the 256-input native driver. The plugin's single
# unconditional target fact cannot prove either conditional edge by itself.
DYNAMIC = {
    "df_stack_top_dynamic": (
        "df_stack_top_dynamic_seven",
        "df_stack_top_dynamic_eight",
    ),
    "df_memory_conflicting_byte": (
        "df_memory_byte_target_seven",
        "df_memory_byte_target_eight",
    ),
    "df_memory_conflicting_store": ("df_memory_target", "df_memory_target_eight"),
}

# These targets are observed under the native driver's initial image, argument,
# and disjoint-object contract. The IDA static root has no such input contract;
# neither a static success nor failure is inferred from their absence.
CONCRETE_ONLY = {
    "df_memory_missing_byte": "df_memory_target",
    "df_memory_stack_round_trip": "df_memory_target",
    "df_memory_xchg_unknown_source": "df_memory_target",
    "df_memory_initial_word": "df_memory_target",
    "df_memory_unknown_alias": "df_memory_target",
    "df_memory_alu_rmw_initial": "df_memory_target",
    "df_memory_alu_rmw_alias": "df_memory_target",
    "df_rep_movs_alias": "df_memory_target",
    "df_stos_alias": "df_memory_target",
    "df_memory_mov_load_initial": "df_memory_target",
    "df_memory_mov_load_alias": "df_memory_target",
    "df_memory_movzx_initial": "df_memory_target",
    "df_memory_movzx_alias": "df_memory_target",
    "df_memory_alu_initial": "df_memory_target",
    "df_memory_alu_alias": "df_memory_target",
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def repository_path(path):
    return str(Path(path).resolve().relative_to(ROOT))


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def symbols(nm, binary):
    result = subprocess.run(
        [str(nm), "-g", str(binary)], capture_output=True, text=True, check=True
    )
    found = {}
    for line in result.stdout.splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]+)\s+([A-Za-z])\s+(_?df_[A-Za-z0-9_]+)", line)
        if match and match.group(2).upper() in ("T", "D", "B", "S"):
            name = match.group(3).removeprefix("_")
            require(name not in found, "duplicate fixture symbol")
            found[name] = int(match.group(1), 16)
    return found


def one_record(capture, kind):
    rows = [
        row
        for row in capture["records"]
        if row["kind"] == kind and (kind != "stack-transfer" or row["fresh"] == "true")
    ]
    require(len(rows) == 1, "missing or duplicate transfer record")
    return rows[0]


def classification(row, expected, cohort, owned):
    if owned:
        proved = row["edge"] == "true"
        require(row["edge"] in ("true", "false"), "invalid edge flag")
        require(
            row["truth"] == ("native-proof" if proved else "candidate"),
            "owned proof/edge contradiction",
        )
        target = row.get("target")
    else:
        proved = row["status"] == "proved"
        require(row["status"] in ("proved", "unresolved"), "invalid ownerless status")
        target = row["target"]
    if not proved:
        require(target in (None, "unknown"), "unresolved record has a target")
        return "unresolved"
    require(target not in (None, "unknown"), "proved record lacks a target")
    target = int(target, 0)
    if cohort == "dynamic":
        # The API carries no input predicate; an unconditional single-target
        # statement contradicts a two-target native contract.
        return "false"
    return "correct" if target in expected else "false"


def load_architecture(owned_report, ownerless_report, nm, architecture):
    owned_dir = owned_report.parent / architecture
    ownerless_dir = ownerless_report.parent / architecture
    owned_report = json.loads(owned_report.read_text())
    ownerless_report = json.loads(ownerless_report.read_text())
    owned_binary = owned_dir / "dataflow"
    ownerless_binary = ownerless_dir / "ownerless"
    own_run = next(row for row in owned_report["runs"] if row["architecture"] == architecture)
    other_run = next(row for row in ownerless_report["runs"] if row["architecture"] == architecture)
    require(digest(owned_binary) == own_run["binary_sha256"], "owned binary changed")
    require(
        digest(ownerless_binary) == other_run["executions"][0]["binary_sha256"],
        "ownerless binary changed",
    )
    own_inspection = json.loads((owned_dir / "inspection/dataflow.json").read_text())
    other_inspection = json.loads(
        (ownerless_dir / "inspection/ownerless_dataflow.json").read_text()
    )
    for directory, run, binary, evidence in (
        (owned_dir, own_run, owned_binary, "dataflow.json"),
        (ownerless_dir, other_run, ownerless_binary, "ownerless_dataflow.json"),
    ):
        manifest = json.loads((directory / "inspection/run.json").read_text())
        require(manifest["input_sha256"] == digest(binary), "IDA input changed")
        require(manifest["plugin_sha256"] == owned_report["plugin_sha256"], "IDA plugin mismatch")
        require(manifest["ida_sha256"] == owned_report["ida_sha256"], "IDA mismatch")
        require(
            manifest["artifacts_unchanged"] and manifest["source_script_unchanged"],
            "IDA run identity changed",
        )
        require(
            run["artifact_sha256"]["inspection/" + evidence]
            == digest(directory / "inspection" / evidence),
            "IDA evidence hash changed",
        )
        require(
            run["artifact_sha256"]["inspection/run.json"]
            == digest(directory / "inspection/run.json"),
            "IDA run manifest hash changed",
        )
    require(not own_inspection["errors"] and not other_inspection["errors"], "IDA inspection error")
    names = set(FIXED) | set(DYNAMIC) | set(CONCRETE_ONLY)
    require(
        len(names) == len(FIXED) + len(DYNAMIC) + len(CONCRETE_ONLY), "overlapping oracle classes"
    )
    answer = {
        "architecture": architecture,
        "binary_sha256": {"owned": digest(owned_binary), "ownerless": digest(ownerless_binary)},
        "resource_scope": "outer wait4 runner process, including launch; not isolated IDA resource use",
        "resource_measurements": {
            "owned_wrapper": {
                key: own_run["inspection"][key] for key in ("elapsed_ns", "peak_resident_bytes")
            },
            "ownerless_wrapper": {
                key: other_run["inspection"][key] for key in ("elapsed_ns", "peak_resident_bytes")
            },
        },
        "counts": {},
        "cases": [],
    }
    for inspection, sym, owned in (
        (own_inspection, symbols(nm, owned_binary), True),
        (other_inspection, symbols(nm, ownerless_binary), False),
    ):
        measurements = {
            "oracle_edges": len(FIXED) + sum(map(len, DYNAMIC.values())),
            "correct_edges": 0,
            "false_edges": 0,
            "unresolved_candidates": 0,
            "concrete_only_candidates": len(CONCRETE_ONLY),
            "concrete_only_unresolved": 0,
            "concrete_only_matching_target": 0,
            "concrete_only_mismatches": 0,
        }
        for name in sorted(names):
            cohort = "fixed" if name in FIXED else "dynamic" if name in DYNAMIC else "concrete_only"
            target_names = (
                (FIXED[name],)
                if cohort == "fixed"
                else (DYNAMIC[name] if cohort == "dynamic" else (CONCRETE_ONLY[name],))
            )
            require(
                name in sym and all(target in sym for target in target_names),
                "oracle symbol absent",
            )
            capture = inspection["captures"].get(name)
            require(isinstance(capture, dict), "fixture capture absent")
            if owned:
                require(int(capture["function"], 0) == sym[name], "owned root mismatch")
                row = one_record(capture, "stack-transfer")
                published = capture["user_edges"].get(row["site"])
                require(isinstance(published, list), "missing owned user-edge inventory")
                proof_target = [row["target"]] if row["edge"] == "true" else []
                require(published == proof_target, "owned publication and proof disagree")
            else:
                facts = capture["facts"]
                require(
                    int(facts["root"], 0) == sym[name]
                    and not facts["published"]
                    and facts["available"]
                    and facts["converged"]
                    and not facts["truncated"],
                    "ownerless root incomplete",
                )
                require(
                    capture["inventory_before"] == capture["inventory_after"],
                    "ownerless inspection changed IDB",
                )
                row = one_record(facts, "push-return")
            expected = {sym[target] for target in target_names}
            require(len(expected) == len(target_names), "oracle targets collapse")
            outcome = classification(row, expected, cohort, owned)
            if cohort != "concrete_only":
                measurements[
                    outcome + ("_edges" if outcome != "unresolved" else "_candidates")
                ] += 1
            elif outcome == "unresolved":
                measurements["concrete_only_unresolved"] += 1
            elif outcome == "correct":
                # A concrete match does not validate an unconditional static edge.
                measurements["concrete_only_matching_target"] += 1
            else:
                measurements["concrete_only_mismatches"] += 1
            answer["cases"].append(
                {
                    "name": name,
                    "analysis": "owned" if owned else "ownerless",
                    "class": cohort,
                    "oracle_targets": sorted(hex(ea) for ea in expected),
                    "reported_target": row.get("target", "unknown"),
                    "owned_user_edges": published if owned else None,
                    "outcome": outcome,
                }
            )
        answer["counts"]["owned" if owned else "ownerless"] = measurements
    return answer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owned-report", required=True, type=Path)
    parser.add_argument("--ownerless-report", required=True, type=Path)
    parser.add_argument("--nm", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    for source, pinned in SOURCE_PINS.items():
        require(digest(ROOT / source) == pinned, "fixture source changed: " + source)
    for source, pinned in PROBE_PINS.items():
        require(digest(ROOT / source) == pinned, "IDA probe changed: " + source)
    owned = json.loads(args.owned_report.read_text())
    ownerless = json.loads(args.ownerless_report.read_text())
    require(owned["passed"] and ownerless["passed"], "failed input report")
    require(
        owned["plugin_sha256"] == ownerless["plugin_sha256"]
        and owned["ida_sha256"] == ownerless["ida_sha256"],
        "unmatched analysis tools",
    )
    for source in SOURCE_PINS:
        require(
            owned["source_sha256"][source] == SOURCE_PINS[source], "unmatched owned fixture source"
        )
    require(
        ownerless["source_sha256"]["tests/vmp_native/dataflow.S"]
        == SOURCE_PINS["tests/vmp_native/dataflow.S"],
        "unmatched ownerless assembly",
    )
    require(
        owned["source_sha256"]["tests/ida_dataflow_probe.py"]
        == PROBE_PINS["tests/ida_dataflow_probe.py"]
        and ownerless["source_sha256"]["tests/ida_ownerless_dataflow_probe.py"]
        == PROBE_PINS["tests/ida_ownerless_dataflow_probe.py"],
        "unmatched IDA probes",
    )
    require(
        {row["architecture"] for row in owned["runs"]} == {"x86_64", "i386"}
        and {row["architecture"] for row in ownerless["runs"]} == {"x86_64", "i386"},
        "incomplete architecture matrix",
    )
    report = {
        "schema": 1,
        "scope": "source-annotated native transfer fixtures; fixed and conditional oracle edges only",
        "oracle_source_sha256": SOURCE_PINS,
        "ida_probe_sha256": PROBE_PINS,
        "input_report_sha256": {
            repository_path(args.owned_report): digest(args.owned_report),
            repository_path(args.ownerless_report): digest(args.ownerless_report),
        },
        "plugin_sha256": owned["plugin_sha256"],
        "ida_sha256": owned["ida_sha256"],
        "nm_sha256": digest(args.nm),
        "architectures": [
            load_architecture(args.owned_report, args.ownerless_report, args.nm, architecture)
            for architecture in ("x86_64", "i386")
        ],
    }
    (output / "native_edge_benchmark.json").write_text(json.dumps(report, indent=2) + "\n")
    for item in report["architectures"]:
        print(json.dumps({"architecture": item["architecture"], "counts": item["counts"]}))


if __name__ == "__main__":
    main()
