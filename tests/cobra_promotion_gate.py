"""Fail closed unless all six native runtime reports satisfy the frozen gates."""

from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def require(value, message):
    if not value:
        raise ValueError(message)


def embedded_revision_matches(embedded, full):
    return (
        isinstance(embedded, str)
        and re.fullmatch(r"[0-9a-f]{12,40}", embedded) is not None
        and full.startswith(embedded)
    )


def d810_probes():
    return (
        {
            ("memory", name, fault)
            for name in ("test_chained_add", "test_cst_simplification")
            for fault in range(23)
        }
        | {
            ("control", name, fault)
            for name in (
                "single_iteration_simple",
                "abc_f6_add_dispatch",
                "nested_simple",
                "while_switch_flattened",
            )
            for fault in range(18)
        }
        | {
            ("negative-control", name, 16 if name == "d810_control_volatile" else -1)
            for name in (
                "d810_control_dynamic",
                "d810_control_switch",
                "d810_control_volatile",
                "d810_control_cycle",
                "d810_control_escape",
            )
        }
    )


def verify_d810(report, native, sdk):
    rows = report["rows"]
    require(
        {(r["route"], r["function"], r["fault"]) for r in rows} == d810_probes()
        and len(rows) == 123,
        "Supplemental D810 matrix incomplete",
    )
    require(
        not report["failures"] and all(not r["code"] and r["passed"] for r in rows),
        "Supplemental D810 probe failed",
    )
    for row in rows:
        positive = row["route"] != "negative-control" and row["fault"] == 0
        require(
            (
                (row["changes"] > 0 and not row["unchanged"])
                if positive
                else (row["changes"] == 0 and row["unchanged"])
            ),
            "Supplemental D810 mutation contract failed",
        )
        if row["route"] != "negative-control" and row["fault"] in (14, 15):
            require(row["post_poll"], "Supplemental post-proof fault was not reached")
    literals = report["literals"]
    require(
        {r["input32"] for r in literals} == {0xFFFFFFFF, 0x80000000, 0xADC07CB7}
        and len(literals) == 3
        and all(
            not r["code"]
            and r["text"]
            and r["expected64"] == ((r["input32"] - (1 << 32)) & ((1 << 64) - 1))
            for r in literals
        ),
        "Supplemental signed-literal matrix failed",
    )
    require(
        embedded_revision_matches(report["revision"], native["revision"])
        and all(report["source_fingerprint"] == r["source_fingerprint"] for r in sdk["reports"]),
        "Supplemental source provenance differs",
    )
    require(
        all(
            report[key] == sdk[key]
            for key in ("kernel_version", "hexrays_version", "system", "machine")
        ),
        "Supplemental native runtime differs",
    )
    for stem, expected in (
        ("chernobog_mba_d810_sdk_bridge.", report["bridge_sha256"]),
        ("chernobog_mba_d810_runtime_fixture", native["d810"]["fixture_sha256"]),
    ):
        hashes = [
            value
            for name, value in native["bundle"]["files"].items()
            if name.startswith(stem) and not name.endswith(".pdb")
        ]
        require(hashes == [expected], "Supplemental artifact identity mismatch")
    require(
        native["d810"]["cases"] == 123 and native["d810"]["literals"] == 3,
        "Supplemental native receipt incomplete",
    )


def distribution(values):
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "min": ordered[0],
        "p50": ordered[(50 * len(ordered) + 99) // 100 - 1],
        "p95": ordered[(95 * len(ordered) + 99) // 100 - 1],
        "max": ordered[-1],
    }


def verify(directory):
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    tree = re.search(
        r'COBRA_EXPECTED_TREE_HASH "([0-9a-f]+)"',
        (ROOT / "vendor/cobra.provenance.cmake").read_text(),
    ).group(1)
    manifest_path = ROOT / "tests/fixtures/mba_cobra_positive_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    expected = {f["id"]: f for f in manifest["fixtures"]}
    runtimes = json.loads((ROOT / "tests/fixtures/ida_cobra_runtime_manifest.json").read_text())
    require(runtimes["status"] == "checksums_frozen", "Installer fingerprints must be frozen")
    targets = {r["target"]: r for r in runtimes["runtimes"]}
    legacy_path = ROOT / "tests/fixtures/mba_cobra_legacy_manifest.json"
    legacy = json.loads(legacy_path.read_text())
    legacy_hash = hashlib.sha256(legacy_path.read_bytes()).hexdigest()
    require(
        legacy_hash == runtimes["legacy_manifest_sha256"], "Legacy manifest fingerprint changed"
    )
    for name, expected_hash in legacy["sources"].items():
        require(
            hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected_hash,
            "Legacy source fingerprint changed",
        )
    require(len(expected) == 42 and len(targets) == 6, "Frozen fixture or target set changed")
    reports = list(directory.glob("*/native.json"))
    observed = [json.loads(p.read_text()) for p in reports]
    require(
        len(observed) == 6 and {r["target"] for r in observed} == set(targets),
        "All six native reports are required",
    )
    revisions, sources, trees = set(), set(), set()
    positives = negatives = controls = 0
    measurements = []
    corpus_measurements = []
    fault_measurements = []
    for path, native in zip(reports, observed):
        target = native["target"]
        require(
            native["runtime"] == targets[target]
            and native["status"] == "passed"
            and native["collection_mode"] == "full",
            f"Runtime mismatch: {target}",
        )
        require(
            native["revision"] == revision
            and native["harness_revision"] == revision
            and native["bundle"]["revision"] == revision
            and native["bundle"]["target"] == target,
            "Evidence revision/bundle target differs from gate checkout",
        )
        revisions.add(native["revision"])
        require(native["legacy_manifest_sha256"] == legacy_hash, "Native legacy manifest differs")
        require(
            native["native_control"]
            == {
                group: legacy["oracle_comparisons"][group]
                for group in ("nested", "masks", "semantic")
            },
            "Original native controls incomplete",
        )
        fixture_hashes = [
            digest
            for name, digest in native["bundle"]["files"].items()
            if name.startswith("chernobog_mba_cobra_runtime_fixture") and not name.endswith(".pdb")
        ]
        require(fixture_hashes == [native["fixture_sha256"]], "Native fixture identity mismatch")
        sdk = json.loads((path.parent / "sdk.json").read_text())
        require(
            not sdk["errors"] and sdk["kernel_version"].startswith(targets[target]["ida_version"]),
            f"SDK runtime failed: {target}",
        )
        require(
            sdk["system"]
            == {"macos": "Darwin", "linux": "Linux", "windows": "Windows"}[target.split("-")[0]],
            "SDK process operating system mismatch",
        )
        require(
            sdk["machine"].lower() in ("arm64", "aarch64", "x86_64", "amd64"),
            "Unsupported native process architecture",
        )
        bridge = [
            digest
            for name, digest in native["bundle"]["files"].items()
            if name.startswith("chernobog_mba_cobra_sdk_bridge.")
        ]
        require(bridge == [sdk["bridge_sha256"]], "SDK bridge artifact identity mismatch")
        arm = sdk["machine"].lower() in ("arm64", "aarch64")
        require(arm == target.endswith("arm64"), f"SDK process architecture mismatch: {target}")
        verify_d810(json.loads((path.parent / "d810-sdk.json").read_text()), native, sdk)
        runs = native["runs"]
        require(
            {r["label"] for r in runs}
            == {"sdk-cobra", "sdk-legacy", "legacy", "cobra", "d810-sdk"}
            | {
                backend + "-" + group
                for backend in ("legacy", "cobra")
                for group in ("semantic", "calls", "masks")
            }
            and len(runs) == 11,
            f"Missing paired execution: {target}",
        )
        require(
            all(
                r["artifacts_unchanged"] and r["plugin_sha256"] == sdk["plugin_sha256"]
                for r in runs
            ),
            f"Plugin artifact mismatch: {target}",
        )
        profiles = {(r["backend"], r["profile"]): r for r in sdk["reports"]}
        require(
            set(profiles)
            == {
                ("cobra", "Normal"),
                ("cobra", "Deep"),
                ("cobra", "Faults"),
                ("legacy", "Normal"),
                ("legacy", "Deep"),
            }
            and len(sdk["reports"]) == 5,
            f"Missing SDK modes: {target}",
        )
        for (backend, profile), report in profiles.items():
            require(
                embedded_revision_matches(report["revision"], native["revision"])
                and report["manifest_sha256"] == manifest_hash
                and report["boundary"] == "sdk_emitted"
                and report["vendor_tree"] == tree
                and report["failures"] == 0,
                f"Proof/source attribution failed: {target}/{backend}/{profile}",
            )
            sources.add(report["source_fingerprint"])
            trees.add(report["vendor_tree"])
            rows = report["rows"]
            if profile == "Faults":
                micro = [r for r in rows if r.get("route", "microcode") == "microcode"]
                ctree = [r for r in rows if r.get("route") == "ctree"]
                require(
                    {r["fault"] for r in micro} == set(range(20)) and len(micro) == 20,
                    f"Missing microcode faults: {target}",
                )
                require(
                    {r["fault"] for r in ctree} == set(range(12)) and len(ctree) == 12,
                    f"Missing ctree faults: {target}",
                )
                for row in rows:
                    require(
                        (row.get("kind") == "control")
                        == (row.get("route") == "ctree" and row["fault"] == 0),
                        "Legacy control identity mismatch",
                    )
                    fault_measurements.append({"target": target, **row})
                    if row.get("kind") == "control":
                        require(
                            row["passed"] and row["expected_apply"] and row["mutations"] == 1,
                            "Legacy fallback control failed",
                        )
                        controls += 1
                    else:
                        require(
                            row["rejected"] and row["mutations"] == 0, "Fault allowed IR mutation"
                        )
                        negatives += 1
                continue
            require(
                len(rows) == 42 and {r["fixture"] for r in rows} == set(expected),
                f"Fixture set mismatch: {target}/{profile}",
            )
            for row in rows:
                fixture = expected[row["fixture"]]
                require(
                    row["width"] == fixture["width"] and row["source_matches"] and row["passed"],
                    "Fixture attribution failed",
                )
                if backend == "cobra":
                    require(
                        all(
                            row[key]
                            for key in (
                                "has_candidate",
                                "candidate_unsat",
                                "emitted_unsat",
                                "frame",
                                "applied",
                            )
                        ),
                        "Both proofs and actual mutation are required",
                    )
                    for cost in ("term", "emitted"):
                        require(
                            row[cost + "_output_cost"] < row[cost + "_input_cost"],
                            "Strict cost reduction failed",
                        )
                        if fixture.get("max_cost_denominator"):
                            require(
                                fixture["max_cost_denominator"] * row[cost + "_output_cost"]
                                <= fixture["max_cost_numerator"] * row[cost + "_input_cost"],
                                "Polynomial half-cost gate failed",
                            )
                    if fixture.get("max_output_nodes"):
                        require(
                            row["output_nodes"] <= fixture["max_output_nodes"],
                            "Output node bound failed",
                        )
                    if fixture.get("canonical_support_empty"):
                        require(
                            row["output_nodes"] == 1 and row["canonical_support_empty"],
                            "Opaque constant support gate failed",
                        )
                    if fixture.get("inner_width"):
                        for width in (fixture["inner_width"], fixture["width"]):
                            require(
                                row["proved_widths"] & (1 << (width // 8)),
                                "Missing nested-width proof",
                            )
                    require(
                        row["scratch_peak_bytes"] <= manifest["profiles"][profile]["scratch_bytes"],
                        "Instrumented payload limit exceeded",
                    )
                    positives += 1
                require(
                    row["elapsed_ns"] > 0 and row["process_peak_rss_bytes"] > 0,
                    "Paired timing/RSS measurement missing",
                )
                measurements.append(
                    {"target": target, "backend": backend, "profile": profile, **row}
                )
        for backend in ("legacy", "cobra"):
            capture = json.loads((path.parent / (backend + ".json")).read_text())
            oracle = json.loads((path.parent / (backend + "-oracle.json")).read_text())
            require(
                oracle["fixture_sha256"] == legacy["sources"]["tests/vmp_native/mba_nested.c"]
                and oracle["capture_sha256"]
                == hashlib.sha256((path.parent / (backend + ".json")).read_bytes()).hexdigest(),
                "Nested oracle source/capture mismatch",
            )
            require(
                not capture["errors"] and len(capture["functions"]) == 6,
                f"Required corpus regression: {target}/{backend}",
            )
            require(
                {f["name"] for f in capture["functions"]}
                == {
                    "mba_nested_1",
                    "mba_nested_2",
                    "mba_nested_3",
                    "mba_nested_combined",
                    "mba_nested_solve",
                    "mba_nested_caller",
                },
                "Required corpus identity mismatch",
            )
            for function in capture["functions"]:
                require(set(function["statistics"]) == {"normal", "deep"}, "Missing corpus profile")
                for profile, statistics in function["statistics"].items():
                    algebraic = statistics["algebraic"]
                    corpus_measurements.append(
                        {
                            "target": target,
                            "backend": backend,
                            "profile": profile,
                            "group": "nested",
                            "function": function["name"],
                            **algebraic,
                        }
                    )
                    require(
                        algebraic["backend"] == backend and algebraic["vendor_tree"] in trees,
                        "Installed plugin backend/provenance mismatch",
                    )
                    require(
                        algebraic["process_peak_rss_bytes"] > 0,
                        "Installed plugin RSS measurement missing",
                    )

            require(
                {r["profile"] for r in oracle["results"]} == {"normal", "deep"}
                and all(
                    r["comparisons"] == 607986 and r.get("sanitizers") == ["undefined"]
                    for r in oracle["results"]
                ),
                "Independent unsigned oracle incomplete",
            )
            for group in ("semantic", "calls", "masks"):
                capture_path = path.parent / (backend + "-" + group + ".json")
                capture = json.loads(capture_path.read_text())
                oracle = json.loads(
                    (path.parent / (backend + "-" + group + "-oracle.json")).read_text()
                )
                require(
                    not capture["errors"]
                    and len(capture["functions"]) == len(legacy["groups"][group])
                    and {f["name"] for f in capture["functions"]} == set(legacy["groups"][group]),
                    f"Required {group} regression: {target}/{backend}",
                )
                profiles_expected = (
                    {"normal", "deep", "restored"} if group == "semantic" else {"normal", "deep"}
                )
                for function in capture["functions"]:
                    if group == "semantic":
                        for profile in profiles_expected:
                            statistics = function[profile]
                            corpus_measurements.append(
                                {
                                    "target": target,
                                    "backend": backend,
                                    "profile": profile,
                                    "group": group,
                                    "function": function["name"],
                                    **statistics["algebraic"],
                                }
                            )
                            require(
                                statistics["budget_ms"] == (30000 if profile == "deep" else 1000),
                                "Scoped semantic profile not restored",
                            )
                            require(
                                statistics["algebraic"]["backend"] == backend
                                and statistics["algebraic"]["vendor_tree"] == tree,
                                "Semantic backend attribution mismatch",
                            )
                    else:
                        require(
                            set(function["captures"]) == profiles_expected,
                            "Missing required capture profile",
                        )
                if group == "calls":
                    require(
                        re.search(r"\bmba_transform_2\s*\(", capture["disabled"]),
                        "Disable-option regression",
                    )
                source = (
                    "tests/vmp_native/mba_masks.c"
                    if group == "masks"
                    else "tests/vmp_native/mba_smt.c"
                )
                require(
                    oracle["fixture_sha256"] == legacy["sources"][source]
                    and oracle["capture_sha256"]
                    == hashlib.sha256(capture_path.read_bytes()).hexdigest(),
                    "Compiled oracle source/capture mismatch",
                )
                require(
                    len(oracle["results"]) == len(profiles_expected)
                    and {r["profile"] for r in oracle["results"]} == profiles_expected
                    and all(
                        r["comparisons"] == legacy["oracle_comparisons"][group]
                        and r.get("sanitizers") == ["undefined"]
                        for r in oracle["results"]
                    ),
                    "Required compiled oracle incomplete",
                )
    require(
        len(revisions) == len(sources) == len(trees) == 1, "Cross-target source provenance differs"
    )
    require(
        positives == 504 and negatives == 186 and controls == 6,
        "Complete promotion cardinality failed",
    )
    phase_distributions = []
    phase_keys = (
        "extraction_ns",
        "invocation_ns",
        "reconstruction_ns",
        "cleanup_ns",
        "generation_ns",
        "candidate_proof_ns",
        "emission_ns",
        "emitted_proof_ns",
    )
    for target in sorted(targets):
        for backend in ("legacy", "cobra"):
            for profile in ("normal", "deep", "restored"):
                selected = [
                    r
                    for r in corpus_measurements
                    if r["target"] == target and r["backend"] == backend and r["profile"] == profile
                ]
                phase_distributions.append(
                    {
                        "target": target,
                        "backend": backend,
                        "profile": profile,
                        "timing_unit": "ns",
                        "phases": {
                            key: distribution([r.get(key, 0) for r in selected])
                            for key in phase_keys
                        },
                        "applied": sum(r.get("applied", 0) for r in selected),
                        "proved": sum(r.get("proved", 0) for r in selected),
                        "max_deadline_overshoot_ns": max(
                            r.get("deadline_overshoot_ns", 0) for r in selected
                        ),
                        "max_candidate_overshoot_ns": max(
                            r.get("overshoot_ns", 0) for r in selected
                        ),
                        "peak_process_rss_bytes": max(
                            r["process_peak_rss_bytes"] for r in selected
                        ),
                    }
                )
    return {
        "schema_version": 1,
        "status": "passed",
        "revision": next(iter(revisions)),
        "source_fingerprint": next(iter(sources)),
        "vendor_tree": next(iter(trees)),
        "manifest_sha256": manifest_hash,
        "legacy_manifest_sha256": legacy_hash,
        "positive_passes": positives,
        "negative_rejections": negatives,
        "legacy_fallback_controls": controls,
        "measurements": measurements,
        "corpus_measurements": corpus_measurements,
        "phase_distributions": phase_distributions,
        "fault_measurements": fault_measurements,
        "rss_scope": "process high-water mark; instrumented payload is separately bounded",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify(args.directory)
    except (ValueError, KeyError, OSError, TypeError, StopIteration) as error:
        args.output.write_text(
            json.dumps({"schema_version": 1, "status": "failed", "error": str(error)}, indent=2)
            + "\n"
        )
        raise SystemExit(f"Promotion rejected: {error}") from None
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Promotion matrix passed: {report['positive_passes']} SDK positives; {report['negative_rejections']} fault rejections"
    )


if __name__ == "__main__":
    main()
