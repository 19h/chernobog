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
    for path, native in zip(reports, observed):
        target = native["target"]
        require(
            native["runtime"] == targets[target] and native["status"] == "passed",
            f"Runtime mismatch: {target}",
        )
        require(
            native["revision"] == revision
            and native["bundle"]["revision"] == revision
            and native["bundle"]["target"] == target,
            "Evidence revision/bundle target differs from gate checkout",
        )
        revisions.add(native["revision"])
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
        runs = native["runs"]
        require(
            {r["label"] for r in runs} == {"sdk-cobra", "sdk-legacy", "legacy", "cobra"}
            and len(runs) == 4,
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
                report["revision"] == native["revision"]
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
                    {r["fault"] for r in micro} == set(range(19)) and len(micro) == 19,
                    f"Missing microcode faults: {target}",
                )
                require(
                    {r["fault"] for r in ctree} == set(range(9)) and len(ctree) == 9,
                    f"Missing ctree faults: {target}",
                )
                for row in rows:
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
                for statistics in function["statistics"].values():
                    algebraic = statistics["algebraic"]
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
    require(
        len(revisions) == len(sources) == len(trees) == 1, "Cross-target source provenance differs"
    )
    require(
        positives == 504 and negatives == 162 and controls == 6,
        "Complete promotion cardinality failed",
    )
    return {
        "schema_version": 1,
        "status": "passed",
        "revision": next(iter(revisions)),
        "source_fingerprint": next(iter(sources)),
        "vendor_tree": next(iter(trees)),
        "manifest_sha256": manifest_hash,
        "positive_passes": positives,
        "negative_rejections": negatives,
        "legacy_fallback_controls": controls,
        "measurements": measurements,
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
