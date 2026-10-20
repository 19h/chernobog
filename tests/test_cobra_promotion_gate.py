"""Exercise promotion acceptance and reject missing native proof/corpus evidence.

Synthetic rows test the checker only; they are never native acceptance evidence.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "promotion_gate", Path(__file__).with_name("cobra_promotion_gate.py")
)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class PromotionGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        root = GATE.ROOT
        self.revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip()
        tree = re.search(
            r'COBRA_EXPECTED_TREE_HASH "([0-9a-f]+)"',
            (root / "vendor/cobra.provenance.cmake").read_text(),
        ).group(1)
        runtime = json.loads((root / "tests/fixtures/ida_cobra_runtime_manifest.json").read_text())
        positive_path = root / "tests/fixtures/mba_cobra_positive_manifest.json"
        positive = json.loads(positive_path.read_text())
        legacy_path = root / "tests/fixtures/mba_cobra_legacy_manifest.json"
        legacy = json.loads(legacy_path.read_text())
        rows = []
        for fixture in positive["fixtures"]:
            rows.append(
                dict(
                    fixture=fixture["id"],
                    width=fixture["width"],
                    source_matches=True,
                    passed=True,
                    has_candidate=True,
                    candidate_unsat=True,
                    emitted_unsat=True,
                    frame=True,
                    applied=True,
                    term_input_cost=100,
                    term_output_cost=1,
                    emitted_input_cost=100,
                    emitted_output_cost=1,
                    output_nodes=1,
                    canonical_support_empty=True,
                    proved_widths=0x1FE,
                    scratch_peak_bytes=16,
                    elapsed_ns=1,
                    process_peak_rss_bytes=4096,
                )
            )
        faults = [
            dict(route=route, fault=fault, rejected=True, mutations=0)
            for route, count in (("microcode", 20), ("ctree", 12))
            for fault in range(count)
        ]
        faults[20] = dict(
            route="ctree", fault=0, kind="control", passed=True, expected_apply=True, mutations=1
        )
        for entry in runtime["runtimes"]:
            target = entry["target"]
            directory = self.directory / target
            directory.mkdir()
            labels = ["sdk-cobra", "sdk-legacy", "legacy", "cobra"] + [
                b + "-" + g for b in ("legacy", "cobra") for g in ("semantic", "calls", "masks")
            ]
            self.write(
                directory / "native.json",
                dict(
                    target=target,
                    runtime=entry,
                    status="passed",
                    revision=self.revision,
                    harness_revision=self.revision,
                    collection_mode="full",
                    legacy_manifest_sha256=hashlib.sha256(legacy_path.read_bytes()).hexdigest(),
                    fixture_sha256="fixture",
                    native_control={
                        g: legacy["oracle_comparisons"][g] for g in ("nested", "masks", "semantic")
                    },
                    bundle=dict(
                        revision=self.revision,
                        target=target,
                        files={
                            "chernobog_mba_cobra_sdk_bridge.so": "bridge",
                            "chernobog_mba_cobra_runtime_fixture": "fixture",
                        },
                    ),
                    runs=[
                        dict(label=label, artifacts_unchanged=True, plugin_sha256="plugin")
                        for label in labels
                    ],
                ),
            )
            reports = []
            for backend, profile in (
                ("cobra", "Normal"),
                ("cobra", "Deep"),
                ("cobra", "Faults"),
                ("legacy", "Normal"),
                ("legacy", "Deep"),
            ):
                reports.append(
                    dict(
                        backend=backend,
                        profile=profile,
                        revision=self.revision[:12],
                        manifest_sha256=hashlib.sha256(positive_path.read_bytes()).hexdigest(),
                        boundary="sdk_emitted",
                        vendor_tree=tree,
                        failures=0,
                        source_fingerprint="synthetic",
                        rows=faults if profile == "Faults" else rows,
                    )
                )
            self.write(
                directory / "sdk.json",
                dict(
                    errors=[],
                    kernel_version=entry["ida_version"],
                    system={"macos": "Darwin", "linux": "Linux", "windows": "Windows"}[
                        target.split("-")[0]
                    ],
                    machine="arm64" if target.endswith("arm64") else "x86_64",
                    bridge_sha256="bridge",
                    plugin_sha256="plugin",
                    reports=reports,
                ),
            )
            for backend in ("legacy", "cobra"):
                stats = dict(
                    algebraic=dict(backend=backend, vendor_tree=tree, process_peak_rss_bytes=4096)
                )
                for group, names in legacy["groups"].items():
                    profiles = (
                        ("normal", "deep", "restored")
                        if group == "semantic"
                        else ("normal", "deep")
                    )
                    functions = []
                    for name in names:
                        function = dict(name=name)
                        if group == "nested":
                            function["statistics"] = {p: stats for p in profiles}
                        elif group == "semantic":
                            function.update(
                                {
                                    p: dict(stats, budget_ms=30000 if p == "deep" else 1000)
                                    for p in profiles
                                }
                            )
                        else:
                            function["captures"] = {p: "return 0;" for p in profiles}
                        functions.append(function)
                    label = backend if group == "nested" else backend + "-" + group
                    path = directory / (label + ".json")
                    self.write(
                        path,
                        dict(
                            errors=[],
                            functions=functions,
                            disabled="return mba_transform_2(19,19);",
                        ),
                    )
                    source = (
                        "tests/vmp_native/mba_masks.c"
                        if group == "masks"
                        else (
                            "tests/vmp_native/mba_nested.c"
                            if group == "nested"
                            else "tests/vmp_native/mba_smt.c"
                        )
                    )
                    self.write(
                        directory / (label + "-oracle.json"),
                        dict(
                            fixture_sha256=legacy["sources"][source],
                            capture_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                            results=[
                                dict(
                                    profile=p,
                                    comparisons=legacy["oracle_comparisons"][group],
                                    sanitizers=["undefined"],
                                )
                                for p in profiles
                            ],
                        ),
                    )

    def write(self, path, value):
        path.write_text(json.dumps(value))

    def mutate(self, file, edit):
        path = self.directory / "linux-x86_64" / file
        value = json.loads(path.read_text())
        edit(value)
        self.write(path, value)
        with self.assertRaises((ValueError, KeyError)):
            GATE.verify(self.directory)

    def test_complete_checker_fixture(self):
        result = GATE.verify(self.directory)
        self.assertEqual(
            (
                result["positive_passes"],
                result["negative_rejections"],
                result["legacy_fallback_controls"],
            ),
            (504, 186, 6),
        )

    def test_missing_native_target(self):
        (self.directory / "linux-arm64/native.json").unlink()
        with self.assertRaises((ValueError, KeyError)):
            GATE.verify(self.directory)

    def test_missing_post_proof_fault(self):
        self.mutate("sdk.json", lambda d: d["reports"][2]["rows"].pop(5))

    def test_wrong_destination_mutation(self):
        self.mutate("sdk.json", lambda d: d["reports"][2]["rows"][0].update(mutations=1))

    def test_missing_restored_profile(self):
        self.mutate("legacy-semantic.json", lambda d: d["functions"][0].pop("restored"))

    def test_legacy_oracle_comparison_shortfall(self):
        self.mutate("cobra-calls-oracle.json", lambda d: d["results"][0].update(comparisons=0))

    def test_capture_identity_mismatch(self):
        self.mutate("cobra-masks.json", lambda d: d["functions"][0].update(name="other"))

    def test_mixed_backend(self):
        self.mutate(
            "legacy-semantic.json",
            lambda d: d["functions"][0]["normal"]["algebraic"].update(backend="cobra"),
        )

    def test_wrong_revision(self):
        self.mutate("native.json", lambda d: d.update(revision="0" * 40))

    def test_diagnostic_probe_cannot_qualify_promotion(self):
        self.mutate("native.json", lambda d: d.update(status="diagnostic"))

    def test_wrong_harness_revision(self):
        self.mutate("native.json", lambda d: d.update(harness_revision="0" * 40))

    def test_sdk_only_probe_cannot_qualify_promotion(self):
        self.mutate("native.json", lambda d: d.update(collection_mode="sdk_only"))

    def test_wrong_embedded_revision(self):
        self.mutate("sdk.json", lambda d: d["reports"][0].update(revision="0" * 12))

    def test_too_short_embedded_revision_rejects(self):
        self.mutate("sdk.json", lambda d: d["reports"][0].update(revision=self.revision[:1]))

    def test_full_embedded_revision_also_matches(self):
        path = self.directory / "linux-x86_64/sdk.json"
        value = json.loads(path.read_text())
        value["reports"][0]["revision"] = self.revision
        self.write(path, value)
        self.assertEqual(GATE.verify(self.directory)["positive_passes"], 504)


if __name__ == "__main__":
    unittest.main()
