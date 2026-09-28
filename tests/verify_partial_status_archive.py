"""Verify matched native, IDA, and protected partial-status observations."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path

POSITIVE = (
    "ps_or_nonzero",
    "ps_or_sign",
    "ps_or_parity",
    "ps_xor_sign",
    "ps_and_sign",
    "ps_test_zero",
    "ps_test_nonzero",
    "ps_test_same_sign",
)
NEGATIVE = ("ps_or_unknown", "ps_test_unknown")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(archive, root):
    capture = json.loads(gzip.decompress(archive.read_bytes()))
    assert capture["schema"] == 1
    assert capture["linux32_image_id"].startswith("sha256:")
    assert len(capture["linux32_image_id"]) == 71
    for name, expected in capture["sources"].items():
        assert digest(root / name) == expected, name
    for architecture in ("x86_64", "i386"):
        pair = capture["architectures"][architecture]
        assert pair["native_stdout"] == "partial status native PASS: 2560 results\n"
        assert len(pair["binary_sha256"]) == 64
        prior, current = pair["prior"], pair["current"]
        assert prior["run"]["plugin_sha256"] != current["run"]["plugin_sha256"]
        for profile, item in (("prior", prior), ("current", current)):
            run, probe = item["run"], item["probe"]
            assert run["input_sha256"] == pair["binary_sha256"]
            assert run["script_sha256"] == capture["sources"]["tests/ida_partial_status_probe.py"]
            assert run["ida_sha256"] == capture["ida_sha256"]
            assert run["runner_return_code"] == run["process_return_code"] == 0
            assert run["artifacts_unchanged"] and run["expected_log_found"]
            assert not run["internal_error_found"]
            assert probe["passed"] and not probe["errors"]
            locked = probe["locked_decode"]
            assert locked["size"] == 3 and locked["mnemonic"] == "test"
            assert locked["auxpref"] & 1
            assert not probe["captures"]["locked_test"]["records"]
            restored = probe["captures"]["restored"]["records"]
            assert len(restored) == int(profile == "current")
            for name in POSITIVE + NEGATIVE:
                rows = probe["captures"][name]["records"]
                proofs = [
                    row
                    for row in rows
                    if row["kind"] == "setcc-value"
                    and row["truth"] == "native-proof"
                    and row["fresh"] == "true"
                ]
                expected = int(profile == "current" and name in POSITIVE)
                assert len(proofs) == expected, (architecture, profile, name)
                assert all(row["value"] == "0x1" and row["width_bits"] == "8" for row in proofs)
        assert prior["run"]["input_sha256"] == current["run"]["input_sha256"]
        assert prior["run"]["ida_sha256"] == current["run"]["ida_sha256"]
    plugin = capture["architectures"]["x86_64"]["current"]["run"]["plugin_sha256"]
    assert capture["architectures"]["i386"]["current"]["run"]["plugin_sha256"] == plugin
    protected = capture["protected_97"]
    assert protected["run"]["plugin_sha256"] == plugin
    assert protected["run"]["runner_return_code"] == 0
    assert not protected["probe"]["errors"]
    assert all(row["passed"] for row in protected["probe"]["checks"])
    assert len(protected["probe"]["inspection"]["nodes"]) == 97
    assert len(protected["probe"]["inspection"]["records"]) == 4
    assert protected["independent"]["passed"]
    assert protected["independent"]["node_count"] == 97
    assert not protected["independent"]["proved_condition_sites"]
    regression = capture["prior_logic_regression"]
    assert regression["run"]["plugin_sha256"] == plugin
    assert regression["probe"]["passed"] and not regression["probe"]["errors"]
    return capture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    arguments = parser.parse_args()
    result = verify(arguments.archive, arguments.root)
    print("partial status archive PASS:", len(result["architectures"]), "architectures")


if __name__ == "__main__":
    main()
