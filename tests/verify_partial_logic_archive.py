"""Verify archived matched native and fresh-IDA partial-logic observations."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path

POSITIVE = ("pl_or_chain", "pl_xor_chain", "pl_or_flags")
NEGATIVE = ("pl_or_unknown", "pl_xor_unknown")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(archive, root):
    capture = json.loads(gzip.decompress(archive.read_bytes()))
    assert capture["schema"] == 1
    assert capture["linux32_runtime"]["image_id"].startswith("sha256:")
    assert len(capture["linux32_runtime"]["image_id"]) == 71
    assert all(len(value) == 64 for value in capture["linux32_runtime"]["sha256"].values())
    for name, expected in capture["sources"].items():
        assert digest(root / name) == expected, name
    for architecture in ("x86_64", "i386"):
        pair = capture["architectures"][architecture]
        assert pair["native_stdout"] == "partial logic native PASS: 1280 results\n"
        assert len(pair["binary_sha256"]) == 64
        before = pair["prior"]
        after = pair["current"]
        assert before["run"]["plugin_sha256"] != after["run"]["plugin_sha256"]
        for label, item in (("prior", before), ("current", after)):
            run, probe = item["run"], item["probe"]
            assert run["input_sha256"] == pair["binary_sha256"]
            assert run["script_sha256"] == capture["sources"]["tests/ida_partial_logic_probe.py"]
            assert run["ida_sha256"] == capture["ida_sha256"]
            assert run["runner_return_code"] == run["process_return_code"] == 0
            assert run["artifacts_unchanged"] and run["expected_log_found"]
            assert not run["internal_error_found"]
            assert probe["passed"] and not probe["errors"]
            for name in POSITIVE + NEGATIVE:
                rows = probe["captures"][name]["records"]
                proofs = [
                    row
                    for row in rows
                    if row["kind"] == "setcc-value"
                    and row["truth"] == "native-proof"
                    and row["fresh"] == "true"
                ]
                expected = int(label == "current" and name in POSITIVE)
                assert len(proofs) == expected, (architecture, label, name)
                assert all(row["value"] == "0x1" and row["width_bits"] == "8" for row in proofs)
        assert before["run"]["ida_sha256"] == after["run"]["ida_sha256"]
        assert before["run"]["input_sha256"] == after["run"]["input_sha256"]
    protected = capture["protected_97"]
    assert (
        protected["run"]["plugin_sha256"]
        == capture["architectures"]["x86_64"]["current"]["run"]["plugin_sha256"]
    )
    assert protected["run"]["runner_return_code"] == 0
    assert not protected["probe"]["errors"]
    assert all(row["passed"] for row in protected["probe"]["checks"])
    assert len(protected["probe"]["inspection"]["nodes"]) == 97
    return capture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    arguments = parser.parse_args()
    result = verify(arguments.archive, arguments.root)
    print("partial logic archive PASS:", len(result["architectures"]), "architectures")


if __name__ == "__main__":
    main()
