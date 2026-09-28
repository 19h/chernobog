"""Verify archived paired register-logic and protected-regression reports."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path

NEW = (
    "rl_and_zero",
    "rl_or_nonzero",
    "rl_xor_sign",
    "rl_test_zero",
    "rl_test_nonzero",
    "rl_and_chain",
    "rl_or_chain",
    "rl_xor_chain",
    "rl_self_and",
    "rl_two_and",
    "rl_two_or",
    "rl_two_xor",
    "rl_two_test",
)
STABLE = ("rl_self_xor",)
UNKNOWN = ("rl_test_unknown", "rl_or_unknown", "rl_two_test_unknown")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(archive, root):
    capture = json.loads(gzip.decompress(archive.read_bytes()))
    assert capture["schema"] == 1
    assert len(capture["linux32_image_id"]) == 71
    assert capture["linux32_image_id"].startswith("sha256:")
    for name, expected in capture["sources"].items():
        assert digest(root / name) == expected, name
    current_plugin = None
    for architecture in ("x86_64", "i386"):
        pair = capture["architectures"][architecture]
        assert pair["native_stdout"] == "register logic native PASS: 330752 results\n"
        assert len(pair["binary_sha256"]) == 64
        prior, current = pair["prior"], pair["current"]
        assert prior["run"]["plugin_sha256"] != current["run"]["plugin_sha256"]
        for profile, item in (("prior", prior), ("current", current)):
            run, probe = item["run"], item["probe"]
            assert run["input_sha256"] == pair["binary_sha256"]
            assert run["script_sha256"] == capture["sources"]["tests/ida_register_logic_probe.py"]
            assert run["ida_sha256"] == capture["ida_sha256"]
            assert run["process_return_code"] == run["runner_return_code"] == 0
            assert run["artifacts_unchanged"] and run["expected_log_found"]
            assert not run["internal_error_found"]
            assert probe["passed"] and not probe["errors"]
            for name in NEW + STABLE + UNKNOWN:
                rows = probe["captures"][name]["records"]
                proofs = [
                    row
                    for row in rows
                    if row["kind"] == "setcc-value"
                    and row["truth"] == "native-proof"
                    and row["fresh"] == "true"
                ]
                expected = int(name in STABLE or (profile == "current" and name in NEW))
                assert len(proofs) == expected, (architecture, profile, name)
                assert all(row["value"] == "0x1" and row["width_bits"] == "8" for row in proofs)
        assert prior["run"]["input_sha256"] == current["run"]["input_sha256"]
        assert prior["run"]["ida_sha256"] == current["run"]["ida_sha256"]
        if current_plugin is None:
            current_plugin = current["run"]["plugin_sha256"]
        else:
            assert current_plugin == current["run"]["plugin_sha256"]
    for architecture in ("x86_64", "i386"):
        regression = capture["status_regressions"][architecture]
        assert regression["run"]["plugin_sha256"] == current_plugin
        assert regression["probe"]["passed"] and not regression["probe"]["errors"]
    protected = capture["protected_97"]
    assert protected["run"]["plugin_sha256"] == current_plugin
    assert protected["run"]["runner_return_code"] == 0
    assert not protected["probe"]["errors"]
    assert all(row["passed"] for row in protected["probe"]["checks"])
    assert len(protected["probe"]["inspection"]["nodes"]) == 97
    assert len(protected["probe"]["inspection"]["records"]) == 4
    assert protected["independent"]["passed"]
    assert protected["independent"]["node_count"] == 97
    assert protected["independent"]["proved_condition_sites"] == 0
    return capture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    arguments = parser.parse_args()
    result = verify(arguments.archive, arguments.root)
    print("register logic archive PASS:", len(result["architectures"]), "architectures")


if __name__ == "__main__":
    main()
