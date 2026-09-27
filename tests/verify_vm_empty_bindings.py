"""Package and recheck empty-binding temporal traces from supplied Morok ELFs."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INPUTS = {
    "boo": (
        "samples/boo-linux-x86_64-static",
        "730f6adfba4cb7179320c96a3a5b24856059f1c4ba24bad25b969d74e4054a27",
    ),
    "keygen": (
        "samples/int_woma_keygen-linux-x86_64-static",
        "7d1971b1db221174caac0a5922a7452e1bebe214ca2355ab36c889a635699fd9",
    ),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate(label, runner, report, plugin_hash, ida_hash, probe_hash):
    assert runner["runner_return_code"] == 0 and runner["process_return_code"] == 0
    assert runner["artifacts_unchanged"] and runner["source_script_unchanged"]
    assert runner["input_sha256"] == INPUTS[label][1]
    assert runner["plugin_sha256"] == plugin_hash and runner["ida_sha256"] == ida_hash
    assert runner["script_sha256"] == probe_hash and runner["enable_rax"]
    assert report["passed"] and not report["errors"] and len(report["checks"]) == 10
    assert len({row["case"] for row in report["checks"]}) == 10
    assert all(row["passed"] for row in report["checks"])
    assert report["source"]["bytes"] == "4831ed4889e7488d3598fdbfff4883e4"
    for trace in report["traces"].values():
        assert trace["available"] and trace["ran"] and trace["native_temporal_requested"]
        assert trace["environment_bindings"] == [] and trace["instruction_count"] == 33
        assert not trace["native_temporal_prefix_complete"]
        assert not trace["function_evidence_published"] and not trace["vm_identity_proved"]


def package(args):
    assert args.ida and args.plugin and args.boo_dir and args.keygen_dir
    plugin_hash = digest(args.plugin.read_bytes())
    ida_hash = digest(args.ida.read_bytes())
    probe_hash = digest((ROOT / "tests/ida_vm_empty_bindings_probe.py").read_bytes())
    archive = {"schema": 1, "artifacts": {}}
    outcomes = {}
    for label in INPUTS:
        directory = getattr(args, label + "_dir")
        runner_bytes = (directory / "run.json").read_bytes()
        report_bytes = (directory / "vm_empty_bindings.json").read_bytes()
        runner = json.loads(runner_bytes)
        report = json.loads(report_bytes)
        assert digest((ROOT / INPUTS[label][0]).read_bytes()) == INPUTS[label][1]
        validate(label, runner, report, plugin_hash, ida_hash, probe_hash)
        archive["artifacts"][label] = {
            "run.json": runner_bytes.decode(),
            "report.json": report_bytes.decode(),
        }
        outcomes[label] = {
            "binary": INPUTS[label][0],
            "binary_sha256": INPUTS[label][1],
            "runner_sha256": digest(runner_bytes),
            "report_sha256": digest(report_bytes),
            "checks": 10,
        }
    encoded = json.dumps(archive, sort_keys=True, separators=(",", ":")).encode()
    assert b"/Users/" not in encoded and b"/Applications/" not in encoded
    args.archive.write_bytes(gzip.compress(encoded, mtime=0))
    evidence = {
        "schema": 1,
        "passed": True,
        "scope": "empty temporal VM bindings in two actual IDA static ELF captures",
        "plugin_sha256": plugin_hash,
        "ida_sha256": ida_hash,
        "probe_sha256": probe_hash,
        "runner_source_sha256": digest((ROOT / "tests/run_ida_smoke.py").read_bytes()),
        "verifier_sha256": digest(Path(__file__).read_bytes()),
        "archive_sha256": digest(args.archive.read_bytes()),
        "outcomes": outcomes,
    }
    args.evidence.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")


def verify(args):
    evidence = json.loads(args.evidence.read_text())
    assert evidence["passed"] and evidence["schema"] == 1
    assert digest(Path(__file__).read_bytes()) == evidence["verifier_sha256"]
    assert digest(args.archive.read_bytes()) == evidence["archive_sha256"]
    archive = json.loads(gzip.decompress(args.archive.read_bytes()))
    assert archive["schema"] == 1
    assert set(archive["artifacts"]) == set(evidence["outcomes"]) == set(INPUTS)
    for label, data in archive["artifacts"].items():
        outcome = evidence["outcomes"][label]
        runner_bytes, report_bytes = data["run.json"].encode(), data["report.json"].encode()
        assert digest(runner_bytes) == outcome["runner_sha256"]
        assert digest(report_bytes) == outcome["report_sha256"]
        assert outcome["binary"] == INPUTS[label][0]
        assert outcome["binary_sha256"] == INPUTS[label][1] and outcome["checks"] == 10
        validate(
            label,
            json.loads(runner_bytes),
            json.loads(report_bytes),
            evidence["plugin_sha256"],
            evidence["ida_sha256"],
            evidence["probe_sha256"],
        )
    print(json.dumps({"passed": True, "checks": 20}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("boo-dir", "keygen-dir", "ida", "plugin", "archive", "evidence"):
        parser.add_argument("--" + name, type=Path, required=name in ("archive", "evidence"))
    args = parser.parse_args()
    if args.boo_dir or args.keygen_dir:
        package(args)
    verify(args)


if __name__ == "__main__":
    main()
