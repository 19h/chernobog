"""Replay the production encoding gate against every archived closed certificate."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

import capstone


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compiler", nargs="+", default=["xcrun", "clang++"])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    assert capstone.__version__ == "5.0.7"
    compressed = args.archive.read_bytes()
    expected = json.loads((root / "docs/VMP_UNDEFINED_RESULTS_EVIDENCE.json").read_text())
    assert sha(compressed) == expected["archive"]["sha256"]
    canonical = gzip.decompress(compressed)
    assert sha(canonical) == expected["archive"]["canonical_sha256"]
    archive = json.loads(canonical)
    files = archive["files"]
    report_name = "build/undefined-final-trace/region_temporal_analysis.json"
    report = json.loads(files[report_name]["text"])
    assert report["passed"]
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True
    seen = set()
    cases = []
    for run in report["runs"]:
        name = "build/undefined-final-trace/" + run["label"] + "/region_temporal.json"
        data = files[name]["text"].encode()
        assert sha(data) == files[name]["sha256"] == run["artifact_sha256"]["region_temporal.json"]
        capture = json.loads(data)
        assert not capture["errors"]
        for trace in capture["traces"]:
            for record in trace["undefined_result_slices"]:
                key = run["label"], json.dumps(
                    {k: v for k, v in record.items() if k != "sequence"}, sort_keys=True
                )
                if key in seen:
                    continue
                seen.add(key)
                for step in record["steps"]:
                    raw = bytes.fromhex(step["bytes"])
                    decoded = list(cs.disasm(raw, int(step["site"], 16)))
                    assert len(decoded) == 1 and decoded[0].size == len(raw)
                    cases.append(
                        {
                            "label": run["label"],
                            "site": step["site"],
                            "bytes": raw.hex(),
                            "mode": 64,
                            "operands": len(decoded[0].operands),
                        }
                    )
    assert len(seen) == expected["independent_audit"]["unique_slices"]
    assert len(cases) == expected["independent_audit"]["symbolic_steps"]
    sources = [
        "src/vm/native_undefined.hpp",
        "tests/native_undefined_encoding_replay.cpp",
        "tests/verify_native_undefined_encoding.py",
    ]
    with tempfile.TemporaryDirectory(prefix="chernobog-encoding-") as temporary:
        executable = Path(temporary) / "replay"
        command = args.compiler + [
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I" + str(root / "src"),
            str(root / sources[1]),
            "-o",
            str(executable),
        ]
        subprocess.run(command, check=True, capture_output=True)
        payload = "".join(f"{c['mode']} {c['operands']} {c['bytes']}\n" for c in cases)
        completed = subprocess.run(
            [str(executable)], input=payload, text=True, capture_output=True, check=True
        )
        decisions = completed.stdout.splitlines()
        assert len(decisions) == len(cases) and all(value == "1" for value in decisions)
    result = {
        "passed": True,
        "scope": "Encoding admission only; historical symbolic dependence proofs are unchanged.",
        "archive_sha256": sha(compressed),
        "capstone_version": capstone.__version__,
        "compiler_version": subprocess.check_output(args.compiler + ["--version"], text=True),
        "source_sha256": {name: sha((root / name).read_bytes()) for name in sources},
        "unique_slices": len(seen),
        "instruction_occurrences": len(cases),
        "cases": cases,
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "cases"}, sort_keys=True))


if __name__ == "__main__":
    main()
