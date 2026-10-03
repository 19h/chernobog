#!/usr/bin/env python3
"""Materialize the hash-pinned Morok input and prior reports for a fresh trace."""

import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prepare(prior_path, prior_evidence_path, after_path, after_evidence_path, output_dir):
    prior_bytes = prior_path.read_bytes()
    after_bytes = after_path.read_bytes()
    prior_evidence = json.loads(prior_evidence_path.read_text())
    after_evidence = json.loads(after_evidence_path.read_text())
    assert sha(prior_bytes) == prior_evidence["archive_sha256"]
    assert sha(prior_bytes) == after_evidence["prior_archive_sha256"]
    assert sha(after_bytes) == after_evidence["archive_base64_sha256"]
    prior = json.loads(gzip.decompress(prior_bytes))
    compressed = base64.b64decode(b"".join(after_bytes.split()), validate=True)
    assert sha(compressed) == after_evidence["archive_gzip_sha256"]
    after = json.loads(gzip.decompress(compressed))
    assert prior["schema"] == after["schema"] == 1
    assert len(prior["captures"]) == len(after["cases"]) == 2
    binary = bytes.fromhex(prior["binary_hex"])
    assert sha(binary) == prior["binary_sha256"] == prior_evidence["binary_sha256"]

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "protected-keygen").write_bytes(binary)
    for first, second in zip(prior["captures"], after["cases"]):
        assert (first["variant"], second["variant"]) in (
            ("first", "v14-1"),
            ("second", "v14-0"),
        )
        label = second["variant"]
        input_path = Path("tests/vmp_native/morok_keygen_" + label.replace("-", "_") + ".stdin")
        assert input_path.read_bytes() == bytes.fromhex(first["input_hex"])
        directory = output_dir / "archive" / label
        directory.mkdir(parents=True, exist_ok=True)
        for filename, content in (
            ("branch.json", first["branch_hex"]),
            ("owned.json", first["owned_hex"]),
            ("post.json", first["post_hex"]),
            ("after_return_probe.json", second["ida_hex"]),
            ("run.json", second["run_hex"]),
            ("after_return_shadow.bin", second["shadow_hex"]),
        ):
            (directory / filename).write_bytes(bytes.fromhex(content))
    print("prepared pinned binary and two archived caller cases")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior", type=Path, required=True)
    parser.add_argument("--prior-evidence", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--after-evidence", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.prior, args.prior_evidence, args.after, args.after_evidence, args.output_dir)


if __name__ == "__main__":
    main()
