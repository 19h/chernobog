"""Replay the committed Morok caller checkpoint without ignored build files."""

import argparse
import base64
import gzip
import hashlib
import json
import tempfile
from pathlib import Path

import capstone

from verify_native_after_return import check_case, mutation_checks, sha
from verify_native_candidate_trace import elf64_load_segments

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--prior", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    evidence = json.loads(args.evidence.read_text())
    assert evidence["schema"] == 1 and evidence["passed"]
    assert sha(args.archive) == evidence["archive_base64_sha256"]
    encoded = "".join(args.archive.read_text().split())
    compressed = base64.b64decode(encoded, validate=True)
    assert base64.b64encode(compressed).decode() == encoded
    assert hashlib.sha256(compressed).hexdigest() == evidence["archive_gzip_sha256"]
    expanded = gzip.decompress(compressed)
    assert b"/Users/" not in expanded
    payload = json.loads(expanded)
    assert payload["schema"] == 1 and len(payload["cases"]) == 2
    assert sha(args.prior) == payload["prior_archive_sha256"] == evidence["prior_archive_sha256"]
    prior = json.loads(gzip.decompress(args.prior.read_bytes()))
    assert prior["schema"] == 1 and len(prior["captures"]) == 2
    assert hashlib.sha256(bytes.fromhex(prior["binary_hex"])).hexdigest() == prior["binary_sha256"]
    for name, expected in evidence["sources_sha256"].items():
        assert sha(ROOT / name) == expected
    assert capstone.__version__ == evidence["capstone_version"]
    assert sha(Path(capstone.__file__)) == evidence["capstone_binding_sha256"]
    assert sha(Path(capstone._cs._name)) == evidence["capstone_library_sha256"]

    binary = bytes.fromhex(prior["binary_hex"])
    segments = elf64_load_segments(binary)
    cases = []
    with tempfile.TemporaryDirectory(prefix="chernobog-after-return-") as temporary:
        root = Path(temporary)
        for old, new in zip(prior["captures"], payload["cases"]):
            label = new["variant"]
            assert (old["variant"], label) in (("first", "v14-1"), ("second", "v14-0"))
            directory = root / label
            directory.mkdir()
            input_path = directory / "input.bin"
            post_path = directory / "post.json"
            ida_path = directory / "after_return_probe.json"
            for path, value in (
                (input_path, old["input_hex"]),
                (post_path, old["post_hex"]),
                (ida_path, new["ida_hex"]),
                (directory / "run.json", new["run_hex"]),
                (directory / "after_return_shadow.bin", new["shadow_hex"]),
            ):
                path.write_bytes(bytes.fromhex(value))
            cases.append(check_case(binary, segments, input_path, post_path, ida_path))
            if label == "v14-1":
                mutations = mutation_checks(binary, segments, input_path, post_path, ida_path)
    assert cases == evidence["verification"]["cases"]
    assert mutations == evidence["verification"]["mutations_rejected"]
    assert evidence["verification"]["passed"]
    assert evidence["verification"]["binary_sha256"] == prior["binary_sha256"]
    assert evidence["verification"]["scope"].endswith("no observed post-return process trace")
    print("Morok after-return archive verification: pass")


if __name__ == "__main__":
    main()
