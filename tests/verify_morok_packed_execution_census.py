"""Retain and independently verify raw QEMU packed-section block traces."""

import argparse
from collections import Counter
import copy
import gzip
import hashlib
import json
from pathlib import Path


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_names(report):
    return ["report.json"] + [
        name + suffix
        for name in sorted(report["runs"])
        for suffix in (".trace.log", ".stdout", ".stderr")
    ]


def trace_counts(raw, begin, end):
    counts = Counter()
    first = None
    first_packed = None
    for line in raw.splitlines():
        if not line.startswith(b"Trace "):
            continue
        try:
            bracket = line.split(b" [", 1)[1].split(b"]", 1)[0]
            pc = int(bracket.split(b"/")[1], 16)
        except (IndexError, ValueError) as error:
            raise ValueError("malformed QEMU Trace record") from error
        if first is None:
            first = pc
        if first_packed is None and begin <= pc < end:
            first_packed = pc
        counts[pc] += 1
    if not counts:
        raise ValueError("no executed-block records")
    return counts, first, first_packed


def verify_files(files):
    report = json.loads(files["report.json"])
    if (
        report["schema"] != 1
        or report.get("qemu_log_options") != "exec,nochain"
        or sorted(files) != sorted(file_names(report))
    ):
        raise ValueError("archive file set or schema changed")
    if len(report["runs"]) != 6:
        raise ValueError("expected five supplied runs and one positive control")
    for name, row in report["runs"].items():
        trace = files[name + ".trace.log"]
        stdout, stderr = files[name + ".stdout"], files[name + ".stderr"]
        if sha256(trace) != row["trace_sha256"] or len(trace) != row["trace_bytes"]:
            raise ValueError(name + " trace identity changed")
        if sha256(stdout) != row["stdout_sha256"] or len(stdout) != row["stdout_bytes"]:
            raise ValueError(name + " stdout identity changed")
        if sha256(stderr) != row["stderr_sha256"] or len(stderr) != row["stderr_bytes"]:
            raise ValueError(name + " stderr identity changed")
        region = report["packed_regions"][
            "fixed_seed_positive" if name == "fixed-seed-positive" else "supplied"
        ]
        begin, end = int(region["address"], 16), int(region["end"], 16)
        counts, first, first_packed = trace_counts(trace, begin, end)
        expected = {int(pc, 16): count for pc, count in row["pc_counts"].items()}
        if counts != expected or sum(counts.values()) != row["trace_blocks"]:
            raise ValueError(name + " executed-block inventory changed")
        if len(counts) != row["unique_block_starts"] or hex(first) != row["first_trace_pc"]:
            raise ValueError(name + " trace start or unique count changed")
        packed = sum(count for pc, count in counts.items() if begin <= pc < end)
        if packed != row["packed_blocks"]:
            raise ValueError(name + " packed-section count changed")
        if (None if first_packed is None else hex(first_packed)) != row["first_packed_pc"]:
            raise ValueError(name + " first packed block changed")
        if name == "fixed-seed-positive":
            if packed <= 0 or first_packed != 0x430000:
                raise ValueError("positive control did not execute packed section")
        elif packed != 0 or first_packed is not None:
            raise ValueError(name + " unexpectedly executed packed section")
    return {
        "runs": len(report["runs"]),
        "supplied_packed_blocks": sum(
            row["packed_blocks"]
            for name, row in report["runs"].items()
            if name.startswith("supplied-")
        ),
        "positive_packed_blocks": report["runs"]["fixed-seed-positive"]["packed_blocks"],
        "report_sha256": sha256(files["report.json"]),
    }


def unpack(archive):
    data = json.loads(gzip.decompress(archive.read_bytes()))
    if data["schema"] != 1:
        raise ValueError("archive schema changed")
    return {name: value.encode("latin1") for name, value in data["files"].items()}


def mutation_check(files):
    name = "supplied-valid_v14_1.trace.log"
    raw = files[name]
    needle = b"000000000040025b"
    if needle not in raw:
        raise ValueError("mutation site absent")
    changed = dict(files)
    changed[name] = raw.replace(needle, b"00000000004c0000", 1)
    report = copy.deepcopy(json.loads(files["report.json"]))
    report["runs"]["supplied-valid_v14_1"]["trace_sha256"] = sha256(changed[name])
    changed["report.json"] = (json.dumps(report, indent=2) + "\n").encode()
    try:
        verify_files(changed)
    except ValueError as error:
        return str(error)
    raise ValueError("changed packed-section block was accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--capture-dir", type=Path)
    args = parser.parse_args()
    archive = args.archive
    if args.capture_dir is not None:
        if archive.exists():
            raise ValueError("archive output must be new")
        directory = args.capture_dir
        report = json.loads((directory / "report.json").read_text())
        files = {name: (directory / name).read_bytes() for name in file_names(report)}
        verified = verify_files(files)
        payload = json.dumps(
            {"schema": 1, "files": {name: value.decode("latin1") for name, value in files.items()}},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        archive.write_bytes(gzip.compress(payload, compresslevel=9, mtime=0))
    else:
        files = unpack(archive)
        verified = verify_files(files)
    if unpack(archive) != files:
        raise ValueError("archive round trip changed evidence bytes")
    verified["archive_sha256"] = sha256(archive.read_bytes())
    verified["mutation_rejection"] = mutation_check(files)
    print(json.dumps(verified, sort_keys=True))


if __name__ == "__main__":
    main()
