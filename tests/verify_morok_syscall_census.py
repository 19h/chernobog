"""Archive and independently check Morok guest syscall and process-tree traces."""

import argparse
from collections import Counter
import copy
import gzip
import hashlib
import json
from pathlib import Path
import re

SUPPLIED_SHA256 = "7d1971b1db221174caac0a5922a7452e1bebe214ca2355ab36c889a635699fd9"
POSITIVE_SHA256 = "f479ae1ab6f03857a0598d61df4674e24c787328dcec77461be532e3d962bbae"
POSITIVE_OUTPUT_SHA256 = "2ff6c69467f441be9b4db70e72dc935503171785b53d1d60f54ed290db965855"
IMAGE_ID = "sha256:a4d366ca019230fb6e3f0423bf0cbebaab63d7f32336f19ab007cb18063a7d12"
NAMES = {
    "supplied-empty",
    "supplied-bad_mathid",
    "supplied-valid_v14_1",
    "supplied-valid_v14_0",
    "supplied-default_date",
    "fixed-seed-positive",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_names():
    return ["report.json"] + [
        name + suffix for name in sorted(NAMES) for suffix in (".stdout", ".syscalls")
    ]


def parse_trace(raw, begin, end):
    records = re.findall(rb"(?<![A-Za-z_0-9])(\d+) ([a-z][a-z_0-9]*)\(", raw)
    if not records:
        raise ValueError("no guest syscall records")
    forks = [
        {"parent": int(parent), "kind": kind.decode(), "child": int(child)}
        for parent, kind, child in re.findall(
            rb"(?<![A-Za-z_0-9])(\d+) (fork|vfork)\(\) = (\d+)", raw
        )
    ]
    root = re.match(rb"(\d+) [a-z][a-z_0-9]*\(", raw)
    if root is None:
        raise ValueError("missing first guest syscall")
    guest_pids = {int(root.group(1))}
    guest_pids.update(fork["child"] for fork in forks)
    guest_pids.update(
        int(child)
        for _, child in re.findall(rb"(?<![A-Za-z_0-9])(\d+) clone\([^\n]*\) = (\d+)", raw)
    )
    calls = Counter((int(pid), name.decode()) for pid, name in records if int(pid) in guest_pids)
    protections = []
    for match in re.finditer(
        rb"(?<![A-Za-z_0-9])(\d+) mprotect\((0x[0-9a-f]+),(\d+),([A-Z_|]+)\) = (-?\d+)",
        raw,
    ):
        pid, address, length, flags, status = match.groups()
        address, length = int(address, 16), int(length)
        protections.append(
            {
                "pid": int(pid),
                "address": hex(address),
                "length": length,
                "flags": flags.decode(),
                "return_code": int(status),
                "intersects_packed": address < end and address + length > begin,
            }
        )
    if raw.count(b"mprotect(") != len(protections):
        raise ValueError("unparsed guest mprotect call")
    if raw.count(b"fork(") + raw.count(b"vfork(") != len(forks):
        raise ValueError("unparsed guest fork call")
    return {
        "syscall_records": sum(calls.values()),
        "guest_pids": sorted(guest_pids),
        "forks": forks,
        "clone_calls": sum(count for (pid, name), count in calls.items() if name == "clone"),
        "child_exits": sorted(
            pid for pid, name in calls if name == "exit" and any(f["child"] == pid for f in forks)
        ),
        "mprotect": protections,
        "packed_mprotect": [item for item in protections if item["intersects_packed"]],
    }


def verify_files(files):
    report = json.loads(files["report.json"])
    if (
        sorted(files) != sorted(file_names())
        or report["schema"] != 1
        or set(report["runs"]) != NAMES
        or report["image_id"] != IMAGE_ID
        or report["binary_sha256"]
        != {"supplied": SUPPLIED_SHA256, "fixed_seed_positive": POSITIVE_SHA256}
    ):
        raise ValueError("archive identity or file set changed")
    regions = report["packed_regions"]
    if (regions["supplied"]["address"], regions["supplied"]["end"]) != ("0x4c0000", "0x500000") or (
        regions["fixed_seed_positive"]["address"],
        regions["fixed_seed_positive"]["end"],
    ) != ("0x430000", "0x440000"):
        raise ValueError("packed-region identity changed")
    for name in sorted(NAMES):
        row = report["runs"][name]
        stdout, raw = files[name + ".stdout"], files[name + ".syscalls"]
        if sha256(stdout) != row["stdout_sha256"] or len(stdout) != row["stdout_bytes"]:
            raise ValueError(name + " stdout identity changed")
        if sha256(raw) != row["syscalls_sha256"] or len(raw) != row["syscalls_bytes"]:
            raise ValueError(name + " syscall identity changed")
        region = regions["fixed_seed_positive" if name == "fixed-seed-positive" else "supplied"]
        observed = parse_trace(raw, int(region["address"], 16), int(region["end"], 16))
        if any(row[key] != value for key, value in observed.items()):
            raise ValueError(name + " syscall inventory changed")
        expected_exit = 1 if name in ("supplied-empty", "supplied-bad_mathid") else 0
        if row["return_code"] != expected_exit or (b"Password:" in stdout) != (expected_exit == 0):
            raise ValueError(name + " process output path changed")
        if name == "fixed-seed-positive":
            packed = observed["packed_mprotect"]
            expected = [
                ("0x430000", 65536, "PROT_READ|PROT_WRITE", 0),
                ("0x430000", 65536, "PROT_EXEC|PROT_READ", 0),
            ]
            actual = [
                (item["address"], item["length"], item["flags"], item["return_code"])
                for item in packed
            ]
            if sha256(stdout) != POSITIVE_OUTPUT_SHA256 or actual != expected:
                raise ValueError("positive packed-page transition changed")
        elif observed["packed_mprotect"]:
            raise ValueError(name + " unexpectedly changed packed-page protection")
        elif not observed["forks"]:
            raise ValueError(name + " fork observations disappeared")
    return {
        "runs": len(NAMES),
        "supplied_forks": sum(
            len(row["forks"])
            for name, row in report["runs"].items()
            if name.startswith("supplied-")
        ),
        "supplied_packed_mprotect": 0,
        "positive_packed_mprotect": len(report["runs"]["fixed-seed-positive"]["packed_mprotect"]),
        "report_sha256": sha256(files["report.json"]),
    }


def unpack(archive):
    payload = json.loads(gzip.decompress(archive.read_bytes()))
    if payload["schema"] != 1:
        raise ValueError("archive schema changed")
    return {name: value.encode("latin1") for name, value in payload["files"].items()}


def mutation_check(files):
    name = "supplied-valid_v14_1"
    changed = dict(files)
    raw = (
        files[name + ".syscalls"]
        + b"1 mprotect(0x00000000004c0000,262144,PROT_READ|PROT_WRITE) = 0\n"
    )
    changed[name + ".syscalls"] = raw
    report = copy.deepcopy(json.loads(files["report.json"]))
    row = report["runs"][name]
    row["syscalls_sha256"], row["syscalls_bytes"] = sha256(raw), len(raw)
    row.update(parse_trace(raw, 0x4C0000, 0x500000))
    changed["report.json"] = (json.dumps(report, indent=2) + "\n").encode()
    try:
        verify_files(changed)
    except ValueError as error:
        return str(error)
    raise ValueError("changed packed-page syscall was accepted")


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
        files = {name: (directory / name).read_bytes() for name in file_names()}
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
