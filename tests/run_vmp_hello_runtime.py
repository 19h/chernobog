"""Compare the supplied original and protected Mach-O code at a printf use."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "tests/lldb_vmp_hello_snapshot.py"
INPUT_HASHES = {
    "original": "443b0a464d7de68c5a26a3e31a92e694356ccd1eef3127d522309ac672ecc7c7",
    "protected": "c61935fe4f8a66a6d36e8c0027341a55b816833005dc0006dc0fdbdb342938a5",
}
MACHO_64_MAGIC = 0xFEEDFACF
X86_64_CPU = 0x01000007
LC_SEGMENT_64 = 0x19
S_ZEROFILL = 1


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def section_map(data):
    if len(data) < 32:
        raise ValueError("short Mach-O header")
    magic, cpu, _, _, count, command_bytes, _, _ = struct.unpack_from("<8I", data)
    if magic != MACHO_64_MAGIC or cpu != X86_64_CPU:
        raise ValueError("input is not a little-endian x86-64 Mach-O")
    cursor = 32
    end = cursor + command_bytes
    if end > len(data):
        raise ValueError("load commands exceed the file")
    sections = {}
    for _ in range(count):
        if cursor + 8 > end:
            raise ValueError("incomplete load command")
        command, size = struct.unpack_from("<II", data, cursor)
        if size < 8 or cursor + size > end:
            raise ValueError("invalid load command size")
        if command == LC_SEGMENT_64:
            if size < 72:
                raise ValueError("short segment command")
            name = data[cursor + 8 : cursor + 24].split(b"\0", 1)[0]
            section_count = struct.unpack_from("<I", data, cursor + 64)[0]
            if section_count > (size - 72) // 80:
                raise ValueError("section headers exceed segment command")
            if name == b"__TEXT":
                for index in range(section_count):
                    offset = cursor + 72 + 80 * index
                    section_name = data[offset : offset + 16].split(b"\0", 1)[0]
                    if section_name not in (b"__text", b"__cstring"):
                        continue
                    address, length, file_offset = struct.unpack_from("<QQI", data, offset + 32)
                    flags = struct.unpack_from("<I", data, offset + 64)[0]
                    if section_name in sections:
                        raise ValueError("duplicate selected section")
                    sections[section_name.decode()] = {
                        "address": address,
                        "size": length,
                        "file_offset": file_offset,
                        "type": flags & 255,
                    }
        cursor += size
    if cursor != end or set(sections) != {"__text", "__cstring"}:
        raise ValueError("selected Mach-O sections are incomplete")
    return sections


def verify_snapshot(snapshot, name, sections, expected):
    if snapshot["schema"] != 1 or snapshot["target_name"] != name:
        return False
    if snapshot["stop_reason"] != "breakpoint" or "printf" not in snapshot["function"]:
        return False
    if int(snapshot["preferred_base"], 0) != 0x100000000:
        return False
    slide = int(snapshot["slide"], 0)
    if int(snapshot["loaded_base"], 0) != 0x100000000 + slide:
        return False
    for section_name, value_key, address_key in (
        ("__text", "text_hex", "text_address"),
        ("__cstring", "string_hex", "string_address"),
    ):
        info = sections[section_name]
        if int(snapshot[address_key], 0) != info["address"] + slide:
            return False
        if bytes.fromhex(snapshot[value_key]) != expected[section_name]:
            return False
    if bytes.fromhex(snapshot["window_hex"]) != expected["window"]:
        return False
    return snapshot["format_pointer"] == snapshot["string_address"]


def run_capture(lldb, binary, output, sections):
    environment = os.environ.copy()
    environment.update(
        CHERNOBOG_HELLO_TEXT_ADDRESS=hex(sections["__text"]["address"]),
        CHERNOBOG_HELLO_TEXT_SIZE=str(sections["__text"]["size"]),
        CHERNOBOG_HELLO_STRING_ADDRESS=hex(sections["__cstring"]["address"]),
        CHERNOBOG_HELLO_STRING_SIZE=str(sections["__cstring"]["size"]),
        CHERNOBOG_HELLO_SNAPSHOT_OUTPUT=str(output),
    )
    commands = [
        f"target create {binary}",
        "breakpoint set --name printf",
        "run",
        f"script exec(open({str(SNAPSHOT)!r}).read())",
        "process kill",
    ]
    process = subprocess.run(
        [lldb, "--batch", *sum((["-o", command] for command in commands), [])],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        timeout=45,
        check=False,
    )
    if process.returncode != 0 or not output.is_file():
        raise RuntimeError(
            f"LLDB capture failed for {binary.name}: "
            + (process.stdout + process.stderr)[-4096:].decode(errors="replace")
        )
    report = json.loads(output.read_text())
    return report, sha256(output.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--protected", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--lldb", default="lldb")
    args = parser.parse_args()
    paths = {"original": args.original.resolve(), "protected": args.protected.resolve()}
    images = {key: path.read_bytes() for key, path in paths.items()}
    for key, image in images.items():
        if sha256(image) != INPUT_HASHES[key]:
            raise ValueError(f"{key} sample hash differs from the pinned fixture")
    sections = {key: section_map(image) for key, image in images.items()}
    if (
        sections["original"]["__text"]["type"] == S_ZEROFILL
        or sections["original"]["__cstring"]["type"] == S_ZEROFILL
    ):
        raise ValueError("original sections are not file backed")
    if any(sections["protected"][name]["type"] != S_ZEROFILL for name in sections["original"]):
        raise ValueError("protected sections are not zero fill")
    for name in ("__text", "__cstring"):
        if (
            sections["original"][name]["address"] != sections["protected"][name]["address"]
            or sections["original"][name]["size"] != sections["protected"][name]["size"]
        ):
            raise ValueError("original/protected section geometry differs")
    expected = {}
    for name, info in sections["original"].items():
        end = info["file_offset"] + info["size"]
        if end > len(images["original"]):
            raise ValueError("original section exceeds file")
        expected[name] = images["original"][info["file_offset"] : end]
    if expected["__cstring"] != b"Hello World\0":
        raise ValueError("original literal differs from fixture contract")
    window_start = sections["original"]["__text"]["file_offset"]
    window_end = (
        sections["original"]["__cstring"]["file_offset"] + sections["original"]["__cstring"]["size"]
    )
    if window_end - window_start != 40:
        raise ValueError("unexpected original text/stub/string window")
    expected["window"] = images["original"][window_start:window_end]
    lldb = shutil.which(args.lldb)
    if lldb is None:
        raise RuntimeError("LLDB executable not found")
    version = subprocess.run([lldb, "--version"], capture_output=True, check=True, timeout=10)
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    reports = {}
    for key in ("original", "protected"):
        rows = []
        for index in range(2):
            output = output_dir / f"{key}-{index + 1}.json"
            snapshot, report_hash = run_capture(lldb, paths[key], output, sections[key])
            if not verify_snapshot(snapshot, paths[key].name, sections[key], expected):
                raise AssertionError(f"{key} runtime snapshot differs from original file bytes")
            rows.append({"report_sha256": report_hash, "snapshot": snapshot})
        reports[key] = rows
    main_mutation = copy.deepcopy(reports["protected"][0]["snapshot"])
    main_mutation["text_hex"] = "00" + main_mutation["text_hex"][2:]
    string_mutation = copy.deepcopy(reports["protected"][0]["snapshot"])
    string_mutation["string_hex"] = "00" + string_mutation["string_hex"][2:]
    checks = {
        "all_snapshots_equal_original_sections": True,
        "protected_runs_equal": reports["protected"][0]["snapshot"]["text_hex"]
        == reports["protected"][1]["snapshot"]["text_hex"]
        and reports["protected"][0]["snapshot"]["string_hex"]
        == reports["protected"][1]["snapshot"]["string_hex"],
        "main_mutation_rejected": not verify_snapshot(
            main_mutation, paths["protected"].name, sections["protected"], expected
        ),
        "string_mutation_rejected": not verify_snapshot(
            string_mutation, paths["protected"].name, sections["protected"], expected
        ),
    }
    stub_mutation = copy.deepcopy(reports["protected"][0]["snapshot"])
    stub = bytearray.fromhex(stub_mutation["window_hex"])
    stub[sections["original"]["__text"]["size"]] ^= 1
    stub_mutation["window_hex"] = stub.hex()
    checks["stub_mutation_rejected"] = not verify_snapshot(
        stub_mutation, paths["protected"].name, sections["protected"], expected
    )
    (output_dir / "runtime-window.bin").write_bytes(
        bytes.fromhex(reports["protected"][0]["snapshot"]["window_hex"])
    )
    result = {
        "schema": 1,
        "source_sha256": sha256(Path(__file__).read_bytes()),
        "snapshot_source_sha256": sha256(SNAPSHOT.read_bytes()),
        "lldb_sha256": sha256(Path(lldb).read_bytes()),
        "lldb_version": version.stdout.decode(errors="replace").splitlines()[0],
        "input_sha256": {key: sha256(image) for key, image in images.items()},
        "sections": sections,
        "expected_section_sha256": {key: sha256(value) for key, value in expected.items()},
        "reports": reports,
        "checks": checks,
        "passed": all(checks.values()),
    }
    (output_dir / "report.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not result["passed"]:
        raise AssertionError("runtime snapshot verification failed")
    print("paired VMP hello runtime section check: pass")


if __name__ == "__main__":
    main()
