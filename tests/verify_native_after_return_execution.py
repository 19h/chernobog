"""Execute the exact Morok caller byte slice as an x86-64 macOS control.

The control uses the prior process's data and stack words but executes in a
new translated host process. It does not claim same-process continuation.
"""

import argparse
import base64
import copy
import gzip
import hashlib
import json
from pathlib import Path
import platform
import struct
import subprocess
import tempfile

import lief

from verify_native_after_return import DATA_START, DEFINED_STATUS, ROOT, ZERO_STATUS
from verify_native_candidate_trace import elf64_load_segments, file_bytes
from verify_native_shadow_boundary_memory import translate
from verify_native_shadow_states import REGISTER_NAMES

ROOT_DIR = Path(__file__).resolve().parent.parent
SOURCE_C = ROOT_DIR / "tests/vmp_native/after_return_slice.c"
SOURCE_ASM = ROOT_DIR / "tests/vmp_native/after_return_slice.S"
SLICE_LENGTH = 0x41B8D0 - ROOT


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parse_output(text):
    rows = text.splitlines()
    assert len(rows) == 9
    pairs = [row.split("=", 1) for row in rows]
    assert all(len(pair) == 2 for pair in pairs)
    values = dict(pairs)
    assert list(values) == [
        "code_matched",
        "rax",
        "rbx",
        "rbp",
        "r12",
        "rsi",
        "rflags",
        "rsp_restored",
        "data",
    ]
    assert values["code_matched"] == "1"
    assert values["rsp_restored"] in ("0", "1")
    assert len(values["data"]) == 128
    for name in ("rax", "rbx", "rbp", "r12", "rsi", "rflags"):
        values[name] = int(values[name], 16)
    values["data"] = bytes.fromhex(values["data"])
    return values


def compare(post, trace, actual):
    assert actual["code_matched"] == "1"
    assert actual["rsp_restored"] == "1"
    original_sp = int(post["boundary_registers"]["rsp"], 16)
    synthetic_sp = int(trace["entry_sp"], 16)
    final = {int(row["reg"]): int(row["value"], 16) for row in trace["final_registers"]}
    assert len(final) == 18
    for name in ("rax", "rbx", "rbp", "r12", "rsi"):
        index = REGISTER_NAMES.index(name)
        value, _ = translate(final[256 + index], synthetic_sp, original_sp)
        assert value == actual[name], (name, hex(value), hex(actual[name]))
    assert actual["rflags"] & DEFINED_STATUS == final[18] & DEFINED_STATUS == ZERO_STATUS
    rbx = int(post["boundary_registers"]["rbx"], 16)
    data = bytearray.fromhex(post["boundary_data_hex"])
    start = rbx - DATA_START
    assert 0 <= start and start + 64 <= len(data)
    expected_writes = (
        (rbx + 8, bytes(16)),
        (rbx + 0x20, bytes(16)),
        (rbx + 0x38, bytes(8)),
    )
    writes = tuple(
        sorted(
            (int(row["address"], 16), bytes.fromhex(row["bytes"])) for row in trace["final_writes"]
        )
    )
    assert writes == expected_writes
    for address, value in writes:
        offset = address - DATA_START
        data[offset : offset + len(value)] = value
    assert actual["data"] == data[start : start + 64]
    return {
        "live_code_bytes_compared": SLICE_LENGTH,
        "registers_compared": 5,
        "defined_status_bits_compared": DEFINED_STATUS.bit_count(),
        "data_bytes_compared": 64,
        "stack_restored": True,
        "output_sha256": sha(actual["data"]),
    }


def rejects(action):
    try:
        action()
    except (AssertionError, KeyError, ValueError):
        return True
    return False


def check_slice(actual, expected):
    assert actual == expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--prior", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prior = json.loads(gzip.decompress(args.prior.read_bytes()))
    new = json.loads(gzip.decompress(base64.b64decode("".join(args.archive.read_text().split()))))
    assert prior["schema"] == new["schema"] == 1
    assert len(prior["captures"]) == len(new["cases"]) == 2
    assert new["prior_archive_sha256"] == sha(args.prior.read_bytes())
    binary = bytes.fromhex(prior["binary_hex"])
    assert sha(binary) == prior["binary_sha256"]
    expected_slice = file_bytes(binary, elf64_load_segments(binary), ROOT, SLICE_LENGTH)
    assert expected_slice and len(expected_slice) == 75
    with tempfile.TemporaryDirectory(prefix="chernobog-after-return-slice-") as directory:
        oracle = Path(directory) / "after-return-slice"
        command = [
            "xcrun",
            "clang",
            "-arch",
            "x86_64",
            "-O0",
            "-g0",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(SOURCE_C),
            str(SOURCE_ASM),
            "-o",
            str(oracle),
        ]
        built = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
        assert built.returncode == 0, built.stderr
        macho = lief.MachO.parse(str(oracle))
        assert macho and len(macho) == 1
        image = macho[0]
        assert image.header.cpu_type.name == "X86_64"
        symbol = image.get_symbol("_after_return_slice")
        assert symbol is not None
        embedded = bytes(image.get_content_from_virtual_address(symbol.value, SLICE_LENGTH))
        assert embedded == expected_slice
        cases = []
        actuals = []
        case_commands = []
        for old, current in zip(prior["captures"], new["cases"]):
            assert (old["variant"], current["variant"]) in (
                ("first", "v14-1"),
                ("second", "v14-0"),
            )
            post = json.loads(bytes.fromhex(old["post_hex"]))
            ida = json.loads(bytes.fromhex(current["ida_hex"]))
            rbx = int(post["boundary_registers"]["rbx"], 16)
            data = bytes.fromhex(post["boundary_data_hex"])
            start = rbx - DATA_START
            stack = bytes.fromhex(post["boundary_stack_hex"])
            sp = int(post["boundary_registers"]["rsp"], 16)
            base = int(post["stack_base"], 16)
            r12 = struct.unpack_from("<Q", stack, sp + 16 - base)[0]
            case_command = [
                str(oracle),
                data[start : start + 64].hex(),
                f"{r12:x}",
                expected_slice.hex(),
            ]
            case_commands.append(case_command)
            run = subprocess.run(
                case_command,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            assert run.returncode == 0 and not run.stderr
            actual = parse_output(run.stdout)
            checked = compare(post, ida["capture"], actual)
            actuals.append(actual)
            cases.append(
                {
                    "variant": current["variant"],
                    "input_sha256": post["input_sha256"],
                    "post_sha256": sha(bytes.fromhex(old["post_hex"])),
                    "ida_sha256": sha(bytes.fromhex(current["ida_hex"])),
                    "process_exit": run.returncode,
                    **checked,
                }
            )
        post = json.loads(bytes.fromhex(prior["captures"][0]["post_hex"]))
        trace = json.loads(bytes.fromhex(new["cases"][0]["ida_hex"]))["capture"]
        assert compare(post, trace, actuals[0])
        altered = copy.deepcopy(actuals[0])
        altered["rax"] ^= 1
        register_mutation = rejects(lambda: compare(post, trace, altered))
        altered = copy.deepcopy(actuals[0])
        altered["data"] = bytes([actuals[0]["data"][0] ^ 1]) + actuals[0]["data"][1:]
        data_mutation = rejects(lambda: compare(post, trace, altered))
        slice_mutation = rejects(
            lambda: check_slice(bytes([embedded[0] ^ 1]) + embedded[1:], expected_slice)
        )
        altered_slice = bytes([expected_slice[0] ^ 1]) + expected_slice[1:]
        runtime_mutation = subprocess.run(
            case_commands[0][:-1] + [altered_slice.hex()],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        runtime_code_mutation = (
            runtime_mutation.returncode == 3
            and not runtime_mutation.stdout
            and not runtime_mutation.stderr
        )
        assert register_mutation and data_mutation and slice_mutation and runtime_code_mutation
        result = {
            "schema": 1,
            "passed": True,
            "scope": "exact 75-byte ELF slice executed under x86-64 Rosetta with captured input subset; separate process and stack layout",
            "host_machine": platform.machine(),
            "binary_sha256": sha(binary),
            "elf_slice_sha256": sha(expected_slice),
            "oracle_format": "Mach-O x86-64",
            "oracle_assembly_sha256": sha(SOURCE_ASM.read_bytes()),
            "oracle_c_sha256": sha(SOURCE_C.read_bytes()),
            "cases": cases,
            "mutations_rejected": {
                "oracle_register": register_mutation,
                "oracle_data": data_mutation,
                "embedded_byte": slice_mutation,
                "runtime_code_input": runtime_code_mutation,
            },
        }
    if args.evidence is not None:
        evidence = json.loads(args.evidence.read_text())
        assert evidence["schema"] == 1 and evidence["passed"]
        assert evidence["archive_base64_sha256"] == sha(args.archive.read_bytes())
        assert evidence["prior_archive_sha256"] == sha(args.prior.read_bytes())
        assert evidence["lief_version"] == lief.__version__
        for name, expected in evidence["sources_sha256"].items():
            assert sha((ROOT_DIR / name).read_bytes()) == expected
        assert result == evidence["execution"]
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print("Morok after-return executed slice verification: pass")


if __name__ == "__main__":
    main()
