"""Generate unpacked paired fixtures with recorded settings and behavior oracles.

The supplied console is attributed by binary hash. Source-to-console build
equivalence remains unknown unless established separately. Console banners and
personal paths are never copied into the public report.
"""
import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import re
import signal
import struct
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
MASK = (1 << 32) - 1
INPUT_SEEDS = (0x31415926, 0x9E3779B9, 0xD1B54A35)
PROTECTOR_SEEDS = (0, 1, 0xC0FFEE)
MODES = {"mutation": 1, "virtualization": 0, "combined": 2}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def base_environment():
    return {key: value for key, value in os.environ.items()
            if not key.startswith("DYLD_") and key not in ("LD_PRELOAD", "LD_LIBRARY_PATH")}


def text_section(path):
    data = Path(path).read_bytes()
    if data.startswith(b"\x7fELF"):
        return elf32_text_section(data)
    if len(data) < 32 or struct.unpack_from("<I", data)[0] != 0xFEEDFACF:
        raise ValueError("expected thin little-endian Mach-O64")
    count, length = struct.unpack_from("<II", data, 16)
    if count > 4096 or length > len(data) - 32:
        raise ValueError("invalid load-command bounds")
    cursor = 32
    found = []
    for _ in range(count):
        if cursor + 8 > 32 + length:
            raise ValueError("truncated load command")
        kind, size = struct.unpack_from("<II", data, cursor)
        if size < 8 or cursor + size > 32 + length:
            raise ValueError("invalid load-command size")
        if kind == 0x19:
            if size < 72:
                raise ValueError("truncated segment")
            sections = struct.unpack_from("<I", data, cursor + 64)[0]
            if sections > (size - 72) // 80:
                raise ValueError("invalid section count")
            for index in range(sections):
                at = cursor + 72 + index * 80
                name = data[at:at+16].split(b"\0", 1)[0]
                if name != b"__text":
                    continue
                address, size_bytes, offset = struct.unpack_from("<QQI", data, at + 32)
                flags = struct.unpack_from("<I", data, at + 64)[0]
                found.append({"address": address, "size_bytes": size_bytes, "offset": offset, "flags": flags,
                              "file_backed": offset > 0 and (flags & 255) == 0 and offset + size_bytes <= len(data)})
        cursor += size
    if cursor != 32 + length or len(found) != 1:
        raise ValueError("ambiguous text section")
    return found[0]


def elf32_text_section(data):
    """Bounded ELF32/i386 initialized executable-section inventory."""
    if len(data) < 52 or data[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("expected little-endian ELF32")
    kind, machine, version, _, phoff, shoff, _, ehsize, phsize, phcount, shsize, shcount, names = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
    if kind not in (2, 3) or machine != 3 or version != 1 or ehsize != 52:
        raise ValueError("unsupported ELF architecture/header")
    if (phsize != 32 or not 0 < phcount <= 4096 or phoff < 52 or phoff + phcount * phsize > len(data)
            or shsize != 40 or not 0 < shcount <= 4096 or shoff < 52 or shoff + shcount * shsize > len(data)
            or not 0 < names < shcount):
        raise ValueError("invalid ELF table bounds")
    sections = [struct.unpack_from("<10I", data, shoff + i * shsize) for i in range(shcount)]
    strings = sections[names]
    if strings[1] != 3 or strings[4] + strings[5] > len(data):
        raise ValueError("invalid ELF section-name table")
    strings = data[strings[4]:strings[4] + strings[5]]
    found = []
    for section in sections:
        name, section_kind, flags, address, offset, size = section[:6]
        if name >= len(strings) or strings.find(b"\0", name) < 0:
            raise ValueError("invalid ELF section name")
        if strings[name:strings.find(b"\0", name)] != b".text":
            continue
        initialized = (section_kind == 1 and flags & 6 == 6 and offset > 0
                       and offset + size <= len(data) and address + size <= 1 << 32)
        mapped = False
        for i in range(phcount):
            pkind, poff, va, _, files, memory, perms, _ = struct.unpack_from("<8I", data, phoff + i * phsize)
            if pkind != 1:
                continue
            if poff + files > len(data) or files > memory or va + memory > 1 << 32:
                raise ValueError("invalid ELF load segment")
            if (perms & 5 == 5 and va <= address and address + size <= va + files
                    and offset == poff + address - va):
                mapped = True
        found.append({"address": address, "size_bytes": size, "offset": offset, "flags": flags,
                      "file_backed": initialized and mapped})
    if len(found) != 1:
        raise ValueError("ambiguous ELF text section")
    return found[0]


def function_bytes(path, section, address, size):
    relative = address - section["address"]
    if not section["file_backed"] or relative < 0 or relative + size > section["size_bytes"]:
        raise ValueError("function outside initialized text")
    start = section["offset"] + relative
    return Path(path).read_bytes()[start:start+size]


def execute(args, cwd=None, env=None, timeout=30):
    """Per-process wait4 accounting; bounded output and termination of own group."""
    started = time.perf_counter_ns()
    timed_out = output_exceeded = False
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen([str(a) for a in args], cwd=cwd, env=base_environment() if env is None else env,
                                   stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   start_new_session=True)
        while True:
            pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if pid:
                break
            output_exceeded = os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > 2 * 1024 * 1024
            timed_out = time.perf_counter_ns() - started > timeout * 1_000_000_000
            if timed_out or output_exceeded:
                os.killpg(process.pid, signal.SIGKILL)
                _, status, usage = os.wait4(process.pid, 0)
                break
            time.sleep(0.02)
        process.returncode = os.waitstatus_to_exitcode(status)
        output_exceeded |= os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > 2 * 1024 * 1024
        stdout.seek(0)
        stderr.seek(0)
        out, err = stdout.read(2 * 1024 * 1024), stderr.read(2 * 1024 * 1024)
    return {"exit_code": process.returncode, "elapsed_ns": time.perf_counter_ns() - started,
            "peak_resident_bytes": int(usage.ru_maxrss) * (1 if sys.platform == "darwin" else 1024),
            "timed_out": timed_out, "output_exceeded": output_exceeded,
            "stdout_sha256": hashlib.sha256(out).hexdigest(),
            "stderr_sha256": hashlib.sha256(err).hexdigest()}, out, err


def inputs(seed):
    corners = (0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, MASK)
    yield from itertools.product(corners, repeat=3)
    def next_value():
        nonlocal seed
        seed ^= (seed << 13) & MASK
        seed ^= seed >> 17
        seed ^= (seed << 5) & MASK
        seed &= MASK
        return seed
    for _ in range(64):
        yield next_value(), next_value(), next_value()


def expected(function, x, y, memory):
    mixed = memory ^ (y if function == 1 and x < y else x)
    rotated = ((mixed << 5) | (mixed >> 27)) & MASK
    total = rotated + y
    result = total & MASK
    flags = int(total > MASK)
    flags |= int((result & 255).bit_count() % 2 == 0) << 2
    flags |= int(bool((rotated ^ y ^ result) & 16)) << 4
    flags |= int(result == 0) << 6
    flags |= ((result >> 31) & 1) << 7
    flags |= int(bool((~(rotated ^ y) & (rotated ^ result)) & (1 << 31))) << 11
    return result, flags, 0, 0xA5A5A5A5, result, 0x5A5A5A5A


def verify(output, seed):
    try:
        lines = output.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return {"passed": False, "reason": "non-ASCII record"}
    cases = list(inputs(seed))
    if len(lines) != 2 * len(cases):
        return {"passed": False, "rows": len(lines), "expected_rows": 2 * len(cases), "reason": "row count"}
    mismatches = []
    for index, line in enumerate(lines):
        fields = line.split()
        if len(fields) != 11:
            return {"passed": False, "rows": len(lines), "reason": "record format"}
        case, function = divmod(index, 2)
        try:
            identity = (int(fields[0]), int(fields[1]))
            x, y, memory = (int(value, 16) for value in fields[2:5])
            observed = (int(fields[5], 16), int(fields[6], 16), int(fields[7]),
                        *(int(value, 16) for value in fields[8:11]))
        except ValueError:
            return {"passed": False, "rows": len(lines), "reason": "invalid numeric field"}
        if identity != (case, function):
            return {"passed": False, "rows": len(lines), "reason": "case identity"}
        if (x, y, memory) != cases[case]:
            return {"passed": False, "rows": len(lines), "reason": "input identity"}
        wanted = expected(function, x, y, memory)
        if observed != wanted:
            if len(mismatches) < 16:
                mismatches.append({"case": case, "function": function,
                                   "observed": observed, "expected": wanted})
    return {"passed": not mismatches, "rows": len(lines), "mismatch_examples": mismatches}


def project(path, addresses, mode):
    document = ET.Element("Document", Version="2")
    protection = ET.SubElement(document, "Protection", InputFileName="original", Options="0", VMOptions="0", VMCodeSectionName=".cbg")
    procedures = ET.SubElement(protection, "Procedures")
    for address in addresses.values():
        ET.SubElement(procedures, "Procedure", Address=hex(address), CompilationType=str(MODES[mode]), Options="0")
    ET.ElementTree(document).write(path, encoding="utf-8", xml_declaration=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--protector", required=True, type=Path)
    parser.add_argument("--source-tree", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--architecture", choices=("x86_64", "i386"), default="x86_64")
    parser.add_argument("--linux32-image", help="Prebuilt Linux32 image; resolved to immutable image ID")
    parser.add_argument("--docker-context", default="default")
    parser.add_argument("--smoke", action="store_true", help="One mutation seed and one input seed for configuration checks")
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise RuntimeError("this runner uses the supplied macOS protector and seed instrument")
    if args.architecture == "i386" and not args.linux32_image:
        raise RuntimeError("i386 execution requires --linux32-image")
    root = Path(__file__).resolve().parent.parent
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    protector = args.protector.resolve()
    source_tree = args.source_tree.resolve()
    report = {"schema": 1, "architecture": args.architecture, "format": "ELF" if args.architecture == "i386" else "Mach-O", "host_architecture": platform.machine(),
              "source_build_attestation": "unknown", "protector_sha256": digest(protector),
              "protector_sdk_sha256": digest(protector.parent / "libVMProtectSDK.dylib"),
              "implicit_license_dependent_flags": "unknown; license data is not inspected",
              "packing": False, "project_options": 0, "vm_options": 0, "procedure_options": 0,
              "seed_policy": "test-only C srand interposition; every requested seed replaced with the recorded seed", "smoke": args.smoke,
              "protector_seeds": list(PROTECTOR_SEEDS[:1] if args.smoke else PROTECTOR_SEEDS),
              "input_seeds": list(INPUT_SEEDS[:1] if args.smoke else INPUT_SEEDS),
              "held_out_protector_seed": None if args.smoke else PROTECTOR_SEEDS[-1],
              "held_out_input_seed": None if args.smoke else INPUT_SEEDS[-1],
              "source_sha256": {name: digest(root / name) for name in
                  ("tests/run_vmp_corpus.py", "tests/vmp_corpus/pair.c", "tests/vmp_corpus/pair.S", "tests/vmp_corpus/pair32.S",
                   "tests/vmp_corpus/linux32.py", "tests/vmp_corpus/linux32_exec.py", "tests/vmp_corpus/linux32.Dockerfile",
                   "tests/vmp_corpus/seed.lua", "tests/vmp_corpus/seed_interpose.c", "tests/vmp_corpus/seed_probe.c")},
              "reference_source_sha256": {"vmp/"+name: digest(source_tree / name) for name in
                  ("core/core.cc", "core/core.h", "core/files.cc", "core/files.h", "core/intel.cc", "core/macfile.cc", "core/elffile.cc", "core/script.cc", "third-party/lua/lmathlib.c")},
              "build": {}, "runs": [], "protection": [], "passed": False,
              "scope": "paired behavior corpus for recorded architecture; recovery rates remain unmeasured"}
    try:
        linux32 = None
        if args.architecture == "i386":
            from vmp_corpus.linux32 import Linux32
            linux32 = Linux32(root, output, args.linux32_image, args.docker_context)
            report["linux32_environment"] = linux32.metadata
        original = output / "original"
        report["tool_sha256"] = {}
        for tool in ("clang", "ld"):
            result, stdout, _ = execute(["xcrun", "--find", tool])
            if result["exit_code"]:
                raise RuntimeError("compiler/linker inventory failed")
            report["tool_sha256"][tool] = digest(Path(stdout.decode().strip()))
        command = ["xcrun", "clang", "-arch", "x86_64", "-O2", "-g0", "-Wl,-no_fixup_chains", "-Wl,-no_data_const", "-Wl,-headerpad,0x4000",
                   root / "tests/vmp_corpus/pair.c", root / "tests/vmp_corpus/pair.S", "-o", original]
        if linux32:
            command = ["i686-linux-gnu-gcc", "-O2", "-g0", "-fno-pie", "-no-pie", "-fcf-protection=none",
                       "/source/vmp_corpus/pair.c", "/source/vmp_corpus/pair32.S", "-o", "/output/original"]
        build, _, _ = linux32.execute(command) if linux32 else execute(command, timeout=60)
        report["build"] = build
        report["build_arguments"] = ["xcrun", "clang", "-arch", "x86_64", "-O2", "-g0", "-Wl,-no_fixup_chains",
                                     "-Wl,-no_data_const", "-Wl,-headerpad,0x4000", "tests/vmp_corpus/pair.c", "tests/vmp_corpus/pair.S", "-o", "<output>/original"]
        if linux32:
            report["build_arguments"] = command
            report["build_accounting_scope"] = "Docker client; guest execution is measured separately with Linux wait4"
        if build["exit_code"]:
            raise RuntimeError("fixture compilation failed")
        report["original_sha256"] = digest(original)
        report["original_text"] = original_text = text_section(original)
        instrument, probe = output / "seed.dylib", output / "seed-probe"
        for source, target, extra in [("seed_interpose.c", instrument, ["-dynamiclib"]), ("seed_probe.c", probe, [])]:
            result, _, _ = execute(["xcrun", "clang", "-arch", "x86_64", "-O2", "-g0", *extra,
                                    root / "tests/vmp_corpus" / source, "-o", target])
            if result["exit_code"]:
                raise RuntimeError("seed instrument compilation failed")
        injected = dict(base_environment(), DYLD_INSERT_LIBRARIES=str(instrument), CHERNOBOG_CORPUS_PROTECTOR_SEED="17")
        normal, normal_out, _ = execute([probe, "1"])
        reference, reference_out, _ = execute([probe, "17"])
        overridden, overridden_out, overridden_err = execute([probe, "1"], env=injected)
        seed_verified = (normal["exit_code"] == reference["exit_code"] == overridden["exit_code"] == 0
                         and normal_out != reference_out and overridden_out == reference_out
                         and b"CHERNOBOG_CORPUS_SRAND=17 requested=1" in overridden_err)
        report["seed_instrument"] = {"sha256": digest(instrument), "probe_sha256": digest(probe), "verified": seed_verified}
        if not seed_verified:
            raise RuntimeError("seed interposition verification failed")
        nm, symbols, _ = (linux32.execute(["i686-linux-gnu-nm", "-n", "-g", "/output/original"])
                          if linux32 else execute(["xcrun", "nm", "-n", "-g", original]))
        if nm["exit_code"]:
            raise RuntimeError("fixture symbol inventory failed")
        symbol_prefix = b"" if linux32 else b"_"
        addresses = {name: int(re.search(rb"^([0-9a-fA-F]+) T " + symbol_prefix + name.encode() + rb"$", symbols, re.M)[1], 16)
                     for name in ("corpus_transform", "corpus_branch")}
        report["selected_functions"] = {k: hex(v) for k, v in addresses.items()}
        ends = {name: int(re.search(rb"^([0-9a-fA-F]+) T " + symbol_prefix + name.encode() + rb"_end$", symbols, re.M)[1], 16)
                for name in addresses}
        original_bytes = {name: function_bytes(original, original_text, address, ends[name]-address)
                          for name, address in addresses.items()}
        report["selected_function_bytes"] = {name: data.hex() for name, data in original_bytes.items()}
        repeats = output / "repeats"
        repeats.mkdir()
        observations = output / "observations"
        observations.mkdir()
        binaries = [("original", original)]
        for mode in (["mutation"] if args.smoke else MODES):
            config = output / (mode + ".vmp")
            project(config, addresses, mode)
            for seed in report["protector_seeds"]:
                label = mode + "-" + str(seed)
                target = output / label
                env = dict(base_environment(), CHERNOBOG_CORPUS_PROTECTOR_SEED=str(seed), DYLD_INSERT_LIBRARIES=str(instrument))
                measurement, out, err = execute([protector, original, target, "-pf", config,
                    "-sf", root / "tests/vmp_corpus/seed.lua", "-we"], cwd=protector.parent, env=env, timeout=60)
                markers = re.findall(rb"CHERNOBOG_CORPUS_SEED=(\d+)", out+err)
                applied = re.findall(rb"CHERNOBOG_CORPUS_SRAND=(\d+) requested=(\d+)", out+err)
                item = {"label": label, "mode": mode, "protector_seed": seed, "project_sha256": digest(config),
                        "measurement": measurement, "seed_markers": [int(s) for s in markers],
                        "seed_applications": [{"applied": int(a), "requested": int(r)} for a, r in applied]}
                report["protection"].append(item)
                if (measurement["exit_code"] or [int(s) for s in markers] != [seed] or not target.exists()
                        or not applied or any(int(a) != seed for a, _ in applied)):
                    # Only diagnostic lines, never the console license banner.
                    diagnostics = [line for line in (out+err).decode(errors="replace").splitlines()
                                   if "[Error]" in line and not any(word in line.lower() for word in ("license", "serial", "registered", "@"))]
                    for line in diagnostics[:4]:
                        print(re.sub(r"/Users/[^\s'\"]+", "<local path>", line), file=sys.stderr)
                    raise RuntimeError("protection or seed attestation failed")
                target.chmod(target.stat().st_mode | 0o100)
                item["sha256"] = digest(target)
                item["size_bytes"] = target.stat().st_size
                item["text"] = section = text_section(target)
                item["selected_entry_changed"] = {
                    name: function_bytes(target, section, address, len(original_bytes[name])) != original_bytes[name]
                    for name, address in addresses.items()}
                if not section["file_backed"] or not all(item["selected_entry_changed"].values()):
                    raise RuntimeError("selected code was not visibly transformed in initialized text")
                repeat_target = repeats / label
                repeated, repeat_out, repeat_err = execute([protector, original, repeat_target, "-pf", config,
                    "-sf", root / "tests/vmp_corpus/seed.lua", "-we"], cwd=protector.parent, env=env, timeout=60)
                repeat_applied = re.findall(rb"CHERNOBOG_CORPUS_SRAND=(\d+) requested=(\d+)", repeat_out+repeat_err)
                repeat_markers = re.findall(rb"CHERNOBOG_CORPUS_SEED=(\d+)", repeat_out+repeat_err)
                item["repeat_measurement"] = repeated
                item["repeat_seed_attested"] = (bool(repeat_applied) and all(int(a) == seed for a, _ in repeat_applied)
                                                  and [int(s) for s in repeat_markers] == [seed])
                item["repeat_sha256"] = digest(repeat_target) if repeat_target.exists() else None
                item["repeat_identical"] = (repeated["exit_code"] == 0 and item["repeat_seed_attested"]
                                              and item["repeat_sha256"] == item["sha256"])
                binaries.append((label, target))
        original_stdout = {}
        for label, binary in binaries:
            for seed in report["input_seeds"]:
                measurement, stdout, _ = (linux32.run(binary, seed) if linux32
                                          else execute([binary, str(seed)], cwd=output, timeout=10))
                verdict = verify(stdout, seed) if measurement["exit_code"] == 0 and not measurement["output_exceeded"] else {"passed": False, "reason": "execution did not complete within limits"}
                if label == "original":
                    original_stdout[seed] = measurement["stdout_sha256"]
                observed_file = "observations/" + label + "-" + str(seed) + ".txt"
                (output / observed_file).write_bytes(stdout)
                report["runs"].append({"label": label, "input_seed": seed, "measurement": measurement, "oracle": verdict,
                                       "observations": observed_file, "matches_original_stdout": measurement["stdout_sha256"] == original_stdout[seed]})
                if not verdict["passed"] or measurement["stdout_sha256"] != original_stdout[seed]:
                    raise RuntimeError("paired behavior mismatch")
        report["inputs_unchanged"] = (digest(original) == report["original_sha256"]
              and digest(protector) == report["protector_sha256"]
              and digest(protector.parent / "libVMProtectSDK.dylib") == report["protector_sdk_sha256"])
        report["sources_unchanged"] = (all(digest(root / name) == h for name, h in report["source_sha256"].items())
            and all(digest(source_tree / name.removeprefix("vmp/")) == h for name, h in report["reference_source_sha256"].items()))
        report["protected_artifacts_unchanged"] = all(digest(output / p["label"]) == p["sha256"] for p in report["protection"])
        if (not report["inputs_unchanged"] or not report["sources_unchanged"] or not report["protected_artifacts_unchanged"]
                or not all(p["repeat_identical"] for p in report["protection"])):
            raise RuntimeError("input integrity or repeated protection identity failed")
        report["passed"] = True
        report["behavior_rows"] = sum(r["oracle"]["rows"] for r in report["runs"])
        report["unique_inputs_per_binary"] = len({(f, *values) for s in report["input_seeds"] for values in inputs(s) for f in (0, 1)})
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + re.sub(r"/Users/[^\s'\"]+", "<local path>", str(error))
    finally:
        (output / "corpus.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "protected_files": len(report["protection"]),
                      "behavior_runs": len(report["runs"]), "failure": report.get("failure")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(type(error).__name__ + ": " + re.sub(r"/Users/[^\s'\"]+", "<local path>", str(error)), file=sys.stderr)
        sys.exit(1)
