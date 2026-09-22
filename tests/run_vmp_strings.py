"""Paired native-byte oracle and protected temporal-string recovery benchmark.

Only generated artifacts are written. Public records use logical paths, hashes,
bounded measurements and exception types; console banners are never published.
"""
import argparse
import collections
import json
from pathlib import Path
import platform
import re
import sys

sys.dont_write_bytecode = True
from run_vmp_corpus import (MODES, PROTECTOR_SEEDS, base_environment, digest,
                            execute, function_bytes, project, text_section)

EXPECTED = ("secret!", "second!")
SOURCE = "tests/vmp_native/native_read_strings.S"
PROBE = "tests/ida_protected_strings_probe.py"
BUILD_FLAGS = ["-arch", "x86_64", "-O2", "-g0", "-Wl,-no_fixup_chains",
               "-Wl,-no_data_const", "-Wl,-headerpad,0x4000"]


def successful(measurement):
    return (measurement["exit_code"] == 0 and not measurement["timed_out"]
            and not measurement["output_exceeded"])


def seed_attested(output, seed):
    callbacks = re.findall(rb"CHERNOBOG_CORPUS_SEED=(\d+)", output)
    applied = re.findall(rb"CHERNOBOG_CORPUS_SRAND=(\d+) requested=(\d+)", output)
    return ([int(value) for value in callbacks] == [seed] and bool(applied)
            and all(int(value) == seed for value, _ in applied))


def summarize(probe):
    """Separate literal instances, distinct expected values and abstentions."""
    assert probe["passed"] and not probe["errors"], "probe failed"
    view, candidates = probe["view"], probe["candidates"]
    assert not candidates or (view.get("available") is True and view.get("fresh") is True), "stale publication"
    runs = view.get("runs", [])
    complete = bool(runs) and all(run["ran"] == "true" and run["returned"] == "true"
        and run["temporal_complete"] == "true" and run["temporal_truncated"] == "false"
        and run["memory_observation_available"] == "true" and run["data_trace_truncated"] == "false"
        and run["data_trace_filtered"] == "false" for run in runs)
    assert not view.get("omitted", {}).get("runs", 0), "run inventory truncated"
    assert not candidates or complete, "literal published from incomplete temporal corpus"
    for candidate in candidates:
        assert (candidate["ok"] == 1 and candidate["eligible_runs"] == len(runs)
                and candidate["observations"] == len(runs)), "incomplete consensus"
    values = [candidate["value"] for candidate in candidates]
    correct = sum(value in EXPECTED for value in values)
    distinct = len(set(values) & set(EXPECTED))
    return {"scheduled_runs": len(runs), "returned_runs": sum(run["returned"] == "true" for run in runs),
            "temporal_corpus_complete": complete, "candidate_instances": len(values),
            "correct_value_instances": correct, "unexpected_value_instances": len(values) - correct,
            "distinct_expected_values": distinct, "expected_values": len(EXPECTED),
            "missing_expected_values": len(EXPECTED) - distinct,
            "literal_value_precision": correct / len(values) if values else None,
            "distinct_value_recall": distinct / len(EXPECTED),
            "stop_reasons": dict(collections.Counter(run["kind"] + ":" + run["stop_reason_name"] for run in runs)),
            "display_annotations": len(probe["display"]["annotations"]),
            "display_status": probe["display"]["status"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protector", type=Path, required=True)
    parser.add_argument("--source-tree", type=Path, required=True)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    assert sys.platform == "darwin", "macOS runner required"
    root = Path(__file__).resolve().parent.parent
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    protector, tree, ida, plugin = (p.resolve() for p in (args.protector, args.source_tree, args.ida, args.plugin))
    sources = (SOURCE, PROBE, "tests/run_vmp_strings.py", "tests/run_vmp_corpus.py", "tests/run_ida_smoke.py",
               "tests/vmp_corpus/seed_interpose.c", "tests/vmp_corpus/seed_probe.c", "tests/vmp_corpus/seed.lua")
    report = {"schema": 1, "passed": False, "architecture": "x86_64", "format": "Mach-O",
        "host_architecture": platform.machine(), "source_build_attestation": "unknown",
        "project_options": 0, "vm_options": 0, "procedure_options": 0, "packing": False,
        "implicit_license_dependent_flags": "unknown; license data is not inspected",
        "protector_seeds": list(PROTECTOR_SEEDS), "reserved_protector_seed": PROTECTOR_SEEDS[-1],
        "input_variation": "none; three independent process executions per binary",
        "seed_policy": "test-only srand interposition; each emitted artifact repeated with the same seed",
        "expected_values": list(EXPECTED), "oracle": "unprotected main compares all bytes consumed into RAX and RDX",
        "source_sha256": {name: digest(root / name) for name in sources},
        "reference_source_sha256": {"vmp/" + name: digest(tree / name) for name in
            ("core/intel.cc", "core/macfile.cc", "core/core.cc", "core/script.cc", "runtime/string_manager.cc")},
        "runtime_sha256": {"protector": digest(protector), "protector_sdk": digest(protector.parent / "libVMProtectSDK.dylib"),
                           "ida": digest(ida), "plugin": digest(plugin)},
        "build_arguments": ["xcrun", "clang", *BUILD_FLAGS, SOURCE, "-o", "<output>/original"],
        "protection": [], "native_runs": [], "analysis": [], "negative_oracles": []}
    try:
        for tool in ("clang", "ld"):
            measurement, stdout, _ = execute(["xcrun", "--find", tool])
            assert successful(measurement), "build tool inventory failed"
            report["runtime_sha256"][tool] = digest(Path(stdout.decode().strip()))
        original = output / "original"
        report["build"], _, _ = execute(["xcrun", "clang", *BUILD_FLAGS, root / SOURCE, "-o", original], timeout=60)
        assert successful(report["build"]), "fixture compilation failed"
        report["original_sha256"] = digest(original)
        measurement, symbols, _ = execute(["xcrun", "nm", "-n", "-g", original])
        assert successful(measurement), "symbol inventory failed"
        addresses = {name: int(re.search(rb"^([0-9a-fA-F]+) T _" + name.encode() + rb"$", symbols, re.M)[1], 16)
                     for name in ("native_read_strings", "main")}
        entry, main_entry = addresses["native_read_strings"], addresses["main"]
        assert main_entry > entry, "unexpected source order"
        section = text_section(original)
        span = function_bytes(original, section, entry, main_entry - entry)
        main_span = function_bytes(original, section, main_entry, section["address"] + section["size_bytes"] - main_entry)
        report["selected_entry"] = hex(entry)
        report["selected_span_bytes"] = len(span)
        report["oracle_entry"] = hex(main_entry)
        report["oracle_span_hex"] = main_span.hex()
        # Corrupt only the unprotected comparison immediate, independently for
        # each returned string. Require exit 1 (a crash is not an oracle pass).
        main_offset = section["offset"] + main_entry - section["address"]
        text_end = section["offset"] + section["size_bytes"]
        for index, value in enumerate((0x5a7b2e3f28393f29, 0x5a7b3e3435393f29)):
            data = bytearray(original.read_bytes())
            pattern = value.to_bytes(8, "little")
            at = data.find(pattern, main_offset, text_end)
            assert at >= main_offset and data.find(pattern, at + 1, text_end) == -1, "ambiguous oracle immediate"
            data[at] ^= 1
            negative = output / ("negative-oracle-" + str(index))
            negative.write_bytes(data)
            negative.chmod(0o700)
            measurement, _, _ = execute([negative], timeout=10)
            passed = measurement["exit_code"] == 1 and not measurement["timed_out"] and not measurement["output_exceeded"]
            report["negative_oracles"].append({"index": index, "sha256": digest(negative), "measurement": measurement, "passed": passed})
            assert passed, "negative byte oracle failed"
        instrument, seed_probe = output / "seed.dylib", output / "seed-probe"
        for source, target, extra in (("seed_interpose.c", instrument, ["-dynamiclib"]), ("seed_probe.c", seed_probe, [])):
            measurement, _, _ = execute(["xcrun", "clang", "-arch", "x86_64", "-O2", "-g0", *extra,
                                         root / "tests/vmp_corpus" / source, "-o", target])
            assert successful(measurement), "seed instrumentation build failed"
        normal, a, _ = execute([seed_probe, "1"])
        reference, b, _ = execute([seed_probe, "17"])
        injected, c, err = execute([seed_probe, "1"], env=dict(base_environment(),
            DYLD_INSERT_LIBRARIES=str(instrument), CHERNOBOG_CORPUS_PROTECTOR_SEED="17"))
        assert all(successful(item) for item in (normal, reference, injected)) and a != b and b == c \
            and b"CHERNOBOG_CORPUS_SRAND=17 requested=1" in err, "seed control failed"
        report["seed_instrument"] = {"sha256": digest(instrument), "probe_sha256": digest(seed_probe), "verified": True}
        (output / "repeats").mkdir()
        binaries = [("original", original, report["original_sha256"])]
        for mode in MODES:
            config = output / (mode + ".vmp")
            project(config, {"native_read_strings": entry}, mode)
            for seed in PROTECTOR_SEEDS:
                label = mode + "-" + str(seed)
                target, repeat = output / label, output / "repeats" / label
                item = {"label": label, "mode": mode, "seed": seed, "project_sha256": digest(config), "generations": []}
                report["protection"].append(item)
                for binary in (target, repeat):
                    measurement, out, err = execute([protector, original, binary, "-pf", config,
                        "-sf", root / "tests/vmp_corpus/seed.lua", "-we"], cwd=protector.parent, timeout=60,
                        env=dict(base_environment(), DYLD_INSERT_LIBRARIES=str(instrument), CHERNOBOG_CORPUS_PROTECTOR_SEED=str(seed)))
                    attested = seed_attested(out + err, seed)
                    item["generations"].append({"measurement": measurement, "seed_attested": attested})
                    assert successful(measurement) and attested and binary.is_file(), "protection failed"
                item.update(sha256=digest(target), repeat_sha256=digest(repeat), size_bytes=target.stat().st_size)
                assert item["sha256"] == item["repeat_sha256"], "nondeterministic protection"
                item["entry_changed"] = function_bytes(target, text_section(target), entry, len(span)) != span
                assert item["entry_changed"], "selected bytes unchanged"
                item["oracle_unchanged"] = function_bytes(target, text_section(target), main_entry, len(main_span)) == main_span
                assert item["oracle_unchanged"], "unprotected byte comparator changed"
                target.chmod(target.stat().st_mode | 0o100)
                binaries.append((label, target, item["sha256"]))
        for label, binary, before in binaries:
            assert all(value.encode() not in binary.read_bytes() for value in EXPECTED), "plaintext stored in image"
            for repetition in range(3):
                measurement, _, _ = execute([binary], timeout=10)
                report["native_runs"].append({"label": label, "repetition": repetition, "measurement": measurement})
                assert successful(measurement), "native byte oracle failed"
            run_dir = output / ("ida-" + label)
            measurement, _, _ = execute([sys.executable, "-B", root / "tests/run_ida_smoke.py", binary,
                root / PROBE, "--ida", ida, "--plugin", plugin, "--output-dir", run_dir, "--enable-rax",
                "--set", "CHERNOBOG_STRING_ENTRY=" + hex(entry)], timeout=120)
            assert successful(measurement), "production probe failed"
            probe = json.loads((run_dir / "protected_strings.json").read_text())
            summary = summarize(probe)
            report["analysis"].append({"label": label, "measurement": measurement, "summary": summary,
                "probe_sha256": digest(run_dir / "protected_strings.json"), "runner_sha256": digest(run_dir / "run.json")})
            assert not summary["unexpected_value_instances"], "unexpected literal value"
            if label == "original":
                assert summary["distinct_expected_values"] == 2 and summary["display_annotations"] == 2, "original positive control failed"
            assert digest(binary) == before, "binary changed during evaluation"
            print(json.dumps({"label": label, **summary}), flush=True)
        assert all(digest(root / name) == value for name, value in report["source_sha256"].items()), "source changed"
        assert all(digest(tree / name.removeprefix("vmp/")) == value for name, value in report["reference_source_sha256"].items()), "reference changed"
        for name, path in (("protector", protector), ("protector_sdk", protector.parent / "libVMProtectSDK.dylib"), ("ida", ida), ("plugin", plugin)):
            assert digest(path) == report["runtime_sha256"][name], "runtime changed"
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__
    finally:
        (output / "strings.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "protected_files": len(report["protection"]),
                      "native_runs": len(report["native_runs"]), "analysis_runs": len(report["analysis"]), "failure": report.get("failure")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"passed": False, "failure": type(error).__name__}))
        sys.exit(1)
