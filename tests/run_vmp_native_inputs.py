"""Measure explicit-input native captures on an existing paired VMP corpus."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from run_vmp_corpus import digest, execute, expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-report", type=Path, required=True)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--walk", action="store_true", help="opt in to bounded observed native transfers")
    parser.add_argument("--check", action="store_true", help="sample native instruction entries and check local VM transitions")
    args = parser.parse_args()
    if args.check:
        args.walk = True
    root = Path(__file__).resolve().parent.parent
    corpus_path = args.corpus_report.resolve()
    corpus = json.loads(corpus_path.read_text())
    assert corpus["passed"] and not corpus["smoke"]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    files = ["tests/run_vmp_native_inputs.py", "tests/ida_vm_native_input_probe.py", "tests/run_ida_smoke.py",
             "tests/run_vmp_corpus.py", "src/vm/native_region.hpp", "src/vm/native_region.cpp",
             "src/vm/ida_native_trace.hpp", "src/vm/ida_native_trace.cpp", "src/hybrid/emu_driver.hpp",
             "src/hybrid/emu_driver.cpp", "src/hybrid/emu_input.hpp", "src/hybrid/abi_policy.cpp",
             "src/hybrid/evidence.cpp", "src/plugin/idc_api.cpp", "tests/hybrid_tests.cpp", "CMakeLists.txt"]
    if args.check:
        files += ["src/vm/native_observations.hpp", "src/vm/native_observations.cpp", "src/vm/ida_regions.hpp",
                  "src/vm/ida_regions.cpp", "src/vm/transition.cpp", "src/vm/semantics.cpp",
                  "src/vm/region.cpp", "tests/vm_native_observation_tests.cpp"]
        files += ["vendor/rax/src/isa/x86_64/decode/dispatch/legacy.rs", "vendor/rax/capi/src/reg.rs"]
    sources = {name: digest(root / name) for name in files}
    plugin_hash, ida_hash, corpus_hash = digest(args.plugin), digest(args.ida), digest(corpus_path)
    binaries = {"original": corpus["original_sha256"], **{p["label"]: p["sha256"] for p in corpus["protection"]}}
    report = {"schema": 1, "passed": False, "source_sha256": sources, "plugin_sha256": plugin_hash,
              "ida_sha256": ida_hash, "corpus_report_sha256": corpus_hash, "runs": [],
              "native_walk": args.walk,
              "native_check": args.check,
              "scope": "specified-input native observations; incomplete captures are not behavior recovery",
              "profile": "16 input triples per function, bounded initialized pointer objects, normal native analysis"}
    try:
        for label, sha in binaries.items():
            binary, run_dir = corpus_path.parent / label, output / label
            assert digest(binary) == sha
            command = [sys.executable, "-B", root / "tests/run_ida_smoke.py", binary,
                       root / "tests/ida_vm_native_input_probe.py", "--ida", args.ida.resolve(),
                       "--plugin", args.plugin.resolve(), "--output-dir", run_dir, "--enable-rax",
                       "--set", "CHERNOBOG_CORPUS_ENTRIES=" + json.dumps(corpus["selected_functions"]),
                       "--set", "CHERNOBOG_NATIVE_WALK=" + str(int(args.walk)),
                       "--set", "CHERNOBOG_NATIVE_CHECK=" + str(int(args.check)),
                       "--set", "CHERNOBOG_EXPECT_RETURN=" + str(int(label == "original" or label.startswith("mutation-")))]
            measurement, _, _ = execute(command, timeout=180)
            item = {"label": label, "input_sha256": sha, "runner_measurement": measurement}
            report["runs"].append(item)
            assert measurement["exit_code"] == 0 and not measurement["timed_out"] and not measurement["output_exceeded"]
            run = json.loads((run_dir / "run.json").read_text())
            capture = json.loads((run_dir / "vm_native_inputs.json").read_text())
            assert run["runner_return_code"] == 0 and run["artifacts_unchanged"] and run["source_script_unchanged"]
            assert run["input_sha256"] == sha and run["plugin_sha256"] == plugin_hash and run["ida_sha256"] == ida_hash
            assert run["script_sha256"] == sources["tests/ida_vm_native_input_probe.py"]
            assert capture["passed"] and not capture["errors"] and all(c["passed"] for c in capture["checks"])
            assert len(capture["captures"]) == 32
            # Recheck the returned values with the already independently executed
            # paired-corpus oracle, rather than trusting only the IDA probe.
            returned = 0
            stops = Counter()
            for record in capture["captures"]:
                trace, supplied = record["trace"], record["input"]
                stops[trace["stop"]] += 1
                if not trace["reached_sentinel"]:
                    continue
                returned += 1
                x, y = (int(s, 0) for s in supplied["args"][:2])
                initial = int.from_bytes(bytes.fromhex(supplied["objects"][0]["bytes"])[4:8], "little")
                result, flags, delta, left, changed, right = expected(int(record["name"] == "corpus_branch"), x, y, initial)
                mode = trace["address_bits"]
                registers = {int(row["reg"]): int(row["value"], 0) for row in trace["final_registers"]}
                assert registers[0x100 if mode == 64 else 0x200] == result
                assert registers[0x12 if mode == 64 else 0x13] & 0x8d5 == flags
                assert trace["sp_valid"] and trace["sp_delta"] - mode // 8 == delta
                assert bytes.fromhex(trace["input_objects"][0]["final"]) == b"".join(
                    value.to_bytes(4, "little") for value in (left, changed, right))
            item.update(checks=len(capture["checks"]), returned=returned, stops=dict(stops), captures=32,
                        inventory=capture["inventory_before"])
            item["artifact_sha256"] = {name: digest(run_dir / name) for name in ("run.json", "vm_native_inputs.json")}
            print(json.dumps({key: item[key] for key in ("label", "checks", "returned", "stops")}), flush=True)
        assert all(digest(root / name) == value for name, value in sources.items())
        assert digest(args.plugin) == plugin_hash and digest(args.ida) == ida_hash and digest(corpus_path) == corpus_hash
        assert all(digest(corpus_path.parent / name) == value for name, value in binaries.items())
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__
    finally:
        (output / "native_inputs_analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "runs": len(report["runs"]), "failure": report.get("failure")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(type(error).__name__, file=sys.stderr)
        sys.exit(1)
