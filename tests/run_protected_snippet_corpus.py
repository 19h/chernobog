"""Compare bounded x86-64 protected prefixes with independent file/decoder checks."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import struct
import sys

import capstone

sys.dont_write_bytecode = True
from run_protected_mba_corpus import load_corpus
from run_vmp_corpus import digest, execute

ROOT = Path(__file__).resolve().parent.parent
SOURCES = (
    "src/ida_analysis/native_engine.cpp",
    "src/ida_analysis/native_engine.hpp",
    "src/plugin/idc_api.cpp",
    "tests/ida_protected_snippet_probe.py",
    "tests/run_protected_snippet_corpus.py",
    "tests/run_protected_mba_corpus.py",
    "tests/run_ida_smoke.py",
    "tests/run_vmp_corpus.py",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_bytes(data, address, size):
    require(data[:4] == b"\xcf\xfa\xed\xfe", "Mach-O64 input")
    commands, command_bytes = struct.unpack_from("<II", data, 16)
    require(commands <= 4096 and 32 + command_bytes <= len(data), "command bounds")
    offset, hits = 32, []
    for _ in range(commands):
        command, length = struct.unpack_from("<II", data, offset)
        require(length >= 8 and offset + length <= 32 + command_bytes, "command extent")
        if command == 0x19:
            require(length >= 72, "segment command")
            start, memory_size, file_offset, file_size = struct.unpack_from(
                "<QQQQ", data, offset + 24
            )
            permissions = struct.unpack_from("<I", data, offset + 60)[0]
            require(file_offset + file_size <= len(data), "file segment extent")
            if start <= address and address + size <= start + min(memory_size, file_size):
                require(permissions & 4, "nonexecutable instruction bytes")
                position = file_offset + address - start
                hits.append(data[position : position + size])
        offset += length
    require(offset == 32 + command_bytes and len(hits) == 1, "unique file-backed instruction")
    return hits[0]


def verify_capture(report, binary):
    require(report["passed"] and not report["errors"], "prefix capture failed")
    require(report["architecture"] == "x86_64", "prefix architecture")
    require(report["inventory_before"] == report["inventory_after"], "inspection changed inventory")
    require(
        {e["name"] for e in report["entries"]} == {"corpus_transform", "corpus_branch"}
        and len(report["entries"]) == 2,
        "prefix population",
    )
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    data, total = binary.read_bytes(), 0
    for row in report["entries"]:
        require(
            0 < len(row["native"]) <= 16 and 0 < row["end"] - row["target"] <= 128, "prefix budget"
        )
        cursor = row["target"]
        for native in row["native"]:
            require(native["ea"] == cursor, "linear native prefix")
            raw = file_bytes(data, cursor, native["size"])
            require(raw.hex() == native["bytes"], "prefix differs from input file")
            decoded = list(decoder.disasm(raw, cursor))
            require(len(decoded) == 1 and decoded[0].size == native["size"], "independent decode")
            cursor += native["size"]
            total += 1
        require(cursor == row["end"] and row["native_bytes_unchanged"], "prefix end/byte identity")
        require(
            row["native_code_heads"] == sum(n["code_head"] for n in row["native"]),
            "code-head accounting",
        )
        require([s["maturity"] for s in row["stages"]] == [1, 2, 3, 5], "stage population")
        for stage in row["stages"]:
            require(stage["status"] in ("captured", "sdk_refused"), "unexpected stage outcome")
            if stage["status"] == "captured":
                actual = sorted({i[0] for b in stage["blocks"] for i in b["instructions"]})
                require(stage["source_eas"] == actual, "SDK source-site accounting")
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-report", type=Path, required=True)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--prior", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": 1, "passed": False, "runs": [], "pairs": [], "scope": __doc__}
    try:
        pins = {ROOT / name: digest(ROOT / name) for name in SOURCES}
        source_pins = {name: pins[ROOT / name] for name in SOURCES}
        for path in (args.ida, args.prior, args.current):
            pins[path] = digest(path)
        corpus, binaries = load_corpus(args.corpus_report.resolve(), pins)
        require(corpus["architecture"] == "x86_64", "x86-64 prefix corpus")
        report["source_sha256"] = source_pins
        report["plugin_sha256"] = {
            k: pins[p] for k, p in (("prior", args.prior), ("current", args.current))
        }
        report["ida_sha256"] = pins[args.ida]
        report["capstone_version"] = capstone.__version__
        report["ida_components_sha256"] = {}
        for name in (
            "libida.dylib",
            "libidalib.dylib",
            "procs/pc.dylib",
            "plugins/hexx64.dylib",
            "plugins/goomba.dylib",
            "cfg/goomba.cfg",
        ):
            path = args.ida.parent / name
            pins[path] = digest(path)
            report["ida_components_sha256"]["<ida>/" + name] = pins[path]

        def capture(task):
            profile, plugin, label = task
            binary = args.corpus_report.parent / label
            destination = output / (label + "-" + profile)
            command = [
                sys.executable,
                "-B",
                ROOT / "tests/run_ida_smoke.py",
                binary,
                ROOT / "tests/ida_protected_snippet_probe.py",
                "--ida",
                args.ida,
                "--plugin",
                plugin,
                "--output-dir",
                destination,
                "--set",
                "CHERNOBOG_MBA_CORPUS_ENTRIES=" + json.dumps(corpus["selected_functions"]),
            ]
            measure, _, _ = execute(command, timeout=120)
            require(
                measure["exit_code"] == 0
                and not measure["timed_out"]
                and not measure["output_exceeded"],
                "prefix process failed",
            )
            path = destination / "protected_snippet.json"
            captured = json.loads(path.read_text())
            decoded = verify_capture(captured, binary)
            return {
                "profile": profile,
                "label": label,
                "binary_sha256": binaries[label],
                "measurement": measure,
                "independent_decodes": decoded,
                "capture": str(path.relative_to(ROOT)),
                "capture_sha256": digest(path),
                "run_sha256": digest(destination / "run.json"),
            }

        tasks = [
            (profile, plugin, label)
            for label in binaries
            for profile, plugin in (("prior", args.prior), ("current", args.current))
        ]
        with ThreadPoolExecutor(max_workers=2) as pool:
            for run in pool.map(capture, tasks):
                report["runs"].append(run)
                print(json.dumps(run), flush=True)
        require(all(digest(p) == sha for p, sha in pins.items()), "input/tool/source changed")
        for label in binaries:
            profiles = {}
            for profile in ("prior", "current"):
                row = next(
                    r for r in report["runs"] if r["label"] == label and r["profile"] == profile
                )
                profiles[profile] = json.loads((ROOT / row["capture"]).read_text())
            for before, after in zip(profiles["prior"]["entries"], profiles["current"]["entries"]):
                require(
                    all(before[k] == after[k] for k in ("name", "entry", "target", "end", "owner")),
                    "paired prefix or owner changed",
                )
                require(
                    [{k: v for k, v in n.items() if k != "code_head"} for n in before["native"]]
                    == [{k: v for k, v in n.items() if k != "code_head"} for n in after["native"]],
                    "paired native instructions changed",
                )
                report["pairs"].append(
                    {
                        "label": label,
                        "name": before["name"],
                        "owner": after["owner"],
                        "native_instructions": len(after["native"]),
                        "prior_heads": before["native_code_heads"],
                        "current_heads": after["native_code_heads"],
                        "prior_generated_sites": before["stages"][0].get("source_eas", []),
                        "current_generated_sites": after["stages"][0].get("source_eas", []),
                    }
                )
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    (output / "protected_snippets.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "runs": len(report["runs"])}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
