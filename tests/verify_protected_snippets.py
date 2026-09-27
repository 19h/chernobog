"""Audit paired prefix attribution, input bytes and corrupted capture controls."""

import argparse
import copy
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from run_protected_snippet_corpus import ROOT, file_bytes, require, verify_capture
from run_vmp_corpus import digest


def corruption_controls(capture, binary):
    controls = []

    def trial(name, edit):
        wrong = copy.deepcopy(capture)
        edit(wrong)
        try:
            verify_capture(wrong, binary)
        except (ValueError, KeyError):
            controls.append(name)
            return
        raise ValueError("corrupted capture accepted: " + name)

    first = lambda report: report["entries"][0]
    node = lambda report: first(report)["native"][0]
    trial("changed native byte", lambda r: node(r).update(bytes="00"))
    trial("changed native width", lambda r: node(r).update(size=15))
    trial("changed native address", lambda r: node(r).update(ea=node(r)["ea"] + 1))
    trial("wrong prefix end", lambda r: first(r).update(end=first(r)["end"] + 1))
    trial("missing native instruction", lambda r: first(r)["native"].pop())
    trial("wrong code-head count", lambda r: first(r).update(native_code_heads=99))
    trial("missing maturity", lambda r: first(r)["stages"].pop())
    trial("wrong SDK source sites", lambda r: first(r)["stages"][0].update(source_eas=[]))
    trial("wrong architecture", lambda r: r.update(architecture="i386"))
    trial("changed inventory", lambda r: r["inventory_after"].update(heads=-1))
    return controls


def audit(path, corpus_path):
    report = json.loads(path.read_text())
    corpus = json.loads(corpus_path.read_text())
    require(
        report["passed"] and corpus["passed"] and len(report["runs"]) == 20, "capture population"
    )
    require(
        all(digest(ROOT / n) == sha for n, sha in report["source_sha256"].items()), "source changed"
    )
    labels = {"original"} | {row["label"] for row in corpus["protection"]}
    seen, captures, controls, decoded = set(), {}, [], 0
    for row in report["runs"]:
        key = row["profile"], row["label"]
        require(
            key not in seen and key[0] in ("prior", "current") and key[1] in labels,
            "run attribution",
        )
        seen.add(key)
        raw = (ROOT / row["capture"]).resolve()
        require(
            raw.is_relative_to(ROOT) and digest(raw) == row["capture_sha256"], "capture identity"
        )
        run_path = raw.parent / "run.json"
        require(digest(run_path) == row["run_sha256"], "run identity")
        run = json.loads(run_path.read_text())
        require(
            run["plugin_sha256"] == report["plugin_sha256"][key[0]]
            and run["ida_sha256"] == report["ida_sha256"]
            and run["source_script_sha256"]
            == report["source_sha256"]["tests/ida_protected_snippet_probe.py"]
            and run["runner_return_code"] == 0
            and run["artifacts_unchanged"],
            "process/tool attribution",
        )
        binary = corpus_path.parent / key[1]
        require(digest(binary) == row["binary_sha256"] == run["input_sha256"], "binary identity")
        captured = json.loads(raw.read_text())
        count = verify_capture(captured, binary)
        require(count == row["independent_decodes"], "decoder count")
        data = binary.read_bytes()
        for entry in captured["entries"]:
            address = int(corpus["selected_functions"][entry["name"]], 0)
            require(entry["entry"] == address, "selected entry")
            raw_entry = file_bytes(data, address, 5)
            target = (
                address + 5 + int.from_bytes(raw_entry[1:], "little", signed=True)
                if raw_entry[0] == 0xE9
                else address
            )
            require(entry["target"] == target, "direct jump target")
        decoded += count
        captures[key] = captured
    require(
        seen == {(profile, label) for profile in ("prior", "current") for label in labels},
        "profile population",
    )
    require(len(report["pairs"]) == 20, "paired prefix population")
    for pair in report["pairs"]:
        before, after = [
            next(
                e for e in captures[profile, pair["label"]]["entries"] if e["name"] == pair["name"]
            )
            for profile in ("prior", "current")
        ]
        for field in ("entry", "target", "end", "owner", "native"):
            require(before[field] == after[field], "paired native inventory changed")
        require(
            pair["prior_heads"] == before["native_code_heads"]
            and pair["current_heads"] == after["native_code_heads"]
            and pair["prior_generated_sites"] == before["stages"][0].get("source_eas", [])
            and pair["current_generated_sites"] == after["stages"][0].get("source_eas", []),
            "paired metric attribution",
        )
    positive = captures["current", "mutation-0"]
    controls = corruption_controls(positive, corpus_path.parent / "mutation-0")
    return {
        "passed": True,
        "processes": 20,
        "paired_prefixes": 20,
        "independent_decodes": decoded,
        "corruption_controls": controls,
        "source_inventory_and_generated_sites_equal": True,
        "report_sha256": digest(path),
        "corpus_sha256": digest(corpus_path),
        "scope": "file-backed instruction extents and recorded snippet attribution; no protected recovery gain, whole-body, value, flags or fault equivalence",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--corpus-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {"passed": False}
    try:
        pins = {p: digest(p) for p in (args.report, args.corpus_report, Path(__file__))}
        result = audit(args.report, args.corpus_report)
        require(all(digest(p) == sha for p, sha in pins.items()), "audit input changed")
    except Exception as error:
        result["failure"] = type(error).__name__ + ": " + str(error)
    result["verifier_sha256"] = digest(Path(__file__))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
