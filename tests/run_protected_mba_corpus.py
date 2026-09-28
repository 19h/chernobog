"""Measure the complete paired SDK capture matrix on behavior-checked VMP corpora."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
from pathlib import Path
import sys
import struct

sys.dont_write_bytecode = True
from run_vmp_corpus import digest, execute, INPUT_SEEDS, PROTECTOR_SEEDS, text_section, verify
from mba_matching_diagnostics import validate_matching
from mba_match_replay import catalog, validate_inputs

ROOT = Path(__file__).resolve().parent.parent
SOURCES = (
    "tests/run_protected_mba_corpus.py",
    "tests/ida_protected_mba_probe.py",
    "tests/mba_matching_diagnostics.py",
    "tests/mba_match_replay.py",
    "src/deobf/analysis/match_capture.cpp",
    "src/deobf/analysis/match_capture.h",
    "tests/run_ida_smoke.py",
    "tests/run_vmp_corpus.py",
    "src/deobf/rules/rule_verifier.cpp",
    "src/deobf/rules/rule_verifier.h",
    "src/deobf/handlers/mba_simplify.cpp",
    "src/deobf/rules/rule_registry.cpp",
    "src/deobf/rules/rule_registry.h",
    "src/deobf/rules/pattern_rule.cpp",
    "src/deobf/rules/pattern_rule.h",
    "src/deobf/analysis/mba_diagnostics.cpp",
    "src/deobf/analysis/mba_diagnostics.hpp",
    "src/plugin/idc_api.cpp",
    "src/ida_analysis/native_engine.cpp",
    "src/ida_analysis/native_engine.hpp",
    "tests/catalog_tests.cpp",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def relative(path):
    path = Path(path).resolve()
    require(path.is_relative_to(ROOT), "artifact outside repository")
    return str(path.relative_to(ROOT))


def load_corpus(path, pins):
    pins[path] = digest(path)
    corpus = json.loads(path.read_text())
    require(corpus["passed"] and not corpus["smoke"], "incomplete native corpus")
    require(corpus["architecture"] in ("x86_64", "i386"), "native architecture")
    require(
        corpus["protector_seeds"] == list(PROTECTOR_SEEDS)
        and corpus["input_seeds"] == list(INPUT_SEEDS),
        "seed matrix",
    )
    require(
        corpus["held_out_protector_seed"] == PROTECTOR_SEEDS[-1]
        and corpus["held_out_input_seed"] == INPUT_SEEDS[-1],
        "evaluation partition",
    )
    for name, expected in corpus["source_sha256"].items():
        require(digest(ROOT / name) == expected, "native source changed")
        pins[ROOT / name] = expected
    labels = {
        f"{mode}-{seed}"
        for mode in ("mutation", "virtualization", "combined")
        for seed in PROTECTOR_SEEDS
    }
    protected = corpus["protection"]
    require(
        len(protected) == 9 and {p["label"] for p in protected} == labels, "protected population"
    )
    binaries = {"original": corpus["original_sha256"]}
    for item in protected:
        require(
            item["repeat_identical"] and item["protector_seed"] in PROTECTOR_SEEDS,
            "deterministic generation",
        )
        binaries[item["label"]] = item["sha256"]
    for label, expected in binaries.items():
        p = path.parent / label
        require(digest(p) == expected, "native binary changed")
        pins[p] = expected
    require(len(corpus["runs"]) == 30, "native run population")
    seen = set()
    for run in corpus["runs"]:
        key = run["label"], run["input_seed"]
        require(
            key not in seen and key[0] in binaries and key[1] in INPUT_SEEDS,
            "native run attribution",
        )
        seen.add(key)
        measure = run["measurement"]
        require(
            measure["exit_code"] == 0
            and not measure["timed_out"]
            and not measure["output_exceeded"]
            and run["matches_original_stdout"],
            "native run failed",
        )
        p = path.parent / run["observations"]
        require(p.resolve().is_relative_to(path.parent.resolve()), "native observation path")
        require(digest(p) == measure["stdout_sha256"], "native observations changed")
        require(
            verify(p.read_bytes(), key[1]) == run["oracle"] and run["oracle"]["passed"],
            "native integer oracle",
        )
        pins[p] = digest(p)
    require(
        set(corpus["selected_functions"]) == {"corpus_transform", "corpus_branch"},
        "selected entry population",
    )
    return corpus, binaries


def check_probe(probe, entries, disabled, legacy, native_disabled=True, matching_diagnostics=False):
    require(
        probe["passed"] and not probe["errors"] and probe["transformations_disabled"] == disabled,
        "SDK capture failed",
    )
    require(probe["native_analysis_disabled"] == native_disabled, "native analysis profile")
    captured_inputs = "matcher_catalog" in probe
    rules = probe["rule_catalog"]
    require(
        all(type(rules[k]) is int and rules[k] >= 0 for k in ("registered", "verified", "rejected"))
        and rules["registered"] == len(rules["names"]),
        "catalog certification counters",
    )
    require(
        (
            rules["verified"] == rules["rejected"] == 0
            if disabled
            else rules["verified"] + rules["rejected"] == rules["registered"]
        ),
        "catalog certification accounting",
    )
    if captured_inputs:
        model, patterns = catalog(
            probe["matcher_catalog"], probe["rule_catalog"]["names"], disabled
        )
        require(len(patterns) == rules["verified"], "certified catalog count")
    if not native_disabled:
        native = probe["native_statistics"]
        require(
            native["enabled"] == int(not disabled) and native["ran"] == 0,
            "native engine enabled attribution",
        )
        require(
            all(type(value) is int and value >= 0 for value in native.values()), "native statistic"
        )
    require(
        len(probe["entries"]) == 2 and {r["name"] for r in probe["entries"]} == set(entries),
        "SDK entry population",
    )
    totals = Counter()
    for row in probe["entries"]:
        require(row["entry"] == int(entries[row["name"]], 0), "SDK entry attribution")
        body = row["body"]
        if body is not None:
            require(
                row["direct_target"] == body["entry"]
                and body["name"] == row["name"] + ":direct_target",
                "SDK body attribution",
            )
        else:
            require(row["direct_target"] is None, "SDK missing direct target")
    population = [r for row in probe["entries"] for r in (row, row["body"]) if r is not None]
    for row in population:
        totals[row["status"]] += 1
        if row["status"] != "owned":
            require(
                row["status"] in ("ownerless", "entry_inside_owner", "native_range_quota")
                and not row["stages"],
                "unavailable owner has SDK capture",
            )
            continue
        require(
            row["owner"] == row["entry"] and row["native_bytes_unchanged"],
            "SDK native ownership or byte identity",
        )
        require([s["maturity"] for s in row["stages"]] == [1, 2, 3, 5], "SDK maturity matrix")
        for stage in row["stages"]:
            require(
                stage["status"]
                in ("captured", "sdk_refused", "block_quota", "node_or_depth_quota"),
                "SDK stage status",
            )
            totals[stage["status"]] += 1
            stats = stage["statistics"]
            if matching_diagnostics:
                require(stats.get("matching_available") is True, "matching diagnostic attribution")
                validate_matching(
                    stats["matching"], stats, row["entry"], stage["maturity"], disabled
                )
                if captured_inputs:
                    samples = validate_inputs(
                        stats["matching_inputs"],
                        stats,
                        row["entry"],
                        stage["maturity"],
                        disabled,
                        model,
                        patterns,
                    )
                    for sample in samples:
                        require(
                            sample["source"] == 2**64 - 1
                            or any(
                                c["start"] <= sample["source"] < c["end"]
                                for c in row["native_chunks"]
                            ),
                            "input source outside native owner",
                        )
            for name in (
                "total_matches",
                "successful_matches",
                "instance_verified",
                "instance_disproved",
                "instance_unsupported",
                "instance_unknown",
            ):
                require(type(stats[name]) is int and stats[name] >= 0, "SDK statistic")
                totals[name] += stats[name]
            require(stats["reasons_available"] == (not legacy), "reason API attribution")
            if not legacy:
                reasons = stats["rejection_reasons"]
                unrecorded = stats["unrecorded_rejections"]
                require(
                    len(reasons) <= 32 and type(unrecorded) is int and unrecorded >= 0,
                    "reason quota",
                )
                keys, recorded = set(), 0
                for reason in reasons:
                    key = reason["status"], reason["width_bits"], reason["reason"]
                    require(
                        key not in keys
                        and key[0] in ("disproved", "unsupported", "unknown")
                        and key[1] in (0, 8, 16, 32, 64)
                        and len(key[2].encode()) <= 256
                        and type(reason["count"]) is int
                        and reason["count"] > 0,
                        "reason entry",
                    )
                    keys.add(key)
                    recorded += reason["count"]
                require(
                    recorded + unrecorded
                    == sum(stats["instance_" + k] for k in ("disproved", "unsupported", "unknown")),
                    "reason accounting",
                )
                for status in ("disproved", "unsupported", "unknown"):
                    require(
                        sum(r["count"] for r in reasons if r["status"] == status)
                        <= stats["instance_" + status],
                        "reason status accounting",
                    )
            if disabled:
                require(
                    not any(stats[k] for k in stats if k.startswith("instance_"))
                    and stats["successful_matches"] == 0,
                    "disabled proposal applied",
                )
    require(
        probe["capture_nodes"] <= 8192 and probe["capture_text_bytes"] <= 524288, "capture quota"
    )
    return dict(totals)


def check_native_entries(probe, binary):
    data = binary.read_bytes()
    section = text_section(binary)
    require(section["file_backed"], "entry text mapping")
    for row in probe["entries"]:
        raw = bytes.fromhex(row["entry_bytes"])
        offset = row["entry"] - section["address"]
        require(0 <= offset and 1 <= len(raw) <= 15, "entry instruction bounds")
        require(offset + len(raw) <= section["size_bytes"], "entry text bounds")
        start = section["offset"] + offset
        require(data[start : start + len(raw)] == raw, "entry instruction bytes")
        if raw[0] in (0xE9, 0xEB):
            require(len(raw) == (5 if raw[0] == 0xE9 else 2), "direct entry jump width")
            displacement = struct.unpack("<i" if raw[0] == 0xE9 else "b", raw[1:])[0]
            bits = 64 if probe["architecture"] == "x86_64" else 32
            target = (row["entry"] + len(raw) + displacement) & ((1 << bits) - 1)
            require(row["direct_target"] == target, "independent direct entry target")
        else:
            require(row["direct_target"] is None, "unsupported direct entry form")


def controls(
    probe, entries, disabled, legacy, binary, native_disabled=True, matching_diagnostics=False
):
    trials = []

    def run(label, change):
        altered = copy.deepcopy(probe)
        change(altered)
        try:
            check_probe(altered, entries, disabled, legacy, native_disabled, matching_diagnostics)
            check_native_entries(altered, binary)
        except (ValueError, KeyError):
            trials.append(label)
            return
        raise ValueError("capture mutation accepted: " + label)

    run("duplicate entry", lambda p: p["entries"].append(copy.deepcopy(p["entries"][0])))
    run("changed registered catalog count", lambda p: p["rule_catalog"].update(registered=0))
    run(
        "changed certified catalog count",
        lambda p: p["rule_catalog"].update(verified=p["rule_catalog"]["verified"] + 1),
    )
    run(
        "changed rejected catalog count",
        lambda p: p["rule_catalog"].update(rejected=p["rule_catalog"]["rejected"] + 1),
    )
    run("changed entry", lambda p: p["entries"][0].update(entry=0))
    run("changed profile", lambda p: p.update(transformations_disabled=not disabled))
    run(
        "changed native analysis profile",
        lambda p: p.update(native_analysis_disabled=not native_disabled),
    )
    if not native_disabled:
        run(
            "changed native engine attribution",
            lambda p: p["native_statistics"].update(enabled=int(disabled)),
        )
    run("missing entry", lambda p: p["entries"].pop())
    run("changed entry bytes", lambda p: p["entries"][0].update(entry_bytes="00"))
    body = next((i for i, row in enumerate(probe["entries"]) if row["body"] is not None), None)
    if body is not None:
        run("changed body entry", lambda p: p["entries"][body]["body"].update(entry=0))

        def change_target(p):
            p["entries"][body]["direct_target"] += 1
            p["entries"][body]["body"]["entry"] += 1

        run("changed decoded target", change_target)
    owned = next((i for i, row in enumerate(probe["entries"]) if row["status"] == "owned"), None)
    if owned is not None:
        run("missing maturity", lambda p: p["entries"][owned]["stages"].pop())
        run(
            "changed native bytes",
            lambda p: p["entries"][owned].update(native_bytes_unchanged=False),
        )
        if not legacy:
            run(
                "lost rejection",
                lambda p: p["entries"][owned]["stages"][0]["statistics"].update(
                    instance_unsupported=p["entries"][owned]["stages"][0]["statistics"][
                        "instance_unsupported"
                    ]
                    + 1
                ),
            )
        if matching_diagnostics:

            def diagnostic(p):
                return p["entries"][owned]["stages"][0]["statistics"]["matching"]

            run(
                "lost matching API",
                lambda p: p["entries"][owned]["stages"][0]["statistics"].update(
                    matching_available=False
                ),
            )
            run(
                "changed matching event count",
                lambda p: diagnostic(p).update(events=diagnostic(p)["events"] + 1),
            )
            run(
                "changed matching quota accounting",
                lambda p: diagnostic(p).update(unrecorded=diagnostic(p)["unrecorded"] + 1),
            )
            retained = next(
                (
                    (i, j)
                    for i, row in enumerate(probe["entries"])
                    for j, stage in enumerate(row["stages"])
                    if stage["statistics"]["matching"]["samples"]
                ),
                None,
            )
            if retained is not None:

                def sampled(p):
                    return p["entries"][retained[0]]["stages"][retained[1]]["statistics"][
                        "matching"
                    ]

                run("changed matching owner", lambda p: sampled(p)["samples"][0].update(entry=0))
                run(
                    "changed matching maturity",
                    lambda p: sampled(p)["samples"][0].update(maturity=1000),
                )
                run(
                    "changed matching phase count",
                    lambda p: sampled(p)["samples"][0].update(structural_matches=10**9),
                )
                run(
                    "changed matching sample count",
                    lambda p: sampled(p)["samples"][0].update(count=0),
                )
                run(
                    "matching text quota",
                    lambda p: sampled(p)["samples"][0].update(reason="x" * 257),
                )
    return trials


def paired_summary(runs, native_disabled=True):
    profiles = {}
    for run in runs:
        key = run["architecture"], run["label"], run["disabled"]
        require(key not in profiles, "duplicate SDK process")
        path = next(p for p in run["artifact_sha256"] if p.endswith("/protected_mba.json"))
        profiles[key] = json.loads((ROOT / path).read_text())
    pairs, totals = [], Counter()
    for architecture, label in sorted({(a, label) for a, label, _ in profiles}):
        off, on = (profiles[architecture, label, disabled] for disabled in (True, False))
        for baseline, enabled in zip(off["entries"], on["entries"]):
            require(baseline["name"] == enabled["name"], "paired entry order")
            for kind, before, after in (
                ("entry", baseline, enabled),
                ("body", baseline["body"], enabled["body"]),
            ):
                require((before is None) == (after is None), "paired body population")
                if before is None:
                    continue
                ownership_equal = all(
                    before.get(k) == after.get(k)
                    for k in ("entry", "owner", "status", "native_chunks")
                )
                require(before["entry"] == after["entry"], "paired native entry")
                if native_disabled:
                    require(ownership_equal, "paired native ownership/bytes")
                pair = {
                    "architecture": architecture,
                    "label": label,
                    "name": baseline["name"],
                    "kind": kind,
                    "status": after["status"],
                    "off_status": before["status"],
                    "native_ownership_equal": ownership_equal,
                    "stages": [],
                }
                pairs.append(pair)
                totals[kind + "_" + after["status"]] += 1
                if not ownership_equal:
                    totals["native_ownership_changed"] += 1
                    continue
                require(len(before["stages"]) == len(after["stages"]), "paired stage population")
                for left, right in zip(before["stages"], after["stages"]):
                    require(left["maturity"] == right["maturity"], "paired stage maturity")
                    hashes = [
                        hashlib.sha256(
                            json.dumps(s["blocks"], sort_keys=True, separators=(",", ":")).encode()
                        ).hexdigest()
                        for s in (left, right)
                    ]
                    row = {
                        "maturity": right["maturity"],
                        "off_status": left["status"],
                        "on_status": right["status"],
                        "off_shape_sha256": hashes[0],
                        "on_shape_sha256": hashes[1],
                        "recorded_shapes_equal": hashes[0] == hashes[1],
                    }
                    pair["stages"].append(row)
                    totals["paired_stages"] += 1
                    totals["on_" + right["status"]] += 1
                    if left["status"] == right["status"] == "captured":
                        totals[
                            (
                                "captured_shape_equal"
                                if hashes[0] == hashes[1]
                                else "captured_shape_changed"
                            )
                        ] += 1
    return {
        "counts": dict(totals),
        "pairs": pairs,
        "scope": "recorded SDK shapes at matching native owners/bytes; ownership changes counted separately; no semantic equivalence or alias-identity claim",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-report", type=Path, action="append", required=True)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--legacy-reasons", action="store_true")
    parser.add_argument("--legacy-diagnostics", action="store_true")
    parser.add_argument("--native-analysis", action="store_true")
    parser.add_argument("--matcher-inputs", action="store_true")
    parser.add_argument("--input-limit", type=int, choices=(64, 1024), default=64)
    parser.add_argument(
        "--workers", type=int, default=2, help="Concurrent SDK processes, from 1 to 2"
    )
    parser.add_argument(
        "--timeout", type=int, default=300, help="Per-process wall-clock cap in seconds"
    )
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "schema": 1,
        "passed": False,
        "runs": [],
        "legacy_reasons": args.legacy_reasons,
        "matching_diagnostics": not (args.legacy_diagnostics or args.legacy_reasons),
        "native_analysis_disabled": not args.native_analysis,
        "matcher_inputs": args.matcher_inputs,
        "input_limit": args.input_limit,
        "workers": args.workers,
        "process_timeout_seconds": args.timeout,
    }
    try:
        require(1 <= args.timeout <= 600, "process timeout bound")
        require(1 <= args.workers <= 2, "SDK worker bound")
        require(
            args.matcher_inputs or args.input_limit == 64, "input limit requires matcher capture"
        )
        pins = {ROOT / name: digest(ROOT / name) for name in SOURCES}
        pins[args.ida], pins[args.plugin] = digest(args.ida), digest(args.plugin)
        ida_components = {}
        for name in (
            "libida.dylib",
            "libidalib.dylib",
            "procs/pc.dylib",
            "plugins/hexx64.dylib",
            "plugins/goomba.dylib",
            "cfg/goomba.cfg",
        ):
            component = args.ida.parent / name
            require(component.is_file(), "recorded macOS IDA component missing")
            pins[component] = digest(component)
            ida_components["<ida>/" + name] = pins[component]
        corpora = [load_corpus(p.resolve(), pins) for p in args.corpus_report]
        require(
            len(corpora) == 2 and {c[0]["architecture"] for c in corpora} == {"x86_64", "i386"},
            "complete architecture matrix",
        )
        tasks = [
            (path.resolve(), corpus, label, sha, disabled)
            for path, (corpus, binaries) in zip(args.corpus_report, corpora)
            for label, sha in binaries.items()
            for disabled in (True, False)
        ]

        def capture(task):
            path, corpus, label, sha, disabled = task
            destination = (
                output / corpus["architecture"] / (label + ("-off" if disabled else "-on"))
            )
            command = [
                sys.executable,
                "-B",
                ROOT / "tests/run_ida_smoke.py",
                path.parent / label,
                ROOT / "tests/ida_protected_mba_probe.py",
                "--ida",
                args.ida,
                "--plugin",
                args.plugin,
                "--output-dir",
                destination,
                "--set",
                "CHERNOBOG_MBA_CORPUS_ENTRIES=" + json.dumps(corpus["selected_functions"]),
            ]
            if not args.native_analysis:
                command += ["--set", "CHERNOBOG_IDA_ANALYSIS=0"]
            else:
                command += ["--set", "CHERNOBOG_CAPTURE_NATIVE_STATS=1"]
            if args.matcher_inputs:
                command += ["--set", "CHERNOBOG_MBA_CAPTURE_INPUTS=1"]
                if args.input_limit != 64:
                    command += ["--set", f"CHERNOBOG_MBA_INPUT_LIMIT={args.input_limit}"]
            if disabled:
                command += ["--set", "CHERNOBOG_DISABLE=1"]
            if args.legacy_reasons:
                command += ["--set", "CHERNOBOG_MBA_LEGACY_REASONS=1"]
            if args.legacy_diagnostics:
                command += ["--set", "CHERNOBOG_MBA_LEGACY_DIAGNOSTICS=1"]
            measurement, _, _ = execute(command, timeout=args.timeout)
            if (
                measurement["exit_code"] != 0
                or measurement["timed_out"]
                or measurement["output_exceeded"]
            ):
                return {
                    "architecture": corpus["architecture"],
                    "label": label,
                    "disabled": disabled,
                    "binary_sha256": sha,
                    "measurement": measurement,
                    "counts": {"process_failed": 1},
                    "failure": "SDK process failed",
                }
            require(
                measurement["exit_code"] == 0
                and not measurement["timed_out"]
                and not measurement["output_exceeded"],
                "SDK process failed",
            )
            probe = json.loads((destination / "protected_mba.json").read_text())
            require(
                ("matcher_catalog" in probe) == args.matcher_inputs,
                "matcher input profile attribution",
            )
            if args.matcher_inputs:
                for item in probe["entries"]:
                    for row in (item, item.get("body")):
                        if row is None:
                            continue
                        for stage in row["stages"]:
                            require(
                                stage["statistics"]["matching_inputs"]["sample_limit"]
                                == args.input_limit,
                                "requested input limit differs from SDK capture",
                            )
            require(probe["architecture"] == corpus["architecture"], "SDK architecture")
            totals = check_probe(
                probe,
                corpus["selected_functions"],
                disabled,
                args.legacy_reasons,
                not args.native_analysis,
                report["matching_diagnostics"],
            )
            check_native_entries(probe, path.parent / label)
            manifest = json.loads((destination / "run.json").read_text())
            require(
                manifest["input_sha256"] == sha
                and manifest["plugin_sha256"] == pins[args.plugin]
                and manifest["ida_sha256"] == pins[args.ida]
                and manifest["artifacts_unchanged"]
                and manifest["runner_return_code"] == 0,
                "SDK process attribution",
            )
            return {
                "architecture": corpus["architecture"],
                "label": label,
                "disabled": disabled,
                "binary_sha256": sha,
                "measurement": measurement,
                "counts": totals,
                "native_statistics": probe.get("native_statistics"),
                "mutation_controls": controls(
                    probe,
                    corpus["selected_functions"],
                    disabled,
                    args.legacy_reasons,
                    path.parent / label,
                    not args.native_analysis,
                    report["matching_diagnostics"],
                ),
                "artifact_sha256": {
                    relative(destination / name): digest(destination / name)
                    for name in ("run.json", "protected_mba.json")
                },
            }

        def recorded_capture(task):
            try:
                return capture(task)
            except (ValueError, KeyError, OSError) as error:
                _, corpus, label, sha, disabled = task
                # Preserve a terminal row for every scheduled profile. A failed
                # validation must not suppress later results or become success.
                return {
                    "architecture": corpus["architecture"],
                    "label": label,
                    "disabled": disabled,
                    "binary_sha256": sha,
                    "measurement": None,
                    "counts": {"capture_validation_failed": 1},
                    "failure": type(error).__name__ + ": " + str(error),
                }

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            for row in executor.map(recorded_capture, tasks):
                report["runs"].append(row)
                print(
                    json.dumps(
                        {k: row[k] for k in ("architecture", "label", "disabled", "counts")}
                    ),
                    flush=True,
                )
        require(len(report["runs"]) == 40, "SDK run population")
        require(not any("failure" in row for row in report["runs"]), "SDK capture failed")
        report["paired"] = paired_summary(report["runs"], not args.native_analysis)
        for row in report["runs"]:
            for name, sha in row["artifact_sha256"].items():
                pins[ROOT / name] = sha
        require(all(digest(p) == sha for p, sha in pins.items()), "measured artifact changed")
        report.update(
            source_sha256={name: pins[ROOT / name] for name in SOURCES},
            plugin_sha256=pins[args.plugin],
            ida_sha256=pins[args.ida],
            ida_components_sha256=ida_components,
            artifact_sha256={
                relative(p): sha for p, sha in pins.items() if p.resolve().is_relative_to(ROOT)
            },
            passed=True,
        )
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    (output / "protected_mba_analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "runs": len(report["runs"]),
                "failure": report.get("failure"),
            }
        ),
        flush=True,
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
