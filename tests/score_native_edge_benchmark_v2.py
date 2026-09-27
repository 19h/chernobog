"""Score the reviewed current native oracle and independently check destination covers."""

import argparse
import copy
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import capstone
from capstone.x86_const import X86_OP_IMM, X86_OP_REG

from run_vmp_corpus import text_section
from score_native_edge_benchmark import classification, digest, one_record, require, symbols

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "tests/vmp_native/edge_oracle_v2.json"
CONTRACT_SHA256 = "49013ae63837f481a1b795eb3059d9bca99771b7eca48cc8aca2fbd8be0053b9"


def relative(path):
    require(Path(path).resolve().is_relative_to(ROOT), "artifact outside repository")
    return str(Path(path).resolve().relative_to(ROOT))


def contract():
    require(digest(CONTRACT) == CONTRACT_SHA256, "oracle contract changed")
    result = json.loads(CONTRACT.read_text())
    require(result["schema"] == 2, "invalid oracle schema")
    for name, expected in result["source_sha256"].items():
        require(digest(ROOT / name) == expected, "reviewed source changed: " + name)
    classes = [set(result[name]) for name in ("fixed", "dynamic", "concrete_only")]
    require(len(set.union(*classes)) == sum(map(len, classes)), "overlapping oracle classes")
    require(
        result["expected_population"]
        == {
            "fixed_sites": len(classes[0]),
            "dynamic_sites": len(classes[1]),
            "eligible_sites": len(classes[0]) + len(classes[1]),
            "oracle_edges": len(classes[0]) + sum(map(len, result["dynamic"].values())),
            "concrete_only_sites": len(classes[2]),
        },
        "oracle population contradiction",
    )
    return result


def decode_oracle(binary, nm, architecture, oracle):
    names = symbols(nm, binary)
    image, section = binary.read_bytes(), text_section(binary)
    require(section["file_backed"], "text is not file backed")
    first, length = section["address"], section["size_bytes"]
    text = image[section["offset"] : section["offset"] + length]
    decoder = capstone.Cs(
        capstone.CS_ARCH_X86,
        capstone.CS_MODE_64 if architecture == "x86_64" else capstone.CS_MODE_32,
    )
    decoder.detail = True

    def encoded(address, size):
        require(first <= address and address + size <= first + length, "oracle outside text")
        return text[address - first : address - first + size]

    for name, value in oracle["target_return_values"].items():
        require(name in names, "oracle target label absent")
        instructions = []
        for item in decoder.disasm(encoded(names[name], 24), names[name]):
            instructions.append(item)
            if item.mnemonic == "ret":
                break
        stack = name.startswith("df_stack_top_")
        require(len(instructions) == (3 if stack else 2), "target return shape changed")
        if stack:
            item = instructions[0]
            require(
                item.mnemonic == "add"
                and item.reg_name(item.operands[0].reg)
                == ("rsp" if architecture == "x86_64" else "esp")
                and item.operands[1].type == X86_OP_IMM
                and item.operands[1].imm == (8 if architecture == "x86_64" else 4),
                "target stack adjustment changed",
            )
        item = instructions[-2]
        require(
            item.mnemonic == "mov"
            and item.operands[0].type == X86_OP_REG
            and item.reg_name(item.operands[0].reg) == "eax"
            and item.operands[1].type == X86_OP_IMM
            and item.operands[1].imm == value
            and instructions[-1].mnemonic == "ret"
            and not instructions[-1].op_str,
            "target return value changed",
        )
    target_addresses = [names[name] for name in oracle["target_return_values"]]
    require(len(target_addresses) == len(set(target_addresses)), "oracle target labels collapse")
    left, right = [names[name] for name in oracle["byte_patch_target_pair"]]
    require(left >> 8 == right >> 8 and left != right, "byte-target layout changed")
    cases = []
    for cohort in ("fixed", "dynamic", "concrete_only"):
        for name, targets in oracle[cohort].items():
            require(name in names, "oracle root absent")
            start = names[name]
            end = min([first + length] + [ea for ea in names.values() if ea > start])
            require(0 < end - start <= 512, "root decode bounds changed")
            instructions = list(decoder.disasm(encoded(start, end - start), start))
            pairs = [
                (a, b)
                for a, b in zip(instructions, instructions[1:])
                if a.mnemonic == "push" and b.mnemonic == "ret" and not b.op_str
            ]
            require(len(pairs) == 1, "missing or duplicate independent PUSH/RET site")
            push, transfer = pairs[0]
            require(
                push.operands[0].size == (8 if architecture == "x86_64" else 4)
                and 0x66 not in transfer.prefix,
                "transfer operand width changed",
            )
            target_names = targets if cohort == "dynamic" else [targets]
            require(all(target in names for target in target_names), "target symbol absent")
            expected = sorted(names[target] for target in target_names)
            require(len(expected) == len(set(expected)), "oracle case targets collapse")
            cases.append(
                {
                    "name": name,
                    "class": cohort,
                    "root": start,
                    "push": push.address,
                    "source": transfer.address,
                    "oracle_targets": expected,
                    "target_labels": target_names,
                    "push_bytes": bytes(push.bytes).hex(),
                    "source_bytes": bytes(transfer.bytes).hex(),
                }
            )
    return {"cases": cases, "encoded": encoded}


def score_case(capture, case, owned, encoded, architecture):
    if owned:
        require(
            capture["available"] and int(capture["function"], 0) == case["root"],
            "owned root mismatch",
        )
        row = one_record(capture, "stack-transfer")
        require(row["validation"] == "current", "owned validation is stale")
        require(
            int(row["site"], 0) == case["source"] and int(row["source"], 0) == case["push"],
            "owned transfer site mismatch",
        )
        published = capture["user_edges"].get(row["site"])
        require(isinstance(published, list), "missing owned user-edge inventory")
        require(
            published == ([row["target"]] if row["edge"] == "true" else []),
            "owned publication and proof disagree",
        )
    else:
        require(
            capture["inventory_before"] == capture["inventory_after"],
            "ownerless inspection mutated IDB",
        )
        facts = capture["facts"]
        require(
            facts["available"]
            and facts["converged"]
            and not facts["truncated"]
            and not facts["published"]
            and int(facts["root"], 0) == case["root"],
            "ownerless root incomplete",
        )
        row = one_record(facts, "push-return")
        require(
            int(row["site"], 0) == case["push"] and int(row["transfer"], 0) == case["source"],
            "ownerless transfer site mismatch",
        )
        published = None
    expected = set(case["oracle_targets"])
    outcome = classification(row, expected, case["class"], owned)
    values = [int(v, 0) for v in row["target_cover_values"].split(";") if v]
    require(
        values == sorted(set(values))
        and len(values) == int(row["target_cover_count"])
        and len(values) <= 8,
        "invalid cover members",
    )
    bits = 64 if architecture == "x86_64" else 32
    require(
        int(row["width_bits"]) == bits
        and int(row["stack_write_bytes"]) == bits // 8
        and int(row["stack_delta_bytes"]) == 0,
        "transfer width or stack effects contradict the oracle",
    )
    require(all(0 <= v < 1 << bits for v in values), "cover member width overflow")
    complete = row["target_cover_complete"] == "true"
    require(row["target_cover_complete"] in ("true", "false"), "invalid cover completeness")
    require(row["target_cover_widened"] in ("true", "false"), "invalid cover widening")
    status = row["target_cover_status"]
    require(status in ("complete", "partial", "unresolved", "unavailable"), "invalid cover status")
    require((status == "complete") == complete, "contradictory cover status")
    require(row["target_cover_validation"] == "recomputed", "cover validation is stale")
    unknown = int(row["target_cover_unknown_inputs"])
    require(
        unknown >= 0 and (not complete or (unknown == 0 and values)),
        "complete cover has unknown inputs",
    )
    require(status != "unresolved" or not values, "unresolved cover has members")
    require(status != "partial" or (values and not complete), "partial cover lacks members")
    if outcome != "unresolved":
        require(complete and values == [int(row["target"], 0)], "scalar proof and cover disagree")
    support = []
    for item in row["target_cover_support"].split(";"):
        if not item:
            continue
        address, data = item.split(":")
        address, data = int(address, 0), bytes.fromhex(data)
        require(data and data == encoded(address, len(data)), "cover supporting bytes changed")
        support.append(address)
    require(support == sorted(set(support)), "invalid cover support order")
    require(
        not complete or {case["push"], case["source"]} <= set(support),
        "complete cover lacks transfer support",
    )
    members = set(values)
    missing, extra = expected - members, members - expected
    if case["class"] == "concrete_only":
        cover_outcome = "excluded"
    elif not complete:
        cover_outcome = "incomplete"
    elif missing:
        cover_outcome = "unsound"
    elif extra:
        cover_outcome = "sound_superset"
    else:
        cover_outcome = "exact"
    return {
        **{k: v for k, v in case.items() if k not in ("oracle_targets",)},
        "oracle_targets": [hex(v) for v in case["oracle_targets"]],
        "reported_target": row.get("target", "unknown"),
        "owned_user_edges": published,
        "edge_outcome": outcome,
        "cover_outcome": cover_outcome,
        "cover_complete": complete,
        "cover_widened": row["target_cover_widened"] == "true",
        "cover_unknown_inputs": unknown,
        "cover_reason": row["target_cover_reason"],
        "cover_members": [hex(v) for v in values],
        "missing_members": [hex(v) for v in sorted(missing)],
        "extra_members": [hex(v) for v in sorted(extra)],
    }


def counts(cases):
    eligible = [r for r in cases if r["class"] != "concrete_only"]
    excluded = [r for r in cases if r["class"] == "concrete_only"]
    result = {
        "eligible_sites": len(eligible),
        "oracle_edges": sum(len(r["oracle_targets"]) for r in eligible),
        "correct_edges": sum(r["edge_outcome"] == "correct" for r in eligible),
        "false_edges": sum(r["edge_outcome"] == "false" for r in eligible),
        "unresolved_candidates": sum(r["edge_outcome"] == "unresolved" for r in eligible),
        "complete_covers": sum(r["cover_complete"] for r in eligible),
        "exact_covers": sum(r["cover_outcome"] == "exact" for r in eligible),
        "unsound_covers": sum(r["cover_outcome"] == "unsound" for r in eligible),
        "sound_superset_covers": sum(r["cover_outcome"] == "sound_superset" for r in eligible),
        "incomplete_covers": sum(r["cover_outcome"] == "incomplete" for r in eligible),
        "complete_cover_missing_members": sum(
            len(r["missing_members"]) for r in eligible if r["cover_complete"]
        ),
        "complete_cover_extra_members": sum(
            len(r["extra_members"]) for r in eligible if r["cover_complete"]
        ),
        "concrete_only_candidates": len(excluded),
        "concrete_only_unresolved": sum(r["edge_outcome"] == "unresolved" for r in excluded),
        "concrete_only_matching_targets": sum(r["edge_outcome"] == "correct" for r in excluded),
        "concrete_only_mismatches": sum(r["edge_outcome"] == "false" for r in excluded),
        "cover_reasons": {},
    }
    for row in eligible:
        reason = row["cover_reason"]
        result["cover_reasons"][reason] = result["cover_reasons"].get(reason, 0) + 1
    result["missed_oracle_edges"] = result["oracle_edges"] - result["correct_edges"]
    return result


def mutation_controls(captures, decoded, owned, architecture):
    selected = {r["name"]: r for r in decoded["cases"]}
    fixed, dynamic = "df_memory_mov_load", "df_memory_conflicting_store"
    results = []

    def run(label, name, mutate, expected=None):
        capture, case = copy.deepcopy(captures[name]), selected[name]
        rows = (capture if owned else capture["facts"])["records"]
        row = one_record({"records": rows}, "stack-transfer" if owned else "push-return")
        mutate(capture, row, case)
        try:
            result = score_case(capture, case, owned, decoded["encoded"], architecture)
        except ValueError:
            require(expected is None, "mutation classified as malformed: " + label)
            outcome = "rejected"
        else:
            require(
                expected is not None and expected(result), "mutation was not detected: " + label
            )
            outcome = result["edge_outcome"] + "/" + result["cover_outcome"]
        results.append({"name": label, "outcome": outcome})

    def scalar(capture, row, case):
        target = case["oracle_targets"][-1] + (16 if case["class"] == "fixed" else 0)
        row.update(
            target=hex(target),
            target_cover_values=hex(target),
            target_cover_count="1",
            target_cover_complete="true",
            target_cover_status="complete",
            target_cover_unknown_inputs="0",
        )
        if owned:
            row.update(edge="true", truth="native-proof")
            capture["user_edges"][row["site"]] = [hex(target)]
        else:
            row["status"] = "proved"

    run(
        "wrong fixed target",
        fixed,
        scalar,
        lambda r: r["edge_outcome"] == "false" and r["cover_outcome"] == "unsound",
    )
    run(
        "unconditional dynamic target",
        dynamic,
        scalar,
        lambda r: r["edge_outcome"] == "false" and r["cover_outcome"] == "unsound",
    )
    run(
        "complete cover missing member",
        dynamic,
        lambda c, r, s: r.update(
            target_cover_values=hex(s["oracle_targets"][0]), target_cover_count="1"
        ),
        lambda r: r["edge_outcome"] == "unresolved" and r["cover_outcome"] == "unsound",
    )
    run(
        "sound imprecise superset",
        dynamic,
        lambda c, r, s: r.update(
            target_cover_values=";".join(
                hex(v) for v in sorted(s["oracle_targets"] + [s["oracle_targets"][-1] + 16])
            ),
            target_cover_count="3",
        ),
        lambda r: r["edge_outcome"] == "unresolved" and r["cover_outcome"] == "sound_superset",
    )
    run(
        "duplicate cover member",
        dynamic,
        lambda c, r, s: r.update(
            target_cover_values=hex(s["oracle_targets"][0]) + ";" + hex(s["oracle_targets"][0]),
            target_cover_count="2",
        ),
    )
    run(
        "complete cover unknown input",
        dynamic,
        lambda c, r, s: r.update(target_cover_unknown_inputs="1"),
    )
    run(
        "contradictory cover status",
        dynamic,
        lambda c, r, s: r.update(target_cover_status="unresolved"),
    )
    run("wrong transfer source", fixed, lambda c, r, s: r.update(site=hex(int(r["site"], 0) + 1)))
    run("missing record", fixed, lambda c, r, s: (c if owned else c["facts"])["records"].remove(r))
    run(
        "duplicate record",
        fixed,
        lambda c, r, s: (c if owned else c["facts"])["records"].append(copy.deepcopy(r)),
    )
    run(
        "unresolved record with target",
        dynamic,
        lambda c, r, s: r.update(target=hex(s["oracle_targets"][0])),
    )
    run(
        "wrong support bytes",
        dynamic,
        lambda c, r, s: r.update(target_cover_support=hex(s["push"]) + ":00"),
    )
    run("wrong transfer width", fixed, lambda c, r, s: r.update(width_bits="16"))
    if owned:
        run("stale owned proof", fixed, lambda c, r, s: r.update(fresh="false"))
        run("publication mismatch", fixed, lambda c, r, s: c["user_edges"].update({r["site"]: []}))
    else:
        run("inventory mutation", fixed, lambda c, r, s: c.update(inventory_after={}))
        run("published ownerless result", fixed, lambda c, r, s: c["facts"].update(published=True))
    return results


def load_report(path, owned, oracle, nm, pins, document=None):
    pins[path] = digest(path)
    report = json.loads(path.read_text()) if document is None else document
    require(report["passed"] and len(report["runs"]) == 2, "failed or duplicate input runs")
    require(
        {r["architecture"] for r in report["runs"]} == {"x86_64", "i386"},
        "incomplete architecture matrix",
    )
    require(owned or report.get("edge_oracle_driver") is True, "selected native edge driver absent")
    for name, expected in report["source_sha256"].items():
        require(digest(ROOT / name) == expected, "input source changed: " + name)
        pins[ROOT / name] = expected
    needed = (
        [
            "tests/vmp_native/dataflow.S",
            "tests/ida_dataflow_probe.py",
            "tests/vmp_native/dataflow_main.c",
        ]
        if owned
        else [
            "tests/vmp_native/dataflow.S",
            "tests/vmp_native/dataflow_main.c",
            "tests/vmp_native/ownerless_dataflow.S",
            "tests/vmp_native/ownerless_dataflow.c",
            "tests/vmp_native/ownerless_edge_main.c",
            "tests/ida_ownerless_dataflow_probe.py",
            "tests/run_ownerless_dataflow.py",
        ]
    )
    for name in needed:
        require(
            report["source_sha256"][name] == oracle["source_sha256"][name],
            "unreviewed report source",
        )
    result = []
    for run in report["runs"]:
        arch = run["architecture"]
        directory = path.parent / arch
        binary = directory / ("dataflow" if owned else "ownerless")
        expected_binary = run["binary_sha256"] if owned else run["executions"][0]["binary_sha256"]
        require(digest(binary) == expected_binary, "binary changed")
        pins[binary] = expected_binary
        controls = [run] if owned else run["executions"]
        for control in controls:
            native = control["native"]
            require(
                not native["timed_out"] and not native["output_exceeded"],
                "native execution incomplete",
            )
            if not owned:
                require(
                    control["edge_native_result"]
                    == {"passed": True, "checks": oracle["native_checks"]["owned"][arch]},
                    "selected native edge contract failed",
                )
        primary = run["native_result"] if owned else run["executions"][0]["result"]
        require(
            primary
            == {
                "passed": True,
                "checks": oracle["native_checks"]["owned" if owned else "ownerless"][arch],
            },
            "native contract failed",
        )
        require(controls[0]["native"]["exit_code"] == 0, "native process failed")
        if not owned:
            require(
                len(controls) == 3
                and [r["corruption"] for r in controls] == ["none", "equal", "bswap"],
                "missing corrupted native controls",
            )
            require(
                all(
                    r["native"]["exit_code"] == 1 and not r["result"]["passed"]
                    for r in controls[1:]
                ),
                "corrupted native oracle accepted",
            )
            for control in controls[1:]:
                altered = directory / ("ownerless-corrupt-" + control["corruption"])
                require(
                    digest(altered) == control["binary_sha256"], "corrupted-control binary changed"
                )
                pins[altered] = control["binary_sha256"]
        for name, value in run["artifact_sha256"].items():
            require(digest(directory / name) == value, "input artifact changed")
            pins[directory / name] = value
        manifest = json.loads((directory / "inspection/run.json").read_text())
        require(
            manifest["artifacts_unchanged"]
            and manifest["source_script_unchanged"]
            and manifest["input_sha256"] == expected_binary
            and manifest["plugin_sha256"] == report["plugin_sha256"]
            and manifest["ida_sha256"] == report["ida_sha256"]
            and manifest["runner_return_code"] == 0,
            "IDA run attribution failed",
        )
        inspection = json.loads(
            (
                directory
                / ("inspection/dataflow.json" if owned else "inspection/ownerless_dataflow.json")
            ).read_text()
        )
        require(not inspection["errors"], "IDA inspection error")
        checks = inspection["records"] if owned else inspection["checks"]
        require(
            len(checks) == run["checks"] and all(c["passed"] for c in checks),
            "IDA probe check failed",
        )
        decoded = decode_oracle(binary, nm, arch, oracle)
        captures = inspection["captures"]
        cases = [
            score_case(captures[c["name"]], c, owned, decoded["encoded"], arch)
            for c in decoded["cases"]
        ]
        result.append(
            {
                "architecture": arch,
                "analysis": "owned" if owned else "ownerless",
                "binary_sha256": expected_binary,
                "native_checks": primary["checks"],
                "probe_checks": len(checks),
                "counts": counts(cases),
                "cases": cases,
                "mutation_controls": mutation_controls(captures, decoded, owned, arch),
                "resource_scope": "outer wait4 runner child including launch; not isolated IDA resource use",
                "elapsed_s": run["inspection"]["elapsed_ns"] / 1e9,
                "peak_resident_bytes": run["inspection"]["peak_resident_bytes"],
            }
        )
    return report, result


def attribution_controls(owned_path, ownerless_path, oracle, nm):
    results = []

    def run(label, path, owned, mutate, reason):
        altered = json.loads(path.read_text())
        mutate(altered)
        try:
            load_report(path, owned, oracle, nm, {}, altered)
        except ValueError as error:
            require(str(error) == reason, "attribution mutation failed for a different reason")
        else:
            raise ValueError("attribution mutation was not detected")
        results.append({"name": label, "rejection": reason})

    run(
        "fixture source mismatch",
        owned_path,
        True,
        lambda r: r["source_sha256"].update({"tests/vmp_native/dataflow.S": "0" * 64}),
        "input source changed: tests/vmp_native/dataflow.S",
    )
    run(
        "capture checksum mismatch",
        owned_path,
        True,
        lambda r: r["runs"][0]["artifact_sha256"].update({"inspection/dataflow.json": "0" * 64}),
        "input artifact changed",
    )
    run(
        "plugin attribution mismatch",
        owned_path,
        True,
        lambda r: r.update(plugin_sha256="0" * 64),
        "IDA run attribution failed",
    )
    run(
        "binary checksum mismatch",
        owned_path,
        True,
        lambda r: r["runs"][0].update(binary_sha256="0" * 64),
        "binary changed",
    )
    run(
        "duplicate architecture",
        owned_path,
        True,
        lambda r: r["runs"].__setitem__(1, copy.deepcopy(r["runs"][0])),
        "incomplete architecture matrix",
    )
    run(
        "corrupted native oracle accepted",
        ownerless_path,
        False,
        lambda r: r["runs"][0]["executions"][1]["native"].update(exit_code=0),
        "corrupted native oracle accepted",
    )
    run(
        "selected native edge result corrupted",
        ownerless_path,
        False,
        lambda r: r["runs"][0]["executions"][0]["edge_native_result"].update(passed=False),
        "selected native edge contract failed",
    )
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owned-report", required=True, type=Path)
    parser.add_argument("--ownerless-report", required=True, type=Path)
    parser.add_argument("--nm", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": 2, "passed": False, "runs": []}
    try:
        oracle = contract()
        pins = {
            CONTRACT: CONTRACT_SHA256,
            Path(__file__): digest(__file__),
            args.nm: digest(args.nm),
            Path(capstone.__file__): digest(capstone.__file__),
            Path(capstone._cs._name): digest(capstone._cs._name),
        }
        pins.update({ROOT / name: h for name, h in oracle["source_sha256"].items()})
        first, runs = load_report(args.owned_report, True, oracle, args.nm, pins)
        second, others = load_report(args.ownerless_report, False, oracle, args.nm, pins)
        require(
            first["plugin_sha256"] == second["plugin_sha256"]
            and first["ida_sha256"] == second["ida_sha256"],
            "unmatched IDA or plugin profiles",
        )
        report["attribution_controls"] = attribution_controls(
            args.owned_report, args.ownerless_report, oracle, args.nm
        )
        report.update(
            {
                "oracle_contract_sha256": CONTRACT_SHA256,
                "artifact_sha256": {
                    relative(p): h for p, h in pins.items() if p.resolve().is_relative_to(ROOT)
                },
                "input_reports": [relative(args.owned_report), relative(args.ownerless_report)],
                "plugin_sha256": first["plugin_sha256"],
                "ida_sha256": first["ida_sha256"],
                "nm_sha256": pins[args.nm],
                "capstone": {
                    "version": capstone.__version__,
                    "binding_sha256": pins[Path(capstone.__file__)],
                    "library_sha256": pins[Path(capstone._cs._name)],
                },
                "scope": oracle["scope"],
                "runs": runs + others,
            }
        )
        for path, expected in pins.items():
            require(digest(path) == expected, "scored artifact changed during measurement")
        report["passed"] = all(
            r["counts"]["false_edges"] == 0 and r["counts"]["unsound_covers"] == 0
            for r in report["runs"]
        )
    except Exception as error:
        report["failure"] = type(error).__name__ + (
            ": " + str(error) if isinstance(error, ValueError) else ""
        )
    (output / "native_edge_benchmark_v2.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "failure": report.get("failure"),
                "runs": [
                    {
                        "architecture": r["architecture"],
                        "analysis": r["analysis"],
                        "counts": r["counts"],
                        "mutation_controls": len(r["mutation_controls"]),
                    }
                    for r in report["runs"]
                ],
            }
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
