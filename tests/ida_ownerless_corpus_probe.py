"""Read-only ownerless-root inspection on frozen development corpus regions."""

import hashlib
import json
import os
from pathlib import Path
import sys
import traceback

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_loader
import ida_name
import ida_pro
import ida_segment
import ida_ua
import ida_xref
import idautils

sys.dont_write_bytecode = True
report = {"schema": 1, "passed": False, "checks": [], "errors": [], "roots": []}


def check(name, condition):
    report["checks"].append({"case": name, "passed": bool(condition)})
    if not condition:
        report["errors"].append(name)


def evaluate(expression):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    return value


def api(root):
    return json.loads(evaluate(f"chernobog_native_region_facts({root})").c_str())


def stats():
    return {
        key: int(evaluate("chernobog_early_stats()." + key).num)
        for key in ("codegen_setcc", "codegen_cmov", "codegen_cmov_memory")
    }


def inventory():
    digest = hashlib.sha256()
    total = heads = references = 0

    def add(value):
        digest.update(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())

    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        size = int(segment.end_ea - segment.start_ea)
        total += size
        assert total <= 64 * 1024 * 1024
        add((int(segment.start_ea), int(segment.end_ea), segment.bitness, segment.perm))
        for part in ida_bytes.get_bytes_and_mask(segment.start_ea, size) or (b"unloaded",):
            digest.update(part)
        for ea in idautils.Heads(segment.start_ea, segment.end_ea):
            heads += 1
            assert heads <= 1048576
            owner = ida_funcs.get_func(ea)
            add(
                (
                    int(ea),
                    int(ida_bytes.get_full_flags(ea)),
                    int(ida_bytes.get_item_end(ea)),
                    int(owner.start_ea) if owner else None,
                    ida_name.get_name(ea),
                    ida_bytes.get_cmt(ea, False),
                    ida_bytes.get_cmt(ea, True),
                )
            )
            xref = ida_xref.xrefblk_t()
            more = xref.first_from(ea, ida_xref.XREF_ALL)
            while more:
                references += 1
                assert references <= 2097152
                add((int(xref.frm), int(xref.to), int(xref.type), bool(xref.iscode)))
                more = xref.next_from()
    functions = list(idautils.Functions())
    assert len(functions) <= 4096
    for ea in functions:
        add((int(ea), int(ida_funcs.get_func(ea).flags), list(idautils.Chunks(ea))))
    return {
        "sha256": digest.hexdigest(),
        "heads": heads,
        "references": references,
        "functions": len(functions),
    }


try:
    plan = json.loads(Path(os.environ["CHERNOBOG_OWNERLESS_PLAN_FILE"]).read_text())
    case = plan["cases"][os.environ["CHERNOBOG_OWNERLESS_CASE"]]
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    evaluate("chernobog_native_analysis()")
    ida_auto.auto_wait()
    ida_auto.enable_auto(False)
    report["inventory_before"] = inventory()
    before_stats = stats()
    mismatches = []
    for expected in case["heads"]:
        ea = int(expected["site"], 0)
        instruction = ida_ua.insn_t()
        size = ida_ua.decode_insn(instruction, ea)
        if (
            size != expected["size"]
            or (ida_bytes.get_bytes(ea, size) or b"").hex() != expected["bytes"]
            or not ida_bytes.is_code(ida_bytes.get_full_flags(ea))
            or ida_bytes.get_item_head(ea) != ea
            or ida_funcs.get_func(ea) is not None
        ):
            mismatches.append(expected["site"])
    report["baseline_head_mismatches"] = mismatches
    check("archived selected head bytes, spans and ownerless status match", not mismatches)
    for frozen in case["roots"]:
        root = int(frozen["root"], 0)
        current = api(root)
        repeated = api(root)
        report["roots"].append({"baseline": frozen, "current": current})
        label = frozen["root"]
        check(label + " repeatable read-only inspection", current == repeated)
        check(
            label + " root-scoped result",
            current["root"] == label
            and current["address_bits"] == 64
            and current["available"]
            and not current["published"]
            and "conditional on entry" in current["scope"],
        )
        check(
            label + " bounded output",
            len(current["nodes"]) <= 64
            and current["incoming_examined"] <= 64 * 256
            and (current["converged"] or not current["records"]),
        )
        if frozen["node_limit_exceeded"]:
            check(
                label + " oversized graph abstains",
                current["truncated"]
                and not current["converged"]
                and not current["records"]
                and current["reason"] == "node_limit",
            )
        else:
            check(
                label + " frozen graph head set",
                sorted(row["site"] for row in current["nodes"]) == sorted(frozen["nodes"]),
            )
            check(
                label + " complete bounded graph",
                current["converged"] and not current["truncated"],
            )
            expected_conditions = set(frozen["condition_sites"])
            actual_conditions = {
                row["site"]
                for row in current["records"]
                if row["kind"] in ("branch-condition", "setcc-value", "cmov-condition")
            }
            check(label + " exact condition denominator", actual_conditions == expected_conditions)
            for frontier in frozen["frontiers"]:
                if frontier["kind"] == "bswap16":
                    check(
                        label + " undefined BSWAP frontier retained",
                        any(
                            edge["source"] == frontier["site"]
                            and edge["kind"] == "frontier"
                            and edge["reason"] == "unsupported_bswap_width"
                            for edge in current["edges"]
                        ),
                    )
    report["inventory_after"] = inventory()
    report["codegen_delta"] = {key: value - before_stats[key] for key, value in stats().items()}
    check(
        "inspection preserves IDB bytes, heads, ownership, xrefs, names and comments",
        report["inventory_before"] == report["inventory_after"],
    )
    check("inspection performs no microcode lowering", not any(report["codegen_delta"].values()))
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(type(error).__name__)
    report["exception_frames"] = [
        {"function": frame.name, "line": frame.lineno}
        for frame in traceback.extract_tb(error.__traceback__)
    ]

(Path(os.environ["IDAUSR"]).parent / "ownerless_corpus.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][ownerless-corpus] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 2)
