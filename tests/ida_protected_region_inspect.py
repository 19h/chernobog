"""Inspect one exact protected ownerless native region without modifying its IDB."""

import hashlib
import json
import os
import sys
from pathlib import Path

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_pro
import ida_segment
import idautils

sys.dont_write_bytecode = True


def inventory():
    """Bounded identity of bytes, items, ownership, references and annotations."""
    digest = hashlib.sha256()
    total = heads = references = 0

    def add(value):
        digest.update(json.dumps(value, separators=(",", ":")).encode())
        digest.update(b"\n")

    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        size = int(segment.end_ea - segment.start_ea)
        total += size
        assert total <= 64 * 1024 * 1024
        add((int(segment.start_ea), int(segment.end_ea), int(segment.bitness), int(segment.perm)))
        for part in ida_bytes.get_bytes_and_mask(segment.start_ea, size) or (b"unloaded",):
            digest.update(part)
        for ea in idautils.Heads(segment.start_ea, segment.end_ea):
            heads += 1
            assert heads <= 1048576
            function = ida_funcs.get_func(ea)
            add(
                (
                    ea,
                    int(ida_bytes.get_full_flags(ea)),
                    int(ida_bytes.get_item_end(ea)),
                    None if function is None else int(function.start_ea),
                    ida_bytes.get_cmt(ea, True),
                    ida_bytes.get_cmt(ea, False),
                )
            )
            refs = sorted(
                (int(ref.frm), int(ref.to), int(ref.type), bool(ref.iscode), bool(ref.user))
                for ref in idautils.XrefsFrom(ea)
            )
            references += len(refs)
            assert references <= 2097152
            add(refs)
    functions = list(idautils.Functions())
    assert len(functions) <= 4096
    for ea in functions:
        function = ida_funcs.get_func(ea)
        add(
            (
                ea,
                int(function.flags),
                list(idautils.Chunks(ea)),
                ida_funcs.get_func_cmt(function, True),
                ida_funcs.get_func_cmt(function, False),
            )
        )
    add(list(idautils.Names()))
    return {
        "sha256": digest.hexdigest(),
        "heads": heads,
        "references": references,
        "functions": len(functions),
    }


def api(expression):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    return json.loads(value.c_str())


report = {"errors": [], "checks": []}


def check(name, condition):
    report["checks"].append({"case": name, "passed": bool(condition)})
    if not condition:
        report["errors"].append(name)


try:
    root = int(os.environ["CHERNOBOG_PROTECTED_REGION_ROOT"], 0)
    expected = os.environ["CHERNOBOG_PROTECTED_REGION_EXPECT"]
    assert expected in ("truncated", "complete", "undecoded")
    ida_auto.auto_wait()
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, "chernobog_native_analysis()")
    ida_auto.auto_wait()
    report["root"] = root
    report["owner"] = (
        None if ida_funcs.get_func(root) is None else ida_funcs.get_func(root).start_ea
    )
    report["inventory_before"] = inventory()
    report["inspection"] = api("chernobog_native_region_facts(" + str(root) + ")")
    report["inventory_after"] = inventory()
    check("read-only IDB inventory", report["inventory_before"] == report["inventory_after"])
    check("ownerless initializer", report["owner"] is None)
    view = report["inspection"]
    check("schema and root", view["schema"] == 1 and int(view["root"], 0) == root)
    check(
        "bounded unpublished scope",
        view["published"] is False
        and view["limits"]
        == {
            "nodes": 64 if expected == "truncated" else 128,
            "rounds": 128,
            "incoming_per_node": 256,
        }
        and "selected ownerless root" in view["scope"]
        and "no whole-program reachability" in view["scope"],
    )
    nodes = [int(node["site"], 0) for node in view["nodes"]]
    check(
        "unique sorted ownerless nodes",
        nodes == sorted(set(nodes)) and all(ida_funcs.get_func(site) is None for site in nodes),
    )
    frontiers = [
        (edge["reason"], edge["source"], edge["target"])
        for edge in view["edges"]
        if edge["kind"] == "frontier"
    ]
    if expected == "undecoded":
        check(
            "undecoded root abstention",
            not view["available"]
            and not view["converged"]
            and not view["truncated"]
            and view["reason"] == "not_existing_code_head"
            and not nodes
            and not view["edges"]
            and not view["records"],
        )
    elif expected == "truncated":
        check(
            "64-node abstention",
            view["available"]
            and not view["converged"]
            and view["truncated"]
            and view["reason"] == "node_limit"
            and len(nodes) == 64
            and len(view["edges"]) == 66
            and not view["records"],
        )
        check(
            "limit frontier",
            ("node_limit", "0x1001d6c0f", "0x1001d6c12") in frontiers,
        )
    else:
        check(
            "75-node completion",
            view["available"]
            and view["converged"]
            and not view["truncated"]
            and view["reason"] == "complete_bounded_region"
            and len(nodes) == 75
            and len(view["edges"]) == 77,
        )
        check(
            "bounded frontiers",
            sorted(frontiers)
            == sorted(
                [
                    ("call_target_not_followed", "0x1002946ba", "0x1001a9297"),
                    ("unsupported_control", "0x10024801a", "0x10024801a"),
                ]
            ),
        )
        check(
            "three unresolved facts",
            sorted(
                (row["site"], row["kind"], row["status"], row["outcome"]) for row in view["records"]
            )
            == sorted(
                [
                    ("0x1001d6c12", "setcc-value", "unresolved", "unknown"),
                    ("0x100248015", "setcc-value", "unresolved", "unknown"),
                    ("0x10025d082", "branch-condition", "unresolved", "unknown"),
                ]
            ),
        )
    report["expected"] = expected
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "protected_region.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
line = "[chernobog][protected-region] " + (
    "PASS" if not report["errors"] else "FAIL " + "; ".join(report["errors"])
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(0 if not report["errors"] else 2)
