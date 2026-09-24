"""Inspect a packed executable data item without changing IDA classification."""

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
import ida_loader
import ida_pro
import ida_segment
import idautils

sys.dont_write_bytecode = True
ROOT = int(os.environ["CHERNOBOG_CANDIDATE_ROOT"], 0)
CODE = int(os.environ["CHERNOBOG_CANDIDATE_CODE_CONTROL"], 0)
NONEXEC = int(os.environ["CHERNOBOG_CANDIDATE_NONEXEC_CONTROL"], 0)


def inventory():
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
        add((ea, int(function.flags), list(idautils.Chunks(ea))))
    add(list(idautils.Names()))
    return {"sha256": digest.hexdigest(), "heads": heads, "references": references}


def api(name, ea):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"{name}({ea})")
    return json.loads(value.c_str())


report = {"checks": [], "errors": []}


def check(name, condition):
    passed = bool(condition)
    report["checks"].append({"case": name, "passed": passed})
    if not passed:
        report["errors"].append(name)


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    check("root starts as an IDA data head", ida_bytes.is_data(ida_bytes.get_full_flags(ROOT)))
    report["inventory_before"] = inventory()
    report["ordinary_before"] = api("chernobog_native_region_facts", ROOT)
    report["candidate"] = api("chernobog_native_candidate_region", ROOT)
    report["controls"] = {
        "data_tail": api("chernobog_native_candidate_region", ROOT + 1),
        "code_head": api("chernobog_native_candidate_region", CODE),
        "nonexecutable": api("chernobog_native_candidate_region", NONEXEC),
    }
    report["ordinary_after"] = api("chernobog_native_region_facts", ROOT)
    report["inventory_after"] = inventory()
    candidate = report["candidate"]
    check(
        "packed root remains outside existing-code analysis",
        not report["ordinary_before"]["available"]
        and report["ordinary_before"] == report["ordinary_after"],
    )
    check(
        "candidate is explicit conditional byte decode",
        candidate["available"]
        and candidate["candidate_decode"]
        and candidate["converged"]
        and not candidate["truncated"]
        and candidate["reason"] == "complete_candidate_byte_region"
        and candidate["published"] is False
        and candidate["nodes"][0]["site"] == hex(ROOT)
        and candidate["nodes"][0]["bytes"] == "50"
        and all(node["item"] == "candidate-bytes" for node in candidate["nodes"])
        and all(row["truth"] == "conditional-byte-decode" for row in candidate["records"]),
    )
    check(
        "candidate exposes bounded call and packed-section frontiers",
        any(edge["reason"] == "call_target_not_followed" for edge in candidate["edges"])
        and any(edge["reason"] == "segment_boundary" for edge in candidate["edges"]),
    )
    check(
        "invalid roots abstain",
        report["controls"]["data_tail"]["reason"] == "not_unlabeled_data_head"
        and report["controls"]["code_head"]["reason"] == "not_unlabeled_data_head"
        and report["controls"]["nonexecutable"]["reason"] == "nonexecutable_or_external"
        and all(not view["available"] for view in report["controls"].values()),
    )
    check(
        "all IDB bytes, items, owners and xrefs remain unchanged",
        report["inventory_before"] == report["inventory_after"],
    )
except BaseException as error:
    report["errors"].append(type(error).__name__)

(Path(os.environ["IDAUSR"]).parent / "candidate_region.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][native-candidate] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
ida_pro.qexit(2 if report["errors"] else 0)
