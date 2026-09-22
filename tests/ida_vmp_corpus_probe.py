"""Bounded, unmodified-IDB inventory of paired protected corpus entries.

Recovered xrefs are observations, not oracle edges. Missing ownership and
exhausted traversal budgets remain explicit; this probe never forces code or
function boundaries to improve the measured result.
"""
import collections
import json
import os
from pathlib import Path
import sys
import time

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro
import ida_segment
import ida_ua
import ida_xref
import idautils

sys.dont_write_bytecode = True
HEAD_LIMIT = 4096
OWNER_LIMIT = 64


def api(name, ea):
    value = ida_expr.idc_value_t()
    error = ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"{name}({ea})")
    if error or value.vtype != ida_expr.VT_STR:
        raise RuntimeError("inspection API failed")
    return json.loads(value.c_str())


def traverse(entry):
    pending = collections.deque([entry])
    scheduled = {entry}
    rows, owners = [], set()
    while pending and len(rows) < HEAD_LIMIT:
        ea = pending.popleft()
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        owner = ida_funcs.get_func(ea)
        segment = ida_segment.getseg(ea)
        flags = ida_bytes.get_full_flags(ea)
        if owner:
            owners.add(int(owner.start_ea))
        row = {"ea": ea, "owner": int(owner.start_ea) if owner else None,
               "is_code": ida_bytes.is_code(flags),
               "is_data": ida_bytes.is_data(flags), "is_tail": ida_bytes.is_tail(flags),
               "loaded": ida_bytes.is_loaded(ea), "user_name": ida_bytes.has_user_name(flags),
               "name": ida_name.get_name(ea),
               "item_head": int(ida_bytes.get_item_head(ea)),
               "segment": None if not segment else {"name": ida_segment.get_segm_name(segment),
                   "start": int(segment.start_ea), "end": int(segment.end_ea),
                   "permissions": int(segment.perm), "type": int(segment.type), "bitness": int(segment.bitness)},
               "size": size, "bytes": (ida_bytes.get_bytes(ea, size) or b"").hex() if size > 0 else "",
               "mnemonic": insn.get_canon_mnem() if size > 0 else "",
               "outgoing": []}
        for xref in idautils.XrefsFrom(ea):
            if not xref.iscode:
                continue
            kind = int(xref.type) & ida_xref.XREF_MASK
            row["outgoing"].append({"to": int(xref.to), "type": kind})
            # Interprocedural calls are recorded but are not traversed. Jump
            # and ordinary-flow xrefs may cross inferred function boundaries.
            if kind in (ida_xref.fl_JN, ida_xref.fl_JF, ida_xref.fl_F) and int(xref.to) not in scheduled:
                scheduled.add(int(xref.to))
                pending.append(int(xref.to))
        row["outgoing"].sort(key=lambda x: (x["to"], x["type"]))
        rows.append(row)
    return {"entry": entry, "instructions": rows, "traversal_limit": HEAD_LIMIT,
            "traversal_truncated": bool(pending), "pending_heads": len(pending),
            "owner_starts": sorted(owners)}


report = {"schema": 1, "passed": False, "errors": [], "entries": {},
          "scope": "IDA code-xref inventory; oracle edge coverage and false edges unknown",
          "transformations_disabled": os.environ.get("CHERNOBOG_DISABLE") == "1"}
try:
    started = time.perf_counter_ns()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, "chernobog_native_analysis()")
    ida_auto.auto_wait()
    report["native_stats"] = {}
    for field in ("enabled", "direct_jump_decode_attempts", "direct_jump_targets_decoded", "direct_jump_decode_truncated"):
        value = ida_expr.idc_value_t()
        assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, "chernobog_native_analysis()." + field)
        report["native_stats"][field] = int(value.num)
    ida_auto.auto_wait()
    entries = json.loads(os.environ["CHERNOBOG_CORPUS_ENTRIES"])
    assert set(entries) == {"corpus_transform", "corpus_branch"}
    for name, value in entries.items():
        ea = int(value, 0)
        before = traverse(ea)
        owners = before["owner_starts"]
        owners_to_inspect = owners[:OWNER_LIMIT]
        # An ownerless selected entry still gets an unavailable API response;
        # adding a function to make recognition work would bias the benchmark.
        if not owners_to_inspect:
            owners_to_inspect = [ea]
        before["owner_inspection_limit"] = OWNER_LIMIT
        before["owners_omitted"] = max(0, len(owners) - OWNER_LIMIT)
        before["inspections"] = [{"function": owner,
            "native": api("chernobog_native_evidence", owner),
            "vm": api("chernobog_vm_summaries" if os.environ.get("CHERNOBOG_CORPUS_VM_SUMMARIES") == "1" else "chernobog_vm_regions", owner),
            "solver": api("chernobog_solver_evidence", owner)} for owner in owners_to_inspect]
        after = traverse(ea)
        before["inspection_preserved_code_and_xrefs"] = all(before[k] == v for k, v in after.items())
        if not before["inspection_preserved_code_and_xrefs"]:
            report["errors"].append(name + ": inspection changed traversal")
        if not before["instructions"] or before["instructions"][0]["size"] <= 0:
            report["errors"].append(name + ": selected entry undecodable")
        report["entries"][name] = before
    if os.environ.get("CHERNOBOG_CORPUS_DECODER_CONTROL") == "1":
        # Explicit experiment, excluded from baseline/recovery measurements:
        # ask IDA to decode only the existing entry jump's unknown RX target.
        report["materialization_experiment"] = {"requests": [], "entries": {}}
        for entry in report["entries"].values():
            for edge in entry["instructions"][0]["outgoing"]:
                target = edge["to"]
                segment = ida_segment.getseg(target)
                if (edge["type"] == ida_xref.fl_JN and segment
                        and segment.perm & ida_segment.SEGPERM_EXEC
                        and ida_bytes.is_unknown(ida_bytes.get_full_flags(target))):
                    report["materialization_experiment"]["requests"].append(
                        {"target": target, "created_size": ida_ua.create_insn(target)})
        ida_auto.auto_wait()
        report["materialization_experiment"]["entries"] = {name: traverse(int(value, 0)) for name, value in entries.items()}
    report["inspection_elapsed_ns"] = time.perf_counter_ns() - started
    report["passed"] = not report["errors"]
except Exception as error:
    # Exception type is sufficient for public attribution; messages from IDA
    # can contain local paths or installation/license details.
    report["errors"].append(type(error).__name__)

(Path(os.environ["IDAUSR"]).parent / "corpus_inspection.json").write_text(json.dumps(report, indent=2) + "\n")
line = "[chernobog][vmp-corpus] " + ("PASS" if report["passed"] else "FAIL")
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(0 if report["passed"] else 2)
