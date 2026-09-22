"""Measure condition codegen on existing protected-code ownership, without repairs."""
import collections
import hashlib
import json
import os
from pathlib import Path
import time

import ida_allins
import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_hexrays as hx
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_pro
import ida_ua
import ida_xref
import idautils
import idc

HEAD_LIMIT = 4096
OWNER_LIMIT = 64
XREF_LIMIT = 16384
MICRO_LIMIT = 65536
TEXT_LIMIT = 4 * 1024 * 1024
SET_NAMES = ("seto", "setno", "setb", "setnb", "setz", "setnz", "setbe", "seta",
             "sets", "setns", "setp", "setnp", "setl", "setge", "setle", "setg",
             "setc", "setnae", "setae", "setnc", "sete", "setne", "setna", "setnbe",
             "setpe", "setpo", "setnge", "setnl", "setng", "setnle")
CMOV_NAMES = ("cmovo", "cmovno", "cmovb", "cmovnb", "cmovz", "cmovnz", "cmovbe", "cmova",
              "cmovs", "cmovns", "cmovp", "cmovnp", "cmovl", "cmovge", "cmovle", "cmovg")
KINDS = {getattr(ida_allins, "NN_" + name): kind
         for names, kind in ((SET_NAMES, "setcc"), (CMOV_NAMES, "cmov")) for name in names}
COUNTERS = ("codegen_setcc", "codegen_cmov", "codegen_cmov_memory")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def stats():
    return {key: int(idc.eval_idc("chernobog_early_stats()." + key + ";")) for key in COUNTERS}


def native(ea):
    insn = ida_ua.insn_t()
    size = ida_ua.decode_insn(insn, ea)
    owner = ida_funcs.get_func(ea)
    kind = KINDS.get(insn.itype) if size > 0 else None
    result = {"ea": int(ea), "size": size,
              "owner": int(owner.start_ea) if owner else None,
              "is_code": bool(ida_bytes.is_code(ida_bytes.get_full_flags(ea))),
              "bytes": (ida_bytes.get_bytes(ea, size) or b"").hex() if size > 0 else "",
              "kind": kind, "mnemonic": insn.get_canon_mnem() if size > 0 else ""}
    if kind:
        result["operand_bytes"] = int(ida_ua.get_dtype_size(insn.Op1.dtype))
        result["source_memory"] = kind == "cmov" and insn.Op2.type in (ida_ua.o_mem, ida_ua.o_phrase, ida_ua.o_displ)
    return result


def traverse(entry):
    pending, scheduled = collections.deque([entry]), {entry}
    rows, owners = [], set()
    references, reference_limit = 0, False
    while pending and len(rows) < HEAD_LIMIT:
        row = native(pending.popleft())
        if row["owner"] is not None:
            owners.add(row["owner"])
        row["outgoing"] = []
        for xref in idautils.XrefsFrom(row["ea"]):
            if references == XREF_LIMIT:
                reference_limit = True
                break
            references += 1
            if not xref.iscode:
                continue
            kind = int(xref.type) & ida_xref.XREF_MASK
            target = int(xref.to)
            row["outgoing"].append({"to": target, "type": kind})
            if kind in (ida_xref.fl_F, ida_xref.fl_JN, ida_xref.fl_JF) and target not in scheduled:
                scheduled.add(target)
                pending.append(target)
        row["outgoing"].sort(key=lambda edge: (edge["to"], edge["type"]))
        rows.append(row)
        if reference_limit:
            break
    return {"entry": entry, "instructions": rows, "owners": sorted(owners),
            "truncated": bool(pending) or reference_limit, "pending": len(pending),
            "xrefs_visited": references, "xref_limit_reached": reference_limit}


def function_inventory(entry):
    rows = []
    for ea in idautils.FuncItems(entry):
        if len(rows) == HEAD_LIMIT:
            return rows, True
        rows.append(native(ea))
    return rows, False


def microcode(function, sites):
    before = stats()
    failure = hx.hexrays_failure_t()
    started = time.perf_counter_ns()
    mba = hx.gen_microcode(hx.mba_ranges_t(function), failure, None,
                          hx.DECOMP_NO_CACHE | hx.DECOMP_ALL_BLKS, hx.MMAT_GENERATED)
    result = {"elapsed_ns": time.perf_counter_ns() - started,
              "codegen_delta": {key: value - before[key] for key, value in stats().items()},
              "status": "failed", "failure_code": int(failure.code), "failure_ea": int(failure.errea)}
    if mba is None:
        return result
    mba.verify(True)
    by_site = {ea: [] for ea in sites}
    encoded, count, text_bytes = hashlib.sha256(), 0, 0
    truncated = False
    for index in range(mba.qty):
        insn = mba.get_mblock(index).head
        while insn is not None:
            text = insn.dstr()
            row = {"block": index, "ea": int(insn.ea), "opcode": int(insn.opcode),
                   "iprops": int(insn.iprops), "text": text}
            wire = json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
            if count >= MICRO_LIMIT or text_bytes + len(wire) > TEXT_LIMIT:
                truncated = True
                break
            encoded.update(wire + b"\n")
            if row["ea"] in by_site:
                by_site[row["ea"]].append(row)
            count += 1
            text_bytes += len(wire)
            insn = insn.next
        if truncated:
            break
    result.update(status="captured", blocks=int(mba.qty), instruction_count=count,
                  capture_truncated=truncated, serialized_bytes=text_bytes,
                  microcode_sha256=encoded.hexdigest(), conditions=by_site)
    return result


def inspect_owner(entry):
    function = ida_funcs.get_func(entry)
    result = {"entry": entry, "status": "missing_owner"}
    if function is None or function.start_ea != entry:
        return result
    rows, truncated = function_inventory(entry)
    result.update(native_head_count=len(rows), native_truncated=truncated,
                  native_sha256=digest(rows), flags_before=int(function.flags),
                  conditions=[row for row in rows if row["kind"]])
    if truncated:
        result["status"] = "native_budget"
        return result
    result["status"] = "inspected"
    try:
        result["generated"] = microcode(function, {row["ea"] for row in result["conditions"]})
    except Exception as error:
        result["generated"] = {"status": "exception", "exception_type": type(error).__name__}
    before = stats()
    failure = hx.hexrays_failure_t()
    started = time.perf_counter_ns()
    try:
        cfunc = hx.decompile(entry, failure, hx.DECOMP_NO_CACHE)
        ctree = str(cfunc) if cfunc is not None else None
        result["decompiled"] = {"status": "success" if cfunc is not None else "failed",
                                "failure_code": int(failure.code), "failure_ea": int(failure.errea)}
        if ctree is not None:
            wire = ctree.encode()
            result["decompiled"].update(utf8_bytes=len(wire), sha256=hashlib.sha256(wire).hexdigest(),
                                       read_intrinsic_occurrences=ctree.count("__chernobog_read_u"))
            if len(wire) <= TEXT_LIMIT:
                result["decompiled"]["text"] = ctree
            else:
                result["decompiled"]["text_omitted"] = True
    except Exception as error:
        result["decompiled"] = {"status": "exception", "exception_type": type(error).__name__}
    result["decompiled"]["elapsed_ns"] = time.perf_counter_ns() - started
    result["decompiled"]["codegen_delta"] = {key: value - before[key] for key, value in stats().items()}
    after, after_truncated = function_inventory(entry)
    result["native_preserved"] = not after_truncated and rows == after
    function = ida_funcs.get_func(entry)
    result["flags_after"] = int(function.flags) if function else None
    return result


report = {"schema": 1, "passed": False, "errors": [], "entries": {}, "owners": [],
          "condition_codegen": os.environ.get("CHERNOBOG_IDA_CONDITION_CODEGEN", "1") == "1",
          "limits": {"reachable_heads_per_entry": HEAD_LIMIT, "native_heads_per_owner": HEAD_LIMIT,
                     "xrefs_per_entry": XREF_LIMIT,
                     "owners": OWNER_LIMIT, "microinstructions_per_owner": MICRO_LIMIT,
                     "serialized_bytes_per_owner": TEXT_LIMIT},
          "scope": "existing selected-entry reachability and ownership; no ownership repairs or execution"}
try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, "chernobog_native_analysis()")
    ida_auto.auto_wait()
    assert hx.init_hexrays_plugin()
    entries = json.loads(os.environ["CHERNOBOG_CORPUS_ENTRIES"])
    assert set(entries) == {"corpus_transform", "corpus_branch"}
    report["entries"] = {name: traverse(int(ea, 0)) for name, ea in entries.items()}
    owners = sorted({owner for entry in report["entries"].values() for owner in entry["owners"]})
    report["owners_omitted"] = max(0, len(owners) - OWNER_LIMIT)
    for owner in owners[:OWNER_LIMIT]:
        report["owners"].append(inspect_owner(owner))
    report["entries_after"] = {name: traverse(int(ea, 0)) for name, ea in entries.items()}
    report["reachability_preserved"] = report["entries_after"] == report["entries"]
    report["passed"] = True
except Exception as error:
    report["errors"].append(type(error).__name__)
(Path(os.environ["IDAUSR"]).parent / "conditions_corpus.json").write_text(json.dumps(report, indent=2) + "\n")
line = "[chernobog][vmp-conditions] " + ("PASS" if report["passed"] else "FAIL")
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(0 if report["passed"] else 2)
