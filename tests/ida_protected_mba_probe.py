"""Capture actual SDK shapes and typed-proposal rejection reasons without forcing owners."""

import hashlib
import json
import os
from pathlib import Path
import sys
import time

import ida_auto
import ida_allins
import ida_bytes
import ida_expr
import ida_funcs
import ida_hexrays as hx
import ida_ida
import ida_idaapi
import ida_loader
import ida_pro
import ida_ua
import idautils

sys.dont_write_bytecode = True
OPCODES = {
    getattr(hx, name): name
    for name in dir(hx)
    if name.startswith("m_") and isinstance(getattr(hx, name), int)
}
KINDS = {
    getattr(hx, name): name
    for name in dir(hx)
    if name.startswith("mop_") and isinstance(getattr(hx, name), int)
}
SCALARS = (
    "total_matches",
    "successful_matches",
    "instance_verified",
    "instance_disproved",
    "instance_unsupported",
    "instance_unknown",
)


def evaluate(expression):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression), "IDC evaluation"
    return value.c_str() if value.vtype == ida_expr.VT_STR else value.i64


def statistics():
    result = {name: int(evaluate("chernobog_rule_stats()." + name)) for name in SCALARS}
    assert all(v >= 0 for v in result.values()), "negative statistic"
    if os.environ.get("CHERNOBOG_MBA_LEGACY_REASONS") == "1":
        result["reasons_available"] = False
        return result
    result["reasons_available"] = True
    result["unrecorded_rejections"] = int(
        evaluate("chernobog_rule_stats().instance_unrecorded_rejections")
    )
    result["rejection_reasons"] = json.loads(
        evaluate("chernobog_rule_stats().instance_rejection_reasons")
    )
    reasons = result["rejection_reasons"]
    assert len(reasons) <= 32 and result["unrecorded_rejections"] >= 0, "reason quota"
    keys, recorded = set(), 0
    for row in reasons:
        key = row["status"], row["width_bits"], row["reason"]
        assert key not in keys and row["status"] in ("disproved", "unsupported", "unknown")
        assert row["width_bits"] in (0, 8, 16, 32, 64) and row["count"] > 0
        assert len(row["reason"].encode()) <= 256, "reason byte quota"
        keys.add(key)
        recorded += row["count"]
    assert recorded + result["unrecorded_rejections"] == sum(
        result["instance_" + status] for status in ("disproved", "unsupported", "unknown")
    ), "rejection accounting"
    for status in ("disproved", "unsupported", "unknown"):
        assert (
            sum(row["count"] for row in reasons if row["status"] == status)
            <= result["instance_" + status]
        ), "status accounting"
    return result


def native_statistics():
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, "chernobog_native_stats()")
    result = {}
    for name in (
        "enabled",
        "ran",
        "function_updates_scoped",
        "function_updates_global",
        "proof_revalidation_calls",
        "proof_revalidation_checks",
        "proof_revalidation_skipped",
        "proof_metadata_reuses",
        "item_topology_invalidations",
    ):
        field = ida_expr.idc_value_t()
        assert not ida_expr.get_idcv_attr(field, value, name)
        result[name] = int(field.i64)
    assert result["enabled"] == int(os.environ.get("CHERNOBOG_DISABLE") != "1")
    assert result["ran"] == 0
    return result


class Quota(Exception):
    pass


class Capture:
    def __init__(self):
        self.nodes, self.text_bytes = 0, 0

    def operand(self, value, depth):
        row = {
            "kind": int(value.t),
            "kind_name": KINDS.get(value.t, "unknown"),
            "bytes": int(value.size),
            "properties": int(value.oprops),
        }
        if value.t == hx.mop_d:
            row["instruction"] = self.instruction(value.d, depth + 1)
        elif value.t == hx.mop_n:
            row["value"] = int(value.nnn.value)
        elif value.t == hx.mop_r:
            row["register"] = int(value.r)
        elif value.t == hx.mop_S:
            row["offset"] = int(value.s.off)
        elif value.t == hx.mop_v:
            row["address"] = int(value.g)
        elif value.t == hx.mop_b:
            row["block"] = int(value.b)
        return row

    def instruction(self, value, depth=0):
        if depth > 64 or self.nodes == 8192:
            raise Quota()
        self.nodes += 1
        text = value.dstr()
        # Text is diagnostic, never an operand identity or semantic proof.
        allowed = min(1024, 524288 - self.text_bytes)
        encoded = text.encode()
        bounded = encoded[:allowed].decode(errors="ignore")
        self.text_bytes += len(bounded.encode())
        return {
            "opcode": OPCODES.get(value.opcode, "unknown"),
            "ea": int(value.ea),
            "properties": int(value.iprops),
            "text": bounded,
            "text_truncated": len(encoded) > allowed,
            "left": self.operand(value.l, depth),
            "right": self.operand(value.r, depth),
            "destination": self.operand(value.d, depth),
        }


report = {
    "schema": 1,
    "passed": False,
    "errors": [],
    "entries": [],
    "transformations_disabled": os.environ.get("CHERNOBOG_DISABLE") == "1",
    "native_analysis_disabled": os.environ.get("CHERNOBOG_IDA_ANALYSIS") == "0",
    "scope": "selected original/protected entries; SDK shapes and proposal diagnostics; no forced ownership, whole-function equivalence, or recovery-accuracy claim",
}


def capture_entry(capture, name, ea):
    row = {"name": name, "entry": ea, "stages": []}
    function = ida_funcs.get_func(ea)
    row["owner"] = int(function.start_ea) if function else None
    if function is None or function.start_ea != ea:
        row["status"] = "ownerless" if function is None else "entry_inside_owner"
        return row
    chunks = list(idautils.Chunks(ea))
    if len(chunks) > 64 or sum(end - start for start, end in chunks) > 262144:
        row["status"] = "native_range_quota"
        return row
    original = []
    for start, end in chunks:
        data = ida_bytes.get_bytes(start, end - start)
        assert data is not None and len(data) == end - start, "native chunk bytes"
        original.append((start, end, data))
    row["native_chunks"] = [
        {"start": start, "end": end, "sha256": hashlib.sha256(data).hexdigest()}
        for start, end, data in original
    ]
    row["status"] = "owned"
    for maturity in (hx.MMAT_GENERATED, hx.MMAT_PREOPTIMIZED, hx.MMAT_LOCOPT, hx.MMAT_GLBOPT1):
        print(f"[chernobog][protected-mba] {name} maturity={int(maturity)} start", flush=True)
        evaluate("chernobog_rule_reset_stats()")
        before = statistics()
        assert not any(before[key] for key in SCALARS), "statistics reset"
        if before["reasons_available"]:
            assert not before["rejection_reasons"] and before["unrecorded_rejections"] == 0
        stage = {"maturity": int(maturity), "blocks": []}
        row["stages"].append(stage)
        failure = hx.hexrays_failure_t()
        started = time.perf_counter_ns()
        mba = hx.gen_microcode(
            hx.mba_ranges_t(function),
            failure,
            None,
            hx.DECOMP_NO_CACHE | hx.DECOMP_ALL_BLKS,
            maturity,
        )
        stage["generation_elapsed_ns"] = time.perf_counter_ns() - started
        stage["statistics"] = statistics()
        if mba is None:
            stage.update(
                status="sdk_refused", error_code=int(failure.code), error_ea=int(failure.errea)
            )
            continue
        stage["sdk_blocks"] = int(mba.qty)
        if mba.qty > 256:
            stage["status"] = "block_quota"
            continue
        try:
            for index in range(mba.qty):
                block = mba.get_mblock(index)
                part = {
                    "index": index,
                    "successors": [int(block.succ(i)) for i in range(block.nsucc())],
                    "instructions": [],
                }
                stage["blocks"].append(part)
                instruction = block.head
                while instruction is not None:
                    part["instructions"].append(capture.instruction(instruction))
                    instruction = instruction.next
            stage["status"] = "captured"
        except Quota:
            stage["status"] = "node_or_depth_quota"
        stage["native_bytes_unchanged"] = all(
            ida_bytes.get_bytes(start, end - start) == data for start, end, data in original
        )
        assert stage["native_bytes_unchanged"], "SDK generation changed native bytes"
    row["chunks_after"] = [list(c) for c in idautils.Chunks(ea)]
    row["native_bytes_unchanged"] = all(
        ida_bytes.get_bytes(start, end - start) == data for start, end, data in original
    )
    assert row["native_bytes_unchanged"], "native bytes changed"
    return row


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]), "plugin load"
    print("[chernobog][protected-mba] initial analysis start", flush=True)
    ida_auto.auto_wait()
    print("[chernobog][protected-mba] initial analysis complete", flush=True)
    assert hx.init_hexrays_plugin(), "decompiler load"
    report["architecture"] = "x86_64" if ida_ida.inf_is_64bit() else "i386"
    if not report["native_analysis_disabled"]:
        evaluate("chernobog_native_analysis()")
        ida_auto.auto_wait()
    print("[chernobog][protected-mba] native analysis complete", flush=True)
    entries = json.loads(os.environ["CHERNOBOG_MBA_CORPUS_ENTRIES"])
    assert set(entries) == {"corpus_transform", "corpus_branch"}, "entry population"
    capture = Capture()
    for name, raw in entries.items():
        ea = int(raw, 0)
        row = capture_entry(capture, name, ea)
        report["entries"].append(row)
        instruction = ida_ua.insn_t()
        size = ida_ua.decode_insn(instruction, ea)
        assert 0 < size <= 15, "entry decoding"
        row["entry_bytes"] = ida_bytes.get_bytes(ea, size).hex()
        row["direct_target"] = None
        row["body"] = None
        if instruction.itype == ida_allins.NN_jmp and instruction.Op1.type == ida_ua.o_near:
            target = int(instruction.Op1.addr)
            row["direct_target"] = target
            # One decoded direct jump, an existing exact owner, and no ownership
            # mutation. A thunk is not the protected expression body.
            row["body"] = capture_entry(capture, name + ":direct_target", target)
    report["capture_nodes"] = capture.nodes
    report["capture_text_bytes"] = capture.text_bytes
    if os.environ.get("CHERNOBOG_CAPTURE_NATIVE_STATS") == "1":
        report["native_statistics"] = native_statistics()
        assert report["native_statistics"] == native_statistics(), "statistics query ran analysis"
    report["passed"] = True
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
    frames, tb = [], error.__traceback__
    while tb:
        frames.append({"function": tb.tb_frame.f_code.co_name, "line": tb.tb_lineno})
        tb = tb.tb_next
    report["exception_frames"] = frames
payload = json.dumps(report, indent=2) + "\n"
if len(payload.encode()) > 4194304:
    report["passed"] = False
    report["errors"].append("report byte quota")
    for row in [
        r for entry in report["entries"] for r in (entry, entry.get("body")) if r is not None
    ]:
        for stage in row["stages"]:
            stage["blocks"] = []
            stage["status"] = "report_quota"
    payload = json.dumps(report, indent=2) + "\n"
(Path(os.environ["IDAUSR"]).parent / "protected_mba.json").write_text(payload)
print("[chernobog][protected-mba] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 2)
