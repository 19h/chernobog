"""Measure bounded protected execution after the observed Morok branch."""

import hashlib
import json
import os
import struct
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

ROOT = 0x430315
GPRS = (
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
)


def api(request):
    result = ida_expr.idc_value_t()
    expression = (
        "chernobog_vm_trace_candidate_shadow_replay_memory("
        + str(ROOT)
        + ",0,"
        + json.dumps(json.dumps(request, separators=(",", ":")))
        + ")"
    )
    if ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression):
        raise RuntimeError("IDC call failed")
    return json.loads(result.c_str())


def inventory():
    digest = hashlib.sha256()
    total = heads = references = 0

    def add(value):
        digest.update(json.dumps(value, separators=(",", ":")).encode())
        digest.update(b"\n")

    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        size = segment.end_ea - segment.start_ea
        total += size
        if total > 64 * 1024 * 1024:
            raise RuntimeError("oversized segment")
        add((segment.start_ea, segment.end_ea, segment.bitness, segment.perm))
        for part in ida_bytes.get_bytes_and_mask(segment.start_ea, size) or (b"unloaded",):
            digest.update(part)
        for ea in idautils.Heads(segment.start_ea, segment.end_ea):
            heads += 1
            if heads > 1048576:
                raise RuntimeError("too many heads")
            flags = ida_bytes.get_full_flags(ea)
            owner = ida_funcs.get_func(ea)
            add(
                (
                    ea,
                    int(flags),
                    int(ida_bytes.get_item_end(ea)),
                    None if owner is None else int(owner.start_ea),
                    ida_bytes.get_cmt(ea, True),
                    ida_bytes.get_cmt(ea, False),
                )
            )
            refs = sorted(
                (int(ref.frm), int(ref.to), int(ref.type), bool(ref.iscode), bool(ref.user))
                for ref in idautils.XrefsFrom(ea)
            )
            references += len(refs)
            if references > 2097152:
                raise RuntimeError("too many references")
            add(refs)
    functions = list(idautils.Functions())
    if len(functions) > 4096:
        raise RuntimeError("too many functions")
    for ea in functions:
        function = ida_funcs.get_func(ea)
        add((ea, int(function.flags), list(idautils.Chunks(ea))))
    add(list(idautils.Names()))
    return {"sha256": digest.hexdigest(), "heads": heads, "references": references}


def rax_at(trace, index):
    visit = trace["execution"][index]
    state = next(
        row
        for row in trace["states"]
        if row["kind"] == "native instruction entry" and row["sequence"] == visit["sequence"]
    )
    return next(
        value for value in state["registers"].split(";") if value.startswith("256:8:")
    ).split(":")[2]


report = {"checks": [], "errors": []}


def check(name, value):
    passed = bool(value)
    report["checks"].append({"case": name, "passed": passed})
    if not passed:
        report["errors"].append(name)


try:
    shadow = Path(os.environ["CHERNOBOG_BRANCH_SHADOW_FILE"])
    observed_path = Path(os.environ["CHERNOBOG_BRANCH_FILE"])
    observed = json.loads(observed_path.read_text())
    entry = observed["compare_registers"]
    sp = int(entry["rsp"], 16)
    stack = bytes.fromhex(observed["compare_stack_hex"])
    below, above = stack[:1024], stack[1024:]
    near = lambda value: abs(value - sp) <= 0x8000
    relative_gprs = [index for index, name in enumerate(GPRS) if near(int(entry[name], 16))]
    relative_below = [
        offset
        for offset in range(0, len(below), 8)
        if near(struct.unpack_from("<Q", below, offset)[0])
    ]
    relative_above = [
        offset
        for offset in range(0, len(above), 8)
        if near(struct.unpack_from("<Q", above, offset)[0])
    ]
    budget = int(os.environ["CHERNOBOG_BRANCH_CONTINUATION_BUDGET"])
    assert 2 < budget <= 4096
    assert len(shadow.read_bytes()) == 65536 - 0x315
    assert observed["data_length"] == 4096
    assert len(stack) == 1024 + observed["stack_above"]
    assert observed["stack_above"] <= 512
    assert observed["entry_packed_65536_sha256"] == observed["branch_packed_65536_sha256"]
    assert int(entry["rip"], 16) == ROOT
    request = {
        "shadow_file": str(shadow),
        "observed_sp": entry["rsp"],
        "gprs": [entry[name] for name in GPRS],
        "rflags": entry["eflags"],
        "stack_above": above.hex(),
        "stack_relative_gprs": relative_gprs,
        "stack_relative_words": relative_above,
        "stack_below": below.hex(),
        "stack_relative_below_words": relative_below,
        "data_start": observed["data_start"],
        "data_hex": observed["compare_data_hex"],
        "max_insns": budget,
    }
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    flags = ida_bytes.get_full_flags(ROOT)
    segment = ida_segment.getseg(ROOT)
    report["root_info"] = {
        "is_tail": ida_bytes.is_tail(flags),
        "is_loaded": ida_bytes.is_loaded(ROOT),
        "segment_execute": bool(segment.perm & ida_segment.SEGPERM_EXEC),
        "has_function": ida_funcs.get_func(ROOT) is not None,
        "item_head": hex(ida_bytes.get_item_head(ROOT)),
    }
    check(
        "unlabeled executable packed-data tail",
        report["root_info"]["is_tail"]
        and report["root_info"]["is_loaded"]
        and report["root_info"]["segment_execute"]
        and not report["root_info"]["has_function"]
        and ida_bytes.is_data(ida_bytes.get_full_flags(ida_bytes.get_item_head(ROOT))),
    )
    report["inventory_before"] = inventory()
    report["observation_sha256"] = hashlib.sha256(observed_path.read_bytes()).hexdigest()
    report["shadow_sha256"] = hashlib.sha256(shadow.read_bytes()).hexdigest()
    report["budget"] = budget
    report["relative_gprs"] = relative_gprs
    report["relative_below"] = relative_below
    report["relative_above"] = relative_above
    report["capture"] = api(request)
    report["inventory_after"] = inventory()
    capture = report["capture"]
    check("bounded replay admitted", capture.get("available") and capture.get("ran"))
    if capture.get("available") and capture.get("ran"):
        check(
            "checkpoint and budget retained",
            capture.get("observed_tail_checkpoint")
            and capture.get("instruction_budget") == budget
            and 2 <= capture.get("instruction_count", 0) <= budget
            and capture.get("native_state_capture_complete")
            and not capture.get("function_evidence_published")
            and not capture.get("vm_identity_proved"),
        )
        check(
            "observed boundary reached",
            capture.get("stop") == "native-region-boundary"
            and capture.get("stop_pc") == observed["boundary_pc"]
            and capture.get("instruction_count") == len(observed["entries"]),
        )
        narrow = api(dict(request, data_hex=observed["compare_data_hex"][: 1696 * 2]))
        rng_word = struct.unpack_from("<Q", bytes.fromhex(observed["compare_data_hex"]), 0xB08)[0]
        read_wide = next(
            row for row in capture["data"] if row["site"] == "0x41b83d" and row["kind"] == "read"
        )
        read_narrow = next(
            row for row in narrow["data"] if row["site"] == "0x41b83d" and row["kind"] == "read"
        )
        report["narrow_data_control"] = {
            "data_bytes": narrow.get("data_bytes"),
            "wide_first_rng_read": read_wide["value"],
            "narrow_first_rng_read": read_narrow["value"],
            "wide_rax_at_entry_16": rax_at(capture, 16),
            "narrow_rax_at_entry_16": rax_at(narrow, 16),
            "runtime_rax_at_entry_16": observed["entries"][16]["registers"]["rax"],
        }
        check(
            "omitted live RNG word falsifies register replay",
            narrow.get("available")
            and narrow.get("ran")
            and narrow.get("data_bytes") == 1696
            and read_wide["address"] == read_narrow["address"] == "0x444b08"
            and read_wide["value"] == hex(rng_word)
            and read_narrow["value"] != hex(rng_word)
            and rax_at(capture, 16) == observed["entries"][16]["registers"]["rax"]
            and rax_at(narrow, 16) != observed["entries"][16]["registers"]["rax"],
        )
    report["inventory_final"] = inventory()
    check(
        "database inventory unchanged",
        report["inventory_before"] == report["inventory_after"] == report["inventory_final"],
    )
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "branch_continuation.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][branch-continuation] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
ida_pro.qexit(2 if report["errors"] else 0)
