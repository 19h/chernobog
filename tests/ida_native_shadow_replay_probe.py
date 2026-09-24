"""Replay a protected-process entry state over a bounded executable shadow."""

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

ROOT = 0x430000
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
SHADOW = Path(os.environ["CHERNOBOG_SHADOW_FILE"])
RUNTIME = Path(os.environ["CHERNOBOG_ENTRY_STATE_FILE"])


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


def api(request):
    value = ida_expr.idc_value_t()
    expression = (
        "chernobog_vm_trace_candidate_shadow_replay("
        + str(ROOT)
        + ",0,"
        + json.dumps(json.dumps(request, separators=(",", ":")))
        + ")"
    )
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    return json.loads(value.c_str())


report = {"checks": [], "errors": []}


def check(name, condition):
    passed = bool(condition)
    report["checks"].append({"case": name, "passed": passed})
    if not passed:
        report["errors"].append(name)


try:
    raw = SHADOW.read_bytes()
    runtime = json.loads(RUNTIME.read_text())
    assert len(raw) == 65536
    assert hashlib.sha256(raw).hexdigest() == os.environ["CHERNOBOG_SHADOW_SHA256"]
    assert runtime["entry_packed_65536_sha256"] == hashlib.sha256(raw).hexdigest()
    assert runtime["entry_registers"] == runtime["entries"][0]["registers"]
    observed = runtime["entry_registers"]
    sp = int(observed["rsp"], 16)
    stack = bytes.fromhex(runtime["entry_stack_128_hex"])
    assert len(stack) == 128
    near = lambda value: abs(value - sp) <= 0x8000
    relative_gprs = [index for index, name in enumerate(GPRS) if near(int(observed[name], 16))]
    relative_words = [
        offset
        for offset in range(0, len(stack), 8)
        if near(struct.unpack_from("<Q", stack, offset)[0])
    ]
    assert relative_gprs == [4, 5, 13]
    assert relative_words == [64, 80, 88, 96, 104, 112, 120]
    request = {
        "shadow_file": str(SHADOW),
        "observed_sp": observed["rsp"],
        "gprs": [observed[name] for name in GPRS],
        "rflags": observed["eflags"],
        "stack_above": stack.hex(),
        "stack_relative_gprs": relative_gprs,
        "stack_relative_words": relative_words,
    }
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    report["inventory_before"] = inventory()
    report["runtime_report_sha256"] = hashlib.sha256(RUNTIME.read_bytes()).hexdigest()
    report["shadow_sha256"] = hashlib.sha256(raw).hexdigest()
    report["request_summary"] = {
        "observed_sp": observed["rsp"],
        "relative_gprs": relative_gprs,
        "relative_words": relative_words,
        "stack_sha256": hashlib.sha256(stack).hexdigest(),
    }
    result = api(request)
    report["capture"] = result
    report["inventory_after"] = inventory()
    check("entry replay available", result["available"] and result["ran"])
    check(
        "explicit translated entry scope",
        result["entry_state_replay"]
        and result["runtime_shadow"]
        and result["shadow_instruction_states"]
        and result["observed_entry_sp"] == observed["rsp"]
        and result["entry_stack_bytes"] == 128
        and result["stack_relative_gpr_mask"] == sum(1 << index for index in relative_gprs)
        and (int(result["entry_sp"], 16) & 0xFFF) == (sp & 0xFFF)
        and not result["function_evidence_published"]
        and not result["vm_identity_proved"],
    )
    check("bounded instruction states", result["instruction_count"] == 4096)
    check("database inventory unchanged", report["inventory_before"] == report["inventory_after"])
    invalid = dict(request, stack_relative_words=relative_words[:-1])
    rejected = api(invalid)
    check("missing pointer annotation rejected", not rejected.get("ran", False))
    invalid = dict(request, observed_sp=hex(sp + 16))
    rejected = api(invalid)
    check("mismatched SP rejected", not rejected.get("ran", False))
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "shadow_replay.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][shadow-replay] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
ida_pro.qexit(2 if report["errors"] else 0)
