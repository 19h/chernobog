"""Replay the stopped protected hello's observed main-entry registers."""

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

ROOT = 0x100001440
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
WINDOW = Path(os.environ["CHERNOBOG_VMP_HELLO_WINDOW"])
RUNTIME = Path(os.environ["CHERNOBOG_VMP_HELLO_MAIN_STATES"])


def inventory():
    digest = hashlib.sha256()

    def add(value):
        digest.update(json.dumps(value, separators=(",", ":")).encode())
        digest.update(b"\n")

    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        size = int(segment.end_ea - segment.start_ea)
        assert size <= 64 * 1024 * 1024
        add((segment.start_ea, segment.end_ea, segment.bitness, segment.perm))
        for part in ida_bytes.get_bytes_and_mask(segment.start_ea, size) or (b"unloaded",):
            digest.update(part)
        for ea in idautils.Heads(segment.start_ea, segment.end_ea):
            function = ida_funcs.get_func(ea)
            add(
                (
                    ea,
                    int(ida_bytes.get_full_flags(ea)),
                    int(ida_bytes.get_item_end(ea)),
                    None if function is None else int(function.start_ea),
                    ida_bytes.get_cmt(ea, True),
                    ida_bytes.get_cmt(ea, False),
                    sorted(
                        (int(ref.frm), int(ref.to), int(ref.type), bool(ref.iscode))
                        for ref in idautils.XrefsFrom(ea)
                    ),
                )
            )
    add(list(idautils.Functions()))
    add(list(idautils.Names()))
    return digest.hexdigest()


def api(request):
    value = ida_expr.idc_value_t()
    expression = (
        "chernobog_vm_trace_candidate_shadow_replay("
        + str(ROOT)
        + ",0,"
        + json.dumps(json.dumps(request, separators=(",", ":")))
        + ")"
    )
    if ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression):
        raise RuntimeError("IDC call failed")
    return json.loads(value.c_str())


report = {"checks": [], "errors": []}


def check(name, condition):
    passed = bool(condition)
    report["checks"].append({"case": name, "passed": passed})
    if not passed:
        report["errors"].append(name)


try:
    raw = WINDOW.read_bytes()
    observed = json.loads(RUNTIME.read_text())
    assert len(raw) == 40
    assert raw == bytes.fromhex(observed["runtime_window_hex"])
    assert observed["binary_sha256"] == os.environ["CHERNOBOG_VMP_HELLO_BINARY_SHA256"]
    assert observed["entry_registers"] == observed["samples"][0]["registers"]
    entry = observed["entry_registers"]
    sp = int(entry["rsp"], 16)
    stack = bytes.fromhex(observed["entry_stack_above_hex"])
    assert len(stack) == 128 and sp % 16 == 8
    near = lambda value: abs(value - sp) <= 0x8000
    relative_gprs = [index for index, name in enumerate(GPRS) if near(int(entry[name], 16))]
    relative_words = [
        offset
        for offset in range(0, len(stack), 8)
        if near(struct.unpack_from("<Q", stack, offset)[0])
    ]
    request = {
        "shadow_file": str(WINDOW),
        "observed_sp": entry["rsp"],
        "gprs": [entry[name] for name in GPRS],
        "rflags": entry["eflags"],
        "stack_above": stack.hex(),
        "stack_relative_gprs": relative_gprs,
        "stack_relative_words": relative_words,
    }
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    report["inventory_before"] = inventory()
    report["runtime_sha256"] = hashlib.sha256(RUNTIME.read_bytes()).hexdigest()
    report["shadow_sha256"] = hashlib.sha256(raw).hexdigest()
    report["request_summary"] = {
        "observed_sp": entry["rsp"],
        "relative_gprs": relative_gprs,
        "relative_words": relative_words,
        "stack_sha256": hashlib.sha256(stack).hexdigest(),
    }
    result = api(request)
    report["capture"] = result
    report["inventory_after"] = inventory()
    check("replay available", result.get("available") and result.get("ran"))
    if result.get("available") and result.get("ran"):
        check(
            "observed entry replay is bounded and ephemeral",
            result["entry_state_replay"]
            and result["runtime_shadow"]
            and result["shadow_instruction_states"]
            and result["observed_entry_sp"] == entry["rsp"]
            and result["entry_stack_bytes"] == len(stack)
            and result["stack_relative_gpr_mask"] == sum(1 << index for index in relative_gprs)
            and not result["function_evidence_published"]
            and not result["vm_identity_proved"],
        )
        check("six instructions entered", result["instruction_count"] == 6)
    check("database inventory unchanged", report["inventory_before"] == report["inventory_after"])
    invalid = dict(request, observed_sp=hex(sp + 16))
    check("mismatched stack pointer rejected", not api(invalid).get("ran", False))
    invalid = dict(request, stack_relative_gprs=[index for index in relative_gprs if index != 4])
    check("missing stack pointer annotation rejected", not api(invalid).get("ran", False))
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "vmp_hello_entry_replay.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][vmp-hello-entry-replay] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
ida_pro.qexit(2 if report["errors"] else 0)
