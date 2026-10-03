"""Replay an observed owned code head after a protected Morok syscall."""

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

ROOT = 0x41D797
OWNER = 0x41D6C9
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


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def api(address, request):
    result = ida_expr.idc_value_t()
    expression = (
        "chernobog_vm_trace_owned_shadow_replay_memory("
        + str(address)
        + ",0,"
        + json.dumps(json.dumps(request, separators=(",", ":")))
        + ")"
    )
    if ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression):
        raise RuntimeError("IDC call failed")
    return json.loads(result.c_str())


def inventory():
    state = hashlib.sha256()

    def add(value):
        state.update(json.dumps(value, separators=(",", ":")).encode())
        state.update(b"\n")

    total = 0
    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        size = segment.end_ea - segment.start_ea
        total += size
        if total > 64 * 1024 * 1024:
            raise RuntimeError("database exceeds inventory bound")
        add((segment.start_ea, segment.end_ea, segment.bitness, segment.perm))
        for part in ida_bytes.get_bytes_and_mask(segment.start_ea, size) or (b"unloaded",):
            state.update(part)
        for address in idautils.Heads(segment.start_ea, segment.end_ea):
            flags = ida_bytes.get_full_flags(address)
            owner = ida_funcs.get_func(address)
            add(
                (
                    address,
                    int(flags),
                    int(ida_bytes.get_item_end(address)),
                    None if owner is None else int(owner.start_ea),
                    ida_bytes.get_cmt(address, True),
                    ida_bytes.get_cmt(address, False),
                )
            )
            add(
                sorted(
                    (int(ref.frm), int(ref.to), int(ref.type), bool(ref.iscode), bool(ref.user))
                    for ref in idautils.XrefsFrom(address)
                )
            )
    add([(address, list(idautils.Chunks(address))) for address in idautils.Functions()])
    add(list(idautils.Names()))
    return state.hexdigest()


report = {"checks": [], "errors": []}


def check(name, passed):
    report["checks"].append({"case": name, "passed": bool(passed)})
    if not passed:
        report["errors"].append(name)


try:
    observed_path = Path(os.environ["CHERNOBOG_POST_SYSCALL_FILE"])
    shadow_path = Path(os.environ["CHERNOBOG_POST_SYSCALL_SHADOW_FILE"])
    observed = json.loads(observed_path.read_text())
    entry = observed["entry_registers"]
    sp = int(entry["rsp"], 16)
    stack = bytes.fromhex(observed["entry_stack_hex"])
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
    assert digest(shadow_path) == observed["shadow_sha256"]
    assert observed["root"] == hex(ROOT) and observed["owner"] == hex(OWNER)
    request = {
        "shadow_file": str(shadow_path),
        "observed_sp": entry["rsp"],
        "observed_pc": entry["rip"],
        "gprs": [entry[name] for name in GPRS],
        "rflags": entry["eflags"],
        "stack_above": above.hex(),
        "stack_relative_gprs": relative_gprs,
        "stack_relative_words": relative_above,
        "stack_below": below.hex(),
        "stack_relative_below_words": relative_below,
        "data_start": observed["data_start"],
        "data_hex": observed["entry_data_hex"],
        "max_insns": 128,
    }
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    owner = ida_funcs.get_func(ROOT)
    flags = ida_bytes.get_full_flags(ROOT)
    segment = ida_segment.getseg(ROOT)
    report["root_info"] = {
        "owner": None if owner is None else hex(owner.start_ea),
        "code_head": ida_bytes.is_code(flags) and ida_bytes.is_head(flags),
        "loaded": ida_bytes.is_loaded(ROOT),
        "segment_execute": bool(segment and segment.perm & ida_segment.SEGPERM_EXEC),
    }
    check(
        "owned interior code head",
        report["root_info"]
        == {
            "owner": hex(OWNER),
            "code_head": True,
            "loaded": True,
            "segment_execute": True,
        },
    )
    report["inventory_before"] = inventory()
    report["capture"] = api(ROOT, request)
    report["interior_byte"] = api(ROOT + 1, request)
    report["missing_observed_pc"] = api(
        ROOT, {key: value for key, value in request.items() if key != "observed_pc"}
    )
    report["wrong_observed_pc"] = api(ROOT, dict(request, observed_pc=hex(ROOT + 3)))
    report["missing_budget"] = api(
        ROOT, {key: value for key, value in request.items() if key != "max_insns"}
    )
    report["inventory_after"] = inventory()
    capture = report["capture"]
    check(
        "bounded owned tail admitted",
        capture.get("available")
        and capture.get("ran")
        and capture.get("observed_function_checkpoint")
        and capture.get("checkpoint_owner") == hex(OWNER)
        and capture.get("function") == hex(ROOT)
        and capture.get("instruction_budget") == 128
        and capture.get("native_state_capture_complete")
        and not capture.get("function_evidence_published")
        and not capture.get("vm_identity_proved"),
    )
    check("interior byte rejected", not report["interior_byte"].get("available"))
    check("missing observed PC rejected", not report["missing_observed_pc"].get("available"))
    check("wrong observed PC rejected", not report["wrong_observed_pc"].get("available"))
    check("missing budget rejected", not report["missing_budget"].get("available"))
    check("database inventory unchanged", report["inventory_before"] == report["inventory_after"])
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "post_syscall_probe.json").write_text(
    json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
)
print("[chernobog][post-syscall-probe] " + ("PASS" if not report["errors"] else "FAIL"))
ida_pro.qexit(0 if not report["errors"] else 1)
