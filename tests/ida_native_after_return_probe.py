"""Inspect the owned caller after the observed Morok post-syscall return."""

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

ROOT = 0x41B885
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


report = {"errors": []}
try:
    observed = json.loads(Path(os.environ["CHERNOBOG_AFTER_RETURN_FILE"]).read_text())
    entry = observed["boundary_registers"]
    assert int(entry["rip"], 16) == ROOT
    sp = int(entry["rsp"], 16)
    stack_base = int(observed["stack_base"], 16)
    stack = bytes.fromhex(observed["boundary_stack_hex"])
    split = sp - stack_base
    assert 0 < split <= len(stack) and split % 8 == 0
    below, above = stack[:split], stack[split:]
    near = lambda value: abs(value - sp) <= 0x8000
    relative_gprs = [index for index, name in enumerate(GPRS) if near(int(entry[name], 16))]
    relative_below = [
        offset
        for offset in range(0, len(below), 8)
        if near(struct.unpack_from("<Q", below, offset)[0])
    ]
    relative_above = [
        offset
        for offset in range(0, len(above) - len(above) % 8, 8)
        if near(struct.unpack_from("<Q", above, offset)[0])
    ]
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
    shadow = ida_bytes.get_bytes(ROOT, 256)
    assert shadow is not None and len(shadow) == 256
    shadow_path = Path(os.environ["IDAUSR"]).parent / "after_return_shadow.bin"
    shadow_path.write_bytes(shadow)
    report["shadow_origin"] = "current IDB loaded bytes at selected caller head"
    report["stack_below_bytes"] = len(below)
    report["stack_above_bytes"] = len(above)
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
        "data_hex": observed["boundary_data_hex"],
        "max_insns": 128,
    }
    report["inventory_before"] = inventory()
    report["capture"] = api(ROOT, request)
    report["interior_byte"] = api(ROOT + 1, request)
    report["wrong_observed_pc"] = api(ROOT, dict(request, observed_pc=hex(ROOT + 1)))
    report["missing_observed_pc"] = api(
        ROOT, {key: value for key, value in request.items() if key != "observed_pc"}
    )
    report["missing_budget"] = api(
        ROOT, {key: value for key, value in request.items() if key != "max_insns"}
    )
    report["inventory_after"] = inventory()
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "after_return_probe.json").write_text(
    json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
)
print("[chernobog][after-return] " + ("PASS" if not report["errors"] else "FAIL"))
ida_pro.qexit(0 if not report["errors"] else 1)
