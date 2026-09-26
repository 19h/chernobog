"""Exercise a bounded post-call shadow checkpoint with a synthetic state."""

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

ROOT = 0x100001452
WINDOW = Path(os.environ["CHERNOBOG_VMP_HELLO_WINDOW"])
RUNTIME = Path(os.environ["CHERNOBOG_VMP_HELLO_MAIN_STATES"])
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


def inventory():
    rows = []
    for address in range(0x100001440, 0x100001468):
        segment = ida_segment.getseg(address)
        owner = ida_funcs.get_func(address)
        rows.append(
            (
                address,
                None if segment is None else (segment.start_ea, segment.end_ea, segment.perm),
                int(ida_bytes.get_full_flags(address)),
                tuple(ida_bytes.get_bytes_and_mask(address, 1) or (b"unloaded",)),
                None if owner is None else int(owner.start_ea),
                tuple(
                    (int(ref.frm), int(ref.to), int(ref.type))
                    for ref in idautils.XrefsFrom(address)
                ),
            )
        )
    return rows


def state_registers(row):
    return {
        int(name): int(value, 16)
        for name, width, value in (fragment.split(":") for fragment in row["registers"].split(";"))
        if int(width) == 8
    }


def api(request, root=ROOT):
    value = ida_expr.idc_value_t()
    expression = (
        "chernobog_vm_trace_candidate_shadow_checkpoint("
        + str(root)
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
    assert len(raw) == 40 and raw.hex() == observed["runtime_window_hex"]
    assert observed["binary_sha256"] == os.environ["CHERNOBOG_VMP_HELLO_BINARY_SHA256"]
    entry = observed["entry_registers"]
    entry_sp = int(entry["rsp"], 16)
    current_sp = entry_sp - 8
    gprs = dict(entry)
    gprs["rax"] = "0xb"  # a test value; no post-printf state is asserted
    gprs["rsp"] = hex(current_sp)
    gprs["rbp"] = hex(current_sp)
    prior_stack = bytes.fromhex(observed["entry_stack_above_hex"])
    stack = struct.pack("<Q", int(entry["rbp"], 16)) + prior_stack[:120]
    near = lambda value: abs(value - current_sp) <= 0x8000
    relative_gprs = [index for index, name in enumerate(GPRS) if near(int(gprs[name], 16))]
    relative_words = [
        offset
        for offset in range(0, len(stack), 8)
        if near(struct.unpack_from("<Q", stack, offset)[0])
    ]
    suffix = raw[ROOT - 0x100001440 :]
    shadow_file = Path(os.environ["IDAUSR"]).parent / "postcall-shadow.bin"
    shadow_file.write_bytes(suffix)
    request = {
        "shadow_file": str(shadow_file),
        "observed_sp": gprs["rsp"],
        "gprs": [gprs[name] for name in GPRS],
        "rflags": entry["eflags"],
        "stack_above": stack.hex(),
        "stack_relative_gprs": relative_gprs,
        "stack_relative_words": relative_words,
        "max_insns": 4,
    }
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    before = inventory()
    result = api(request)
    report["capture"] = result
    report["shadow_sha256"] = hashlib.sha256(suffix).hexdigest()
    check("available and ran", result.get("available") and result.get("ran"))
    if result.get("available") and result.get("ran"):
        check(
            "bounded explicit checkpoint",
            result.get("observed_checkpoint_request")
            and result.get("checkpoint_instruction_budget") == 4
            and result.get("checkpoint_provenance_verified") is False
            and result.get("entry_state_replay")
            and result.get("runtime_shadow")
            and not result.get("function_evidence_published")
            and not result.get("vm_identity_proved"),
        )
        check(
            "return tail entered",
            [int(row["site"], 16) for row in result["execution"]] == [ROOT, ROOT + 2, ROOT + 3],
        )
        states = [row for row in result["states"] if row["kind"] == "native instruction entry"]
        check("three instruction states", len(states) == 3)
        if len(states) == 3:
            values = [state_registers(row) for row in states]
            scratch_sp = int(result["entry_sp"], 16)
            observed_rbp = int(entry["rbp"], 16)
            check(
                "defined tail register effects",
                values[0][256] == 11
                and values[0][260] == scratch_sp
                and values[0][261] == scratch_sp
                and values[1][256] == 0
                and values[1][260] == scratch_sp
                and values[2][256] == 0
                and values[2][260] == scratch_sp + 8
                and values[2][261] - scratch_sp == observed_rbp - current_sp,
            )
            status_mask = 1 | 4 | 64 | 128 | 2048
            check(
                "XOR defined status bits",
                values[1][18] & status_mask == 4 | 64 and values[2][18] & status_mask == 4 | 64,
            )
        check(
            "return reaches caller address",
            int(result["stop_pc"], 16) == struct.unpack_from("<Q", prior_stack)[0]
            and result["stop"] == "escaped-image-or-exception",
        )
    check(
        "missing budget rejected",
        not api({k: v for k, v in request.items() if k != "max_insns"})["available"],
    )
    check("excess budget rejected", not api(dict(request, max_insns=65))["available"])
    check("missing stack pointer rejected", not api(dict(request, stack_relative_gprs=[5]))["ran"])
    check(
        "loaded import stub rejected",
        api(request, 0x100001456).get("reason") == "not_unloaded_observed_checkpoint",
    )
    shadow_file.write_bytes(bytes([0x90]) + suffix[1:])
    changed = api(request)
    changed_states = [
        row for row in changed.get("states", []) if row["kind"] == "native instruction entry"
    ]
    check(
        "shadow mutation changes first effect",
        changed.get("ran")
        and len(changed_states) >= 2
        and state_registers(changed_states[1])[256] == 11,
    )
    shadow_file.write_bytes(suffix)
    check("IDA inventory unchanged", before == inventory())
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "vmp_hello_postcall_checkpoint.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print(
    "[chernobog][vmp-hello-postcall-checkpoint] " + ("FAIL" if report["errors"] else "PASS"),
    flush=True,
)
ida_pro.qexit(2 if report["errors"] else 0)
