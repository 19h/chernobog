"""Replay a captured instrumented-process state at the protected hello tail."""

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
MAIN = 0x100001440
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
    for address in range(MAIN, MAIN + 40):
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


def values(row):
    parsed = {}
    for fragment in row["registers"].split(";"):
        name, width, value = fragment.split(":")
        if int(width) != 8:
            raise ValueError("unexpected register width")
        parsed[int(name)] = int(value, 16)
    if set(parsed) != {16, 18} | set(range(256, 272)):
        raise ValueError("incomplete register state")
    return parsed


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
    path = Path(os.environ["CHERNOBOG_POSTCALL_REPORT"])
    captured = json.loads(path.read_text())
    index = int(os.environ["CHERNOBOG_POSTCALL_INDEX"])
    assert index in (0, 1)
    assert captured["schema"] == 1
    assert captured["binary_sha256"]["protected"] == os.environ["CHERNOBOG_VMP_HELLO_BINARY_SHA256"]
    source = captured["captures"]["protected"][index]
    primary_bytes = (path.parent / f"postcall-protected-{index}.bin").read_bytes()
    assert len(primary_bytes) == 328
    assert hashlib.sha256(primary_bytes).hexdigest() == source["capture_sha256"]
    assert struct.unpack_from("<3Q", primary_bytes) == (
        0x4348504F53544331,
        1,
        int(source["return_pc"], 16),
    )
    assert struct.unpack_from("<16Q", primary_bytes, 24) == tuple(
        int(source["gprs"][name], 16) for name in GPRS
    )
    assert struct.unpack_from("<Q", primary_bytes, 152)[0] == int(source["rflags"], 16)
    assert primary_bytes[160:288].hex() == source["stack_above_hex"]
    assert primary_bytes[288:328].hex() == source["runtime_window_hex"]
    assert source["count"] == 1 and source["gprs"]["rax"] == "0xb"
    window = bytes.fromhex(source["runtime_window_hex"])
    assert len(window) == 40 and hashlib.sha256(window).hexdigest() == captured["window_sha256"]
    slide = int(source["slide"], 16)
    assert int(source["return_pc"], 16) == ROOT + slide
    stack = bytes.fromhex(source["stack_above_hex"])
    assert len(stack) == 128
    sp = int(source["gprs"]["rsp"], 16)
    assert sp % 16 == 0 and int(source["gprs"]["rbp"], 16) == sp
    relative_gprs = [
        index
        for index, name in enumerate(GPRS)
        if abs(int(source["gprs"][name], 16) - sp) <= 0x8000
    ]
    relative_words = [
        offset
        for offset in range(0, len(stack), 8)
        if abs(struct.unpack_from("<Q", stack, offset)[0] - sp) <= 0x8000
    ]
    suffix = window[ROOT - MAIN :]
    shadow_file = Path(os.environ["IDAUSR"]).parent / "postcall-interpose-shadow.bin"
    shadow_file.write_bytes(suffix)
    request = {
        "shadow_file": str(shadow_file),
        "observed_sp": source["gprs"]["rsp"],
        "gprs": [source["gprs"][name] for name in GPRS],
        "rflags": source["rflags"],
        "stack_above": stack.hex(),
        "stack_relative_gprs": relative_gprs,
        "stack_relative_words": relative_words,
        "max_insns": 4,
    }
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    before = inventory()
    trace = api(request)
    report["capture"] = trace
    report["capture_sha256"] = source["capture_sha256"]
    report["primary_capture_verified"] = True
    report["interposer_report_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    report["shadow_sha256"] = hashlib.sha256(suffix).hexdigest()
    report["request_summary"] = {
        "observed_sp": source["gprs"]["rsp"],
        "relative_gprs": relative_gprs,
        "relative_words": relative_words,
        "stack_sha256": hashlib.sha256(stack).hexdigest(),
    }
    check("bounded checkpoint ran", trace.get("available") and trace.get("ran"))
    if trace.get("available") and trace.get("ran"):
        check(
            "explicit unverified provenance",
            trace["observed_checkpoint_request"]
            and trace["checkpoint_instruction_budget"] == 4
            and trace["checkpoint_provenance_verified"] is False
            and not trace["function_evidence_published"]
            and not trace["vm_identity_proved"],
        )
        check(
            "three return-tail heads",
            trace["planned_heads"] == 3
            and [int(row["site"], 16) for row in trace["execution"]] == [ROOT, ROOT + 2, ROOT + 3],
        )
        states = [row for row in trace["states"] if row["kind"] == "native instruction entry"]
        check("three entered scalar states", len(states) == 3)
        if len(states) == 3:
            entered = [values(row) for row in states]
            scratch_sp = int(trace["entry_sp"], 16)

            def actual(reg, value):
                if reg in relative_gprs:
                    displacement = value - scratch_sp
                    if not -0x8000 <= displacement <= 0x8000:
                        raise ValueError("translated pointer exceeds declared window")
                    return sp + displacement
                return value

            check(
                "captured entry scalars",
                all(
                    actual(reg, entered[0][256 + reg]) == int(source["gprs"][name], 16)
                    for reg, name in enumerate(GPRS)
                )
                and entered[0][16] == ROOT
                and entered[0][18] == int(source["rflags"], 16),
            )
            status_mask = 1 | 4 | 64 | 128 | 2048
            check(
                "XOR effects and unaffected registers",
                entered[1][16] == ROOT + 2
                and entered[1][256] == 0
                and entered[1][18] & status_mask == 4 | 64
                and all(
                    actual(reg, entered[1][256 + reg]) == int(source["gprs"][name], 16)
                    for reg, name in enumerate(GPRS)
                    if reg != 0
                ),
            )
            check(
                "POP effects and unaffected registers",
                entered[2][16] == ROOT + 3
                and entered[2][256] == 0
                and actual(4, entered[2][260]) == sp + 8
                and actual(5, entered[2][261]) == struct.unpack_from("<Q", stack)[0]
                and entered[2][18] & status_mask == 4 | 64
                and all(
                    actual(reg, entered[2][256 + reg]) == int(source["gprs"][name], 16)
                    for reg, name in enumerate(GPRS)
                    if reg not in (0, 4, 5)
                ),
            )
        final = {int(row["reg"]): int(row["value"], 16) for row in trace["final_registers"]}
        check(
            "RET effects at the frontier",
            trace["stop"] == "escaped-image-or-exception"
            and int(trace["stop_pc"], 16) == int(source["caller_return_pc"], 16)
            and final[16] == int(source["caller_return_pc"], 16)
            and final[256] == 0
            and final[260] - int(trace["entry_sp"], 16) == 16,
        )
    check(
        "missing budget rejected",
        not api({k: v for k, v in request.items() if k != "max_insns"})["available"],
    )
    check(
        "loaded stub rejected",
        api(request, 0x100001456)["reason"] == "not_unloaded_observed_checkpoint",
    )
    check("IDA inventory unchanged", before == inventory())
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "vmp_hello_postcall_interpose.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print(
    "[chernobog][vmp-hello-postcall-interpose] " + ("FAIL" if report["errors"] else "PASS"),
    flush=True,
)
ida_pro.qexit(2 if report["errors"] else 0)
