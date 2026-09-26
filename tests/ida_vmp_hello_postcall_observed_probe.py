"""Compare the protected hello return tail with direct LLDB instruction states."""

import copy
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

MAIN = 0x100001440
ROOT = 0x100001452
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
DEFINED_XOR_FLAGS = 1 | 4 | 64 | 128 | 2048


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
    result = {}
    for fragment in row["registers"].split(";"):
        name, width, value = fragment.split(":")
        if int(width) != 8 or int(name) in result:
            raise ValueError("invalid scalar state")
        result[int(name)] = int(value, 16)
    if set(result) != {16, 18} | set(range(256, 272)):
        raise ValueError("incomplete scalar state")
    return result


def api(request):
    value = ida_expr.idc_value_t()
    expression = (
        "chernobog_vm_trace_candidate_shadow_checkpoint("
        + str(ROOT)
        + ",0,"
        + json.dumps(json.dumps(request, separators=(",", ":")))
        + ")"
    )
    if ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression):
        raise RuntimeError("IDC call failed")
    return json.loads(value.c_str())


def compare(trace, observed, relative_gprs):
    states = [values(row) for row in trace["states"] if row["kind"] == "native instruction entry"]
    if len(states) != 3 or not trace["final_registers_complete"]:
        raise ValueError("incomplete replay boundary states")
    final = {}
    for row in trace["final_registers"]:
        reg = int(row["reg"])
        if int(row["width"]) != 8 or reg in final:
            raise ValueError("invalid final scalar")
        final[reg] = int(row["value"], 16)
    if set(final) != {16, 18} | set(range(256, 272)):
        raise ValueError("incomplete final scalar state")
    states.append(final)
    expected = [sample["registers"] for sample in observed["samples"]]
    expected.append(observed["successor_registers"])
    if len(expected) != 4:
        raise ValueError("incomplete debugger boundary states")
    sp = int(observed["entry_registers"]["rsp"], 16)
    scratch = int(trace["entry_sp"], 16)
    slide = int(observed["slide"], 16)
    comparisons = []
    for boundary, (actual, source) in enumerate(zip(states, expected, strict=True)):
        for reg, name in enumerate(GPRS):
            value = actual[256 + reg]
            if reg in relative_gprs:
                value = sp + value - scratch
            comparisons.append(
                {"boundary": boundary, "scalar": name, "matched": value == int(source[name], 16)}
            )
        pc = actual[16] + (slide if boundary < 3 else 0)
        comparisons.append(
            {"boundary": boundary, "scalar": "rip", "matched": pc == int(source["rip"], 16)}
        )
        mask = (1 << 64) - 1 if boundary == 0 else DEFINED_XOR_FLAGS
        comparisons.append(
            {
                "boundary": boundary,
                "scalar": "rflags",
                "mask": hex(mask),
                "matched": actual[18] & mask == int(source["eflags"], 16) & mask,
            }
        )
    return comparisons


report = {"checks": [], "errors": []}


def check(name, condition):
    passed = bool(condition)
    report["checks"].append({"case": name, "passed": passed})
    if not passed:
        report["errors"].append(name)


try:
    source_path = Path(os.environ["CHERNOBOG_POSTCALL_STATES"])
    source_bytes = source_path.read_bytes()
    observed = json.loads(source_bytes)
    assert observed["schema"] == 1
    assert observed["capture_kind"] == "debugger postcall without dyld interposer"
    assert observed["interposer_environment_absent"] is True
    assert observed["binary_sha256"] == os.environ["CHERNOBOG_VMP_HELLO_BINARY_SHA256"]
    window = bytes.fromhex(observed["runtime_window_hex"])
    assert len(window) == 40
    entry = observed["entry_registers"]
    sp = int(entry["rsp"], 16)
    slide = int(observed["slide"], 16)
    assert int(entry["rip"], 16) == ROOT + slide
    assert observed["samples"][0]["registers"] == entry
    stack = bytes.fromhex(observed["entry_stack_above_hex"])
    assert len(stack) == 128
    for index, offset in enumerate((18, 20, 21)):
        sample = observed["samples"][index]
        assert int(sample["registers"]["rip"], 16) == MAIN + offset + slide
        assert bytes.fromhex(sample["bytes_8_hex"]) == window[offset : offset + 8]
        displacement = int(sample["registers"]["rsp"], 16) - sp
        assert bytes.fromhex(sample["stack_16_hex"]) == stack[displacement : displacement + 16]
    successor = observed["successor_registers"]
    assert int(successor["rsp"], 16) == sp + 16
    assert int(successor["rip"], 16) == struct.unpack_from("<Q", stack, 8)[0]
    assert bytes.fromhex(observed["successor_stack_16_hex"]) == stack[16:32]
    report["debugger_source_verified"] = True
    relative_gprs = [
        index for index, name in enumerate(GPRS) if abs(int(entry[name], 16) - sp) <= 0x8000
    ]
    relative_words = [
        offset
        for offset in range(0, len(stack), 8)
        if abs(struct.unpack_from("<Q", stack, offset)[0] - sp) <= 0x8000
    ]
    shadow = window[ROOT - MAIN :]
    shadow_file = Path(os.environ["IDAUSR"]).parent / "postcall-observed-shadow.bin"
    shadow_file.write_bytes(shadow)
    request = {
        "shadow_file": str(shadow_file),
        "observed_sp": entry["rsp"],
        "gprs": [entry[name] for name in GPRS],
        "rflags": entry["eflags"],
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
    report["debugger_source_sha256"] = hashlib.sha256(source_bytes).hexdigest()
    report["shadow_sha256"] = hashlib.sha256(shadow).hexdigest()
    report["stack_relative_gprs"] = relative_gprs
    report["stack_relative_words"] = relative_words
    check("bounded checkpoint ran", trace.get("available") and trace.get("ran"))
    if trace.get("available") and trace.get("ran"):
        check(
            "explicit unverified API provenance",
            trace["observed_checkpoint_request"]
            and trace["checkpoint_instruction_budget"] == 4
            and trace["checkpoint_provenance_verified"] is False
            and not trace["function_evidence_published"]
            and not trace["vm_identity_proved"],
        )
        check(
            "exact observed tail bytes",
            trace["planned_heads"] == 3
            and [(int(row["site"], 16), row["bytes"]) for row in trace["heads"]]
            == [(ROOT, "31c0"), (ROOT + 2, "5d"), (ROOT + 3, "c3")],
        )
        check(
            "exact entered tail sites",
            [int(row["site"], 16) for row in trace["execution"]] == [ROOT, ROOT + 2, ROOT + 3],
        )
        comparisons = compare(trace, observed, relative_gprs)
        report["scalar_comparisons"] = comparisons
        check(
            "all debugger boundary scalars",
            len(comparisons) == 72 and all(row["matched"] for row in comparisons),
        )
        check(
            "observed return frontier",
            trace["stop"] == "escaped-image-or-exception"
            and int(trace["stop_pc"], 16) == int(successor["rip"], 16),
        )
        reads = trace["data"]
        actual_words = []
        for offset, row in zip((0, 8), reads, strict=True):
            word = int(row["value"], 16)
            if offset in relative_words:
                word = sp + word - int(trace["entry_sp"], 16)
            actual_words.append(word)
        check(
            "two observed stack reads",
            not trace["data_trace_truncated"]
            and not trace["final_writes"]
            and [(row["kind"], int(row["site"], 16), int(row["size"])) for row in reads]
            == [("read", ROOT + 2, 8), ("read", ROOT + 3, 8)]
            and [int(row["address"], 16) - int(trace["entry_sp"], 16) for row in reads] == [0, 8]
            and actual_words == list(struct.unpack_from("<2Q", stack)),
        )
        for label, boundary, reg in (("GPR", 1, "rcx"), ("defined flag", 2, "eflags")):
            changed = copy.deepcopy(observed)
            changed["samples"][boundary]["registers"][reg] = hex(
                int(changed["samples"][boundary]["registers"][reg], 16)
                ^ (64 if reg == "eflags" else 1)
            )
            check(
                label + " mutation rejected",
                not all(row["matched"] for row in compare(trace, changed, relative_gprs)),
            )
        changed = copy.deepcopy(observed)
        changed["successor_registers"]["rip"] = hex(int(successor["rip"], 16) ^ 1)
        check(
            "return mutation rejected",
            not all(row["matched"] for row in compare(trace, changed, relative_gprs)),
        )
        changed = copy.deepcopy(observed)
        changed["samples"][1]["registers"]["eflags"] = hex(
            int(changed["samples"][1]["registers"]["eflags"], 16) ^ 16
        )
        check(
            "undefined XOR AF excluded",
            all(row["matched"] for row in compare(trace, changed, relative_gprs)),
        )
    check("IDA inventory unchanged", before == inventory())
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "vmp_hello_postcall_observed.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print(
    "[chernobog][vmp-hello-postcall-observed] " + ("FAIL" if report["errors"] else "PASS"),
    flush=True,
)
ida_pro.qexit(2 if report["errors"] else 0)
