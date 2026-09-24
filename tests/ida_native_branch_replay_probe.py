"""Replay a protected Morok compare/branch from its observed process state."""

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
REGISTERS = (
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
SHADOW = Path(os.environ["CHERNOBOG_BRANCH_SHADOW_FILE"])
OBSERVED = Path(os.environ["CHERNOBOG_BRANCH_FILE"])


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
        "chernobog_vm_trace_candidate_shadow_replay_memory("
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
    observed = json.loads(OBSERVED.read_text())
    registers = observed["compare_registers"]
    sp = int(registers["rsp"], 16)
    stack = bytes.fromhex(observed["compare_stack_hex"])
    below, above = stack[:1024], stack[1024:]
    near = lambda value: abs(value - sp) <= 0x8000
    relative_gprs = [
        index for index, name in enumerate(REGISTERS) if near(int(registers[name], 16))
    ]
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
    request = {
        "shadow_file": str(SHADOW),
        "observed_sp": registers["rsp"],
        "gprs": [registers[name] for name in REGISTERS],
        "rflags": registers["eflags"],
        "stack_above": above.hex(),
        "stack_relative_gprs": relative_gprs,
        "stack_relative_words": relative_above,
        "stack_below": below.hex(),
        "stack_relative_below_words": relative_below,
        "data_start": observed["data_start"],
        "data_hex": observed["compare_data_hex"],
        "max_insns": 2,
    }
    assert hashlib.sha256(raw).hexdigest() == os.environ["CHERNOBOG_BRANCH_SHADOW_SHA256"]
    assert len(raw) == 65536 - 0x315
    assert observed["entry_packed_65536_sha256"] == observed["branch_packed_65536_sha256"]
    assert int(registers["rip"], 16) == ROOT
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    flags = ida_bytes.get_full_flags(ROOT)
    segment = ida_segment.getseg(ROOT)
    report["root_info"] = {
        "is_data": ida_bytes.is_data(flags),
        "is_head": ida_bytes.is_head(flags),
        "is_tail": ida_bytes.is_tail(flags),
        "is_loaded": ida_bytes.is_loaded(ROOT),
        "has_function": ida_funcs.get_func(ROOT) is not None,
        "segment_execute": bool(segment.perm & ida_segment.SEGPERM_EXEC),
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
    report["observation_sha256"] = hashlib.sha256(OBSERVED.read_bytes()).hexdigest()
    report["shadow_sha256"] = hashlib.sha256(raw).hexdigest()
    report["relative_gprs"] = relative_gprs
    report["relative_below"] = relative_below
    report["relative_above"] = relative_above
    result = api(request)
    report["capture"] = result
    expected = observed["successor_registers"]["rip"]
    check(
        "two-instruction observed checkpoint replay",
        result.get("available")
        and result.get("ran")
        and result.get("observed_tail_checkpoint")
        and result.get("native_state_capture_complete")
        and result.get("instruction_count") == 2
        and result.get("instruction_budget") == 2
        and result.get("stop_pc") == expected
        and result.get("stop") == "instruction-budget"
        and not result.get("function_evidence_published")
        and not result.get("vm_identity_proved"),
    )
    word = struct.unpack_from("<I", above, 12)[0]
    assert word in (1, 2)
    changed_above = bytearray(above)
    struct.pack_into("<I", changed_above, 12, 3 - word)
    changed = api(dict(request, stack_above=changed_above.hex()))
    report["stack_word_mutation"] = {
        "original": word,
        "changed": 3 - word,
        "stop_pc": changed.get("stop_pc"),
        "data": changed.get("data"),
    }
    check(
        "observed stack word controls branch",
        changed.get("ran")
        and changed.get("instruction_count") == 2
        and changed.get("stop_pc") != result.get("stop_pc")
        and any(
            row["kind"] == "read" and row["value"] == hex(3 - word)
            for row in changed.get("data", [])
        ),
    )
    invalid = dict(request)
    del invalid["max_insns"]
    check("tail checkpoint requires explicit budget", not api(invalid).get("ran", False))
    check("zero instruction budget rejected", not api(dict(request, max_insns=0)).get("ran", False))
    check(
        "oversized instruction budget rejected",
        not api(dict(request, max_insns=4097)).get("ran", False),
    )
    check(
        "executable data overlay rejected",
        not api(dict(request, data_start=hex(ROOT))).get("ran", False),
    )
    report["inventory_after"] = inventory()
    check("database inventory unchanged", report["inventory_before"] == report["inventory_after"])
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "branch_replay.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print(
    "[chernobog][branch-replay] PASS" if not report["errors"] else "[chernobog][branch-replay] FAIL"
)
ida_pro.qexit(0 if not report["errors"] else 1)
