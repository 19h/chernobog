"""Replay a protected entry with observed writable data and stack windows."""

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
BOUNDARY = Path(os.environ["CHERNOBOG_BOUNDARY_FILE"])


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
    boundary = json.loads(BOUNDARY.read_text())
    assert len(raw) == 65536
    assert hashlib.sha256(raw).hexdigest() == os.environ["CHERNOBOG_SHADOW_SHA256"]
    assert boundary["entry_packed_65536_sha256"] == hashlib.sha256(raw).hexdigest()
    observed = boundary["entry_registers"]
    sp = int(observed["rsp"], 16)
    assert int(observed["rip"], 16) == ROOT
    assert boundary["stack_below"] == 1024 and boundary["stack_above"] == 128
    below, above = (
        bytes.fromhex(boundary["entry_stack_hex"][:2048]),
        bytes.fromhex(boundary["entry_stack_hex"][2048:]),
    )
    data = bytes.fromhex(boundary["entry_data_hex"])
    assert len(below) == 1024 and len(above) == 128 and len(data) == 1696
    near = lambda value: abs(value - sp) <= 0x8000
    relative_gprs = [index for index, name in enumerate(GPRS) if near(int(observed[name], 16))]
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
    assert relative_gprs == [4, 5, 13]
    assert relative_below == [448, 528, 544, 552, 696, 704, 712, 840, 848, 864, 872]
    assert relative_above == [64, 80, 88, 96, 104, 112, 120]
    request = {
        "shadow_file": str(SHADOW),
        "observed_sp": observed["rsp"],
        "gprs": [observed[name] for name in GPRS],
        "rflags": observed["eflags"],
        "stack_above": above.hex(),
        "stack_relative_gprs": relative_gprs,
        "stack_relative_words": relative_above,
        "stack_below": below.hex(),
        "stack_relative_below_words": relative_below,
        "data_start": boundary["data_start"],
        "data_hex": data.hex(),
    }
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    report["inventory_before"] = inventory()
    report["boundary_report_sha256"] = hashlib.sha256(BOUNDARY.read_bytes()).hexdigest()
    report["shadow_sha256"] = hashlib.sha256(raw).hexdigest()
    report["request_summary"] = {
        "observed_sp": observed["rsp"],
        "relative_gprs": relative_gprs,
        "relative_below_words": relative_below,
        "relative_above_words": relative_above,
        "below_sha256": hashlib.sha256(below).hexdigest(),
        "above_sha256": hashlib.sha256(above).hexdigest(),
        "data_sha256": hashlib.sha256(data).hexdigest(),
    }
    result = api(request)
    report["capture"] = result
    check("entry memory replay available", result["available"] and result["ran"])
    check(
        "bounded observed entry scope",
        result["entry_state_replay"]
        and result["runtime_shadow"]
        and result["runtime_data"]
        and result["shadow_instruction_states"]
        and result["observed_entry_sp"] == observed["rsp"]
        and result["entry_stack_below_bytes"] == 1024
        and result["entry_stack_bytes"] == 128
        and result["data_bytes"] == 1696
        and result["data_start"] == boundary["data_start"]
        and (int(result["entry_sp"], 16) & 0xFFF) == (sp & 0xFFF)
        and not result["function_evidence_published"]
        and not result["vm_identity_proved"],
    )
    check("bounded instruction states", result["instruction_count"] == 4096)
    mutated_data = bytearray(data)
    mutated_data[0x684] ^= 1
    mutated = api(dict(request, data_hex=mutated_data.hex()))
    first_data_read = next(
        (
            row
            for row in mutated.get("data", [])
            if row["kind"] == "read"
            and row["address"] == hex(int(boundary["data_start"], 16) + 0x684)
        ),
        None,
    )
    check(
        "entry data mutation observed by first read",
        first_data_read is not None and first_data_read["value"] == "0x1",
    )
    check("entry data mutation changes bounded path", mutated.get("stop_pc") != result["stop_pc"])
    report["data_mutation"] = {
        "offset": 0x684,
        "first_read_value": None if first_data_read is None else first_data_read["value"],
        "stop": mutated.get("stop"),
        "stop_pc": mutated.get("stop_pc"),
    }
    invalid = dict(request, stack_relative_below_words=relative_below[:-1])
    check("missing below pointer annotation rejected", not api(invalid).get("ran", False))
    invalid = dict(request, data_start=hex(ROOT))
    check("executable data patch rejected", not api(invalid).get("ran", False))
    invalid = dict(request)
    del invalid["data_hex"]
    check("missing data field rejected", not api(invalid).get("ran", False))
    report["inventory_after"] = inventory()
    check("database inventory unchanged", report["inventory_before"] == report["inventory_after"])
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "shadow_memory_replay.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][shadow-memory-replay] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
ida_pro.qexit(2 if report["errors"] else 0)
