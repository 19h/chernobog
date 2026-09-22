"""Production decoding, conditional summaries and observed immediate-push checks."""

import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import traceback

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_loader
import ida_name
import ida_pro
import ida_segment
import ida_ua
import ida_xref
import idautils

sys.dont_write_bytecode = True
checks, errors, captures = [], [], []
symbols, static, summaries = {}, None, None
before = after = None
config = json.loads(os.environ["CHERNOBOG_VM_PUSH_CONFIG"])


def check(name, condition):
    checks.append({"case": name, "passed": bool(condition)})
    if not condition:
        errors.append(name)


def api(expression):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, expression)
    return json.loads(value.c_str())


def symbol(suffix):
    # The relative fixture's fast continuation is its final JMP. Object formats
    # retain both labels, but IDA may retain either name for their shared address.
    aliases = (suffix,)
    if config["relative"] and suffix in ("continuation", "dispatch"):
        aliases = ("continuation", "dispatch")
    addresses = set()
    for name in aliases:
        for prefix in ("_vm_push_", "vm_push_"):
            ea = ida_name.get_name_ea(ida_idaapi.BADADDR, prefix + name)
            if ea != ida_idaapi.BADADDR:
                addresses.add(int(ea))
    if addresses:
        assert len(addresses) == 1
        return addresses.pop()
    raise AssertionError("missing fixture symbol")


def oracle(index, equal):
    """Integer and byte oracle; no production IR or emulator values are inputs."""
    bits, mode = config["bits"], config["mode"]
    dispatch_bits = 32 if config["relative"] else 8
    encoded = (0, (1 << 64) - 1, 0x80017FFFAB0080FE)[index] & ((1 << bits) - 1)
    key = (0, (1 << 64) - 1, 0x9A785634A581F03C)[index] & ((1 << mode) - 1)
    mixed = (encoded ^ key) & ((1 << bits) - 1)
    decoded = ((((mixed << 3) | (mixed >> (bits - 3))) & ((1 << bits) - 1)) + 7) & ((1 << bits) - 1)
    decoded = ((decoded ^ 0x5A) - 9) & ((1 << bits) - 1)
    payload_key = key ^ decoded
    delta = (-32, 0x7FFFFFFF, -0x80000000)[index] if config["relative"] else 0
    key_after = payload_key ^ (delta & 0xFFFFFFFF)
    inverse = ((((delta + 9) & ((1 << dispatch_bits) - 1)) ^ 0x5A) - 7) & ((1 << dispatch_bits) - 1)
    dispatch_encoded = ((inverse >> 3) | (inverse << (dispatch_bits - 3))) & (
        (1 << dispatch_bits) - 1
    )
    dispatch_encoded ^= payload_key & ((1 << dispatch_bits) - 1)
    payload_bytes, dispatch_bytes = bits // 8, dispatch_bits // 8
    code = bytearray(16)
    at = dispatch_bytes if config["backward"] else 0
    code[at : at + payload_bytes] = encoded.to_bytes(payload_bytes, "little")
    at = 0 if config["backward"] else payload_bytes
    code[at : at + dispatch_bytes] = dispatch_encoded.to_bytes(dispatch_bytes, "little")
    code[12:16] = (delta & 0xFFFFFFFF).to_bytes(4, "little")
    consumed = payload_bytes + (dispatch_bytes if config["relative"] or not equal else 0)
    vip_after = payload_bytes + dispatch_bytes - consumed if config["backward"] else consumed
    stored_bits = max(16, bits)
    stored = (0xA5A5A5A5A5A5A5A5 & ~((1 << stored_bits) - 1)) | decoded
    initial = bytes(code) + struct.pack("<7Q", key, 0, 0, 0, 0, 0, 0)
    final = bytes(code) + struct.pack(
        "<7Q", key, stored, key_after, vip_after, 1 - equal, 0x3C3C3C3C3C3C3C3C, 0x5A5A5A5A5A5A5A5A
    )
    return initial.hex(), final.hex(), decoded, key_after


def inventory():
    digest = hashlib.sha256()
    total = heads = refs = 0
    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        size = int(segment.end_ea - segment.start_ea)
        total += size
        assert total <= 64 * 1024 * 1024
        digest.update(
            str(
                (
                    int(segment.start_ea),
                    int(segment.end_ea),
                    int(segment.bitness),
                    int(segment.perm),
                )
            ).encode()
        )
        for part in ida_bytes.get_bytes_and_mask(segment.start_ea, size) or (b"unloaded",):
            digest.update(part)
        for ea in idautils.Heads(segment.start_ea, segment.end_ea):
            heads += 1
            assert heads <= 1048576
            digest.update(
                str(
                    (ea, int(ida_bytes.get_full_flags(ea)), int(ida_bytes.get_item_end(ea)))
                ).encode()
            )
            xref = ida_xref.xrefblk_t()
            more = xref.first_from(ea, ida_xref.XREF_ALL)
            while more:
                refs += 1
                assert refs <= 2097152
                digest.update(
                    str((int(xref.frm), int(xref.to), int(xref.type), bool(xref.iscode))).encode()
                )
                more = xref.next_from()
    functions = list(idautils.Functions())
    assert len(functions) <= 4096
    for ea in functions:
        digest.update(
            str((ea, int(ida_funcs.get_func(ea).flags), list(idautils.Chunks(ea)))).encode()
        )
    return {
        "sha256": digest.hexdigest(),
        "heads": heads,
        "xrefs": refs,
        "functions": len(functions),
    }


def registers(state):
    result = {}
    for item in state["registers"].split(";"):
        reg, width, value = item.split(":")
        reg, width, value = int(reg), int(width), int(value, 0)
        assert width == config["mode"] // 8 and reg not in result
        result[reg] = value
    return result


try:
    ida_auto.auto_wait()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    for name in (
        "run",
        "handler",
        "store",
        "stack_check",
        "branch",
        "continuation",
        "dispatch",
        "capture",
        "slow",
        "end",
    ):
        symbols[name] = symbol(name)
    start, end = symbols["run"], symbols["end"]
    assert start < end and end - start < 4096
    # The assembly owns this explicit fixture range. This setup does not infer
    # handler ownership or alter the production recognizer's entry rules.
    for ea in list(idautils.Functions(start, end)):
        ida_funcs.del_func(ea)
    # These source-owned INT3 gaps are nonexecuted padding. Defining them as
    # instructions would add an artificial IDA fallthrough into the next label.
    # Assert their exact bytes before retaining them as data in the fixture IDB.
    gaps = {symbols["stack_check"] - 3, symbols["capture"] - 3}
    assert len(gaps) == 2
    for gap in gaps:
        assert start <= gap < gap + 3 <= end
        assert ida_bytes.get_bytes(gap, 3) == b"\xcc" * 3
        assert ida_bytes.del_items(gap, ida_bytes.DELIT_SIMPLE, 3)
        assert ida_bytes.create_data(gap, ida_bytes.FF_BYTE, 3, ida_idaapi.BADADDR)
    ea = start
    while ea < end:
        if ea in gaps:
            ea += 3
            continue
        size = ida_ua.create_insn(ea)
        assert size > 0
        ea += size
    assert ea == end and ida_funcs.add_func(start, end)
    ida_auto.auto_wait()
    result = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, "chernobog_native_analysis()")
    ida_auto.auto_wait()
    ida_auto.enable_auto(False)
    before = inventory()
    publication = api(f"chernobog_evidence_state({start})")
    static = api(f"chernobog_vm_regions({start})")
    summaries = api(f"chernobog_vm_summaries({start})")
    candidates = [
        row
        for row in static["records"]
        if int(row["site"], 0) == symbols["handler"]
        and row.get("payload_bits") == str(config["bits"])
    ]
    check("one complete synthetic fast-path candidate", len(candidates) == 1)
    assert len(candidates) == 1
    candidate = candidates[0]
    check(
        "payload and dispatch metadata are distinct",
        candidate["stored_bits"] == str(max(16, config["bits"]))
        and candidate["read_bits"] == str(32 if config["relative"] else 8)
        and candidate["payload_read"] != candidate["read"]
        and int(candidate["payload_store"], 0) == symbols["store"]
        and candidate["payload_value_register"] == "2"
        and candidate["virtual_stack_register"] == "5"
        and candidate["stack_check_register"] == "1"
        and candidate["stack_check"] == "true"
        and int(candidate["stack_check_branch"], 0) == symbols["branch"]
        and int(candidate["stack_check_offset"], 0) == (256 if config["mode"] == 64 else 96),
    )
    check(
        "direction retained",
        candidate["direction"] == ("backward" if config["backward"] else "forward"),
    )
    bindings = [
        row
        for row in summaries["summary_bindings"]
        if row["vm_candidate"] == candidate["vm_candidate"]
    ]
    check(
        "complete candidate has a summary reference",
        len(bindings) == 1 and "summary_id" in bindings[0],
    )
    assert len(bindings) == 1 and "summary_id" in bindings[0]
    described = [
        row for row in summaries["summaries"] if row["summary_id"] == bindings[0]["summary_id"]
    ]
    check(
        "conditional input domain explicitly displayed",
        len(described) == 1
        and described[0].get("domain_complete") == "true"
        and "input_virtual_stack" in described[0].get("domain", "")
        and "input_sp" in described[0].get("domain", "")
        and described[0]["domain"] != "true",
    )
    for index in range(3):
        for equal in range(2):
            prefix = f"case{index}:equal{equal}"
            initial, final, decoded, key_after = oracle(index, equal)
            supplied = {
                "args": ["0x0", hex(equal)],
                "objects": [{"argument": 0, "offset": 0, "bytes": initial}],
            }
            text = json.dumps(supplied, separators=(",", ":"))
            trace = api(
                f"chernobog_vm_trace_check({start}, {index * 2 + equal}, {json.dumps(text)})"
            )
            captures.append({"index": index, "equal": equal, "input": supplied, "trace": trace})
            check(
                prefix + " available completed native capture",
                trace.get("available") and trace.get("ran") and trace.get("reached_sentinel"),
            )
            assert trace.get("available") and trace.get("ran")
            check(
                prefix + " scoped explicit input and complete state",
                trace["scope"] == "native-region"
                and trace["explicit_input"]
                and not trace["function_evidence_published"]
                and not trace["vm_identity_proved"]
                and trace["native_state_capture_requested"]
                and trace["native_state_capture_complete"]
                and trace["final_registers_complete"]
                and trace["data_trace_complete"],
            )
            objects = trace["input_objects"]
            check(
                prefix + " independent object and guard-byte oracle",
                len(objects) == 1
                and objects[0]["initial"] == initial
                and objects[0]["final"] == final,
            )
            final_registers = {
                int(row["reg"]): int(row["value"], 0) for row in trace["final_registers"]
            }
            base = 0x100 if config["mode"] == 64 else 0x200
            check(
                prefix + " independent return and native stack oracle",
                final_registers.get(base) == 1 - equal
                and trace["sp_valid"]
                and trace["sp_delta"] == config["mode"] // 8,
            )
            branch_states = [
                row
                for row in trace["states"]
                if row["kind"] == "native instruction entry"
                and int(row["site"], 0) == symbols["branch"]
            ]
            check(prefix + " unique captured stack-check state", len(branch_states) == 1)
            assert len(branch_states) == 1
            branch_registers = registers(branch_states[0])
            native_sp, virtual_sp = branch_registers[base + 4], branch_registers[base + 5]
            limit = (native_sp + (256 if config["mode"] == 64 else 96)) & (
                (1 << config["mode"]) - 1
            )
            flags = branch_registers[0x12 if config["mode"] == 64 else 0x13]
            check(
                prefix + " strict unsigned stack-check oracle",
                (virtual_sp == limit if equal else virtual_sp > limit)
                and flags & 0x41 == (0x40 if equal else 0),
            )
            branch_edges = [
                row for row in trace["edges"] if int(row["source"], 0) == symbols["branch"]
            ]
            if not equal:
                check(
                    prefix + " taken JA destination witnessed",
                    len(branch_edges) == 1
                    and int(branch_edges[0]["target"], 0) == symbols["continuation"],
                )
            else:
                check(
                    prefix + " equality never takes fast edge",
                    not any(
                        int(row["target"], 0) == symbols["continuation"] for row in branch_edges
                    ),
                )
                check(
                    prefix + " controlled slow stub executed",
                    any(int(row["site"], 0) == symbols["slow"] for row in trace["execution"]),
                )
            stores = [row for row in trace["data"] if int(row["site"], 0) == symbols["store"]]
            check(
                prefix + " exact payload write witnessed",
                len(stores) == 1
                and stores[0]["kind"] == "write"
                and int(stores[0]["size"]) == max(2, config["bits"] // 8)
                and int(stores[0]["address"], 0) == virtual_sp
                and int(stores[0]["value"], 0) == decoded,
            )
            view = trace["native_observations"]
            check(prefix + " native projection available", view["available"])
            rows = [
                row
                for row in view["records"]
                if int(row["site"], 0) == symbols["handler"]
                and row.get("payload_bits") == str(config["bits"])
            ]
            check(
                prefix + " fast-path admission follows actual branch", len(rows) == int(not equal)
            )
            for row in rows:
                validated = (
                    row["semantic_validation"] == "corroborated for captured transition"
                    and row.get("transition_queries") == "2"
                    and row["path"] == "complete captured native path"
                    and row["data_capture_complete"] == "true"
                    and row["stack_check"] == "true"
                    and int(row.get("target", "-1"), 0) == symbols["capture"]
                )
                check(
                    prefix + " full captured transition corroborated nonvacuously",
                    validated,
                )
                if not validated:
                    continue
                check(
                    prefix + " virtual-stack delta and retained key corroborated",
                    int(row["entry_virtual_stack"], 0) - int(row["output_virtual_stack"], 0)
                    == max(2, config["bits"] // 8)
                    and int(row["output_virtual_stack"], 0) == virtual_sp
                    and int(row["output_key"], 0) == key_after
                    and int(row["output_payload_register"], 0) == decoded
                    and int(row["output_stack_check_register"], 0) == limit
                    and row["payload_value_register"] == "2"
                    and row["virtual_stack_register"] == "5"
                    and row["stack_check_register"] == "1",
                )
                if config["relative"]:
                    delta = (-32, 0x7FFFFFFF, -0x80000000)[index]
                    address_mask = (1 << config["mode"]) - 1
                    check(
                        prefix + " signed delta and live dispatch base oracle",
                        int(row["output_decoded_register"], 0) == delta & address_mask
                        and (int(row["entry_dispatch_base"], 0) + delta) & address_mask
                        == symbols["capture"]
                        and int(row["output_dispatch_base"], 0) == symbols["capture"],
                    )
                check(
                    prefix + " local role observations preserve unknown global identity",
                    row["scope"] == "native-region"
                    and int(row["capture"], 0) == trace["capture"]
                    and row["region_identity"] == trace["region_identity"]
                    and row["image_hash"] == trace["image_hash"]
                    and row["logical_state_complete"] == "false"
                    and row["vm_context"] == row["memory_epoch"] == "unknown"
                    and row["merge"] == "not admitted",
                )
    after = inventory()
    check("inspection and captures leave database unchanged", before == after)
    check(
        "ordinary publication unchanged", api(f"chernobog_evidence_state({start})") == publication
    )
    check(
        "static candidate inventory remains repeatable",
        api(f"chernobog_vm_regions({start})") == static,
    )
except Exception as error:
    errors.append(type(error).__name__)
    errors.extend(
        frame.name + ":" + str(frame.lineno) for frame in traceback.extract_tb(error.__traceback__)
    )

report = {
    "schema": 1,
    "passed": not errors,
    "scope": "synthetic source-grammar fixture; observed fast stack-check path only; no relocation semantics or protector-source authenticity claim",
    "config": config,
    "symbols": symbols,
    "checks": checks,
    "errors": errors,
    "inventory_before": before,
    "inventory_after": after,
    "candidates": static,
    "summaries": summaries,
    "captures": captures,
}
(Path(os.environ["IDAUSR"]).parent / "vm_push_handlers.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][vm-push-handler] " + ("FAIL" if errors else "PASS"), flush=True)
ida_pro.qexit(2 if errors else 0)
