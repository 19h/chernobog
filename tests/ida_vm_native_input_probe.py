"""Explicit native inputs: observable behavior, rejection, and IDB preservation."""

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
import ida_pro
import ida_segment
import ida_xref
import idautils

sys.dont_write_bytecode = True
checks, errors, captures = [], [], []


def check(name, condition):
    checks.append({"case": name, "passed": bool(condition)})
    if not condition:
        errors.append(name)


def api(expression):
    result = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression)
    return json.loads(result.c_str())


def inventory():
    h = hashlib.sha256()
    total = heads = refs = 0
    for i in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(i)
        length = int(segment.end_ea - segment.start_ea)
        total += length
        assert total <= 64 * 1024 * 1024
        h.update(
            str(
                (
                    int(segment.start_ea),
                    int(segment.end_ea),
                    int(segment.bitness),
                    int(segment.perm),
                )
            ).encode()
        )
        for part in ida_bytes.get_bytes_and_mask(segment.start_ea, length) or (b"unloaded",):
            h.update(part)
        for ea in idautils.Heads(segment.start_ea, segment.end_ea):
            heads += 1
            assert heads <= 1048576
            h.update(
                str(
                    (ea, int(ida_bytes.get_full_flags(ea)), int(ida_bytes.get_item_end(ea)))
                ).encode()
            )
            x = ida_xref.xrefblk_t()
            ok = x.first_from(ea, ida_xref.XREF_ALL)
            while ok:
                refs += 1
                assert refs <= 2097152
                h.update(str((int(x.frm), int(x.to), int(x.type), bool(x.iscode))).encode())
                ok = x.next_from()
    functions = list(idautils.Functions())
    assert len(functions) <= 4096
    for ea in functions:
        h.update(str((ea, int(ida_funcs.get_func(ea).flags), list(idautils.Chunks(ea)))).encode())
    return {"sha256": h.hexdigest(), "heads": heads, "xrefs": refs, "functions": len(functions)}


def oracle(name, x, y, initial):
    # Integer model of pair.S/pair32.S, independent of emulator/production IR.
    operand = y if name == "corpus_branch" and x < y else x
    v = initial ^ operand
    rotated = ((v << 5) | (v >> 27)) & 0xFFFFFFFF
    total = rotated + y
    result = total & 0xFFFFFFFF
    flags = int(total > 0xFFFFFFFF)
    flags |= int((result & 255).bit_count() % 2 == 0) << 2
    flags |= int(bool((rotated ^ y ^ result) & 16)) << 4
    flags |= int(result == 0) << 6
    flags |= ((result >> 31) & 1) << 7
    flags |= int(bool((~(rotated ^ y) & (rotated ^ result)) & 0x80000000)) << 11
    return result, flags, struct.pack("<III", 0xA5A5A5A5, result, 0x5A5A5A5A).hex()


def request(ea, value, seed=0, walk=None):
    text = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    if walk is None:
        walk = os.environ.get("CHERNOBOG_NATIVE_WALK") == "1"
    function = (
        (
            "chernobog_vm_trace_check"
            if os.environ.get("CHERNOBOG_NATIVE_CHECK") == "1"
            else "chernobog_vm_trace_walk"
        )
        if walk
        else "chernobog_vm_trace_input"
    )
    return api(f"{function}({ea}, {seed}, {json.dumps(text)})")


before = after = None
try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, "chernobog_native_analysis()")
    ida_auto.auto_wait()
    ida_auto.enable_auto(False)
    entries = {
        name: int(ea, 0) for name, ea in json.loads(os.environ["CHERNOBOG_CORPUS_ENTRIES"]).items()
    }
    assert set(entries) == {"corpus_transform", "corpus_branch"}
    before = inventory()
    publication = {name: api(f"chernobog_evidence_state({ea})") for name, ea in entries.items()}
    # Eight corner triples plus eight deterministic independent xorshift triples.
    cases = [
        (0, 0, 0),
        (0, 1, 0xFFFFFFFF),
        (1, 0, 0x80000000),
        (0x7FFFFFFF, 1, 0),
        (0x80000000, 0xFFFFFFFF, 1),
        (0xFFFFFFFF, 0x7FFFFFFF, 0xFFFFFFFE),
        (15, 1, 0),
        (1, 1, 1),
    ]
    state = 0xC0FFEE
    for _ in range(8):
        values = []
        for _ in range(3):
            state ^= (state << 13) & 0xFFFFFFFF
            state ^= state >> 17
            state ^= (state << 5) & 0xFFFFFFFF
            state &= 0xFFFFFFFF
            values.append(state)
        cases.append(tuple(values))
    for name, ea in entries.items():
        for index, (x, y, initial) in enumerate(cases):
            data = struct.pack("<III", 0xA5A5A5A5, initial, 0x5A5A5A5A).hex()
            supplied = {
                "args": [hex(x), hex(y), "0x0"],
                "objects": [{"argument": 2, "offset": 4, "bytes": data}],
            }
            trace = request(ea, supplied, index)
            captures.append({"name": name, "case": index, "input": supplied, "trace": trace})
            prefix = name + ":" + str(index)
            check(prefix + " available", trace.get("available") and trace.get("ran"))
            if not trace.get("available") or not trace.get("ran"):
                continue
            mode = trace["address_bits"]
            check(
                prefix + " isolated evidence",
                trace["explicit_input"]
                and trace["scope"] == "native-region"
                and not trace["function_evidence_published"]
                and not trace["vm_identity_proved"],
            )
            objects = trace["input_objects"]
            check(
                prefix + " object snapshot",
                len(objects) == 1
                and objects[0]["initial"] == data
                and objects[0]["readable"] == "true"
                and len(objects[0]["final"]) == len(data),
            )
            check(prefix + " complete final registers", trace["final_registers_complete"])
            if os.environ.get("CHERNOBOG_NATIVE_WALK") == "1":
                baseline = request(ea, supplied, index, walk=False)
                captures[-1]["baseline"] = baseline
                check(
                    prefix + " bounded native walk",
                    trace["native_walk"]
                    and len(trace["native_admissions"]) <= 64
                    and trace["planned_heads"] <= 4096
                    and len(trace["execution"]) <= 4096
                    and len(trace["data"]) <= 4096,
                )
                check(
                    prefix + " matched snapshot and input",
                    baseline["available"]
                    and baseline["ran"]
                    and trace["initial_region_identity"] == baseline["region_identity"]
                    and trace["input_arguments"] == baseline["input_arguments"]
                    and trace["states"][0] == baseline["states"][0],
                )
                # Independent engine instances need not share timestamp/random
                # inputs. Preserve each comparison result as a measurement;
                # continuation correctness uses one retained machine state.
                captures[-1]["separate_run_prefix_equal"] = {
                    field: (
                        [s for s in trace[field] if s["kind"] != "native instruction entry"]
                        if field == "states"
                        else trace[field]
                    )[: len(baseline[field])]
                    == baseline[field]
                    for field in ("execution", "edges", "states", "data")
                }
                for field in ("execution", "data"):
                    sequences = [int(row["sequence"]) for row in trace[field]]
                    check(prefix + " unique ordered " + field, sequences == sorted(set(sequences)))
                identity = trace["initial_region_identity"]
                for step in trace["native_admissions"]:
                    edge = [
                        row
                        for row in trace["edges"]
                        if row["source"] == step["source"]
                        and row["target"] == step["target"]
                        and row["sequence"] == step["sequence"]
                    ]
                    check(
                        prefix + " observed admission provenance",
                        len(edge) == 1 and step["before_identity"] == identity,
                    )
                    identity = step["after_identity"]
                    if step["admitted"] == "true":
                        check(
                            prefix + " admitted target in plan",
                            int(step["added_heads"]) > 0
                            and any(head["site"] == step["target"] for head in trace["heads"]),
                        )
                    else:
                        check(
                            prefix + " rejected admission preserves plan",
                            step["after_identity"] == step["before_identity"]
                            and step["added_heads"] == "0",
                        )
                check(prefix + " final plan provenance", identity == trace["region_identity"])
            if os.environ.get("CHERNOBOG_NATIVE_CHECK") == "1":
                view = trace["native_observations"]
                check(
                    prefix + " native projection available",
                    view["available"]
                    and trace["native_state_capture_requested"]
                    and trace["native_state_capture_complete"],
                )
                samples = [
                    state
                    for state in trace["states"]
                    if state["kind"] == "native instruction entry"
                ]
                check(
                    prefix + " one state per entered instruction",
                    [(s["site"], s["sequence"]) for s in samples]
                    == [(e["site"], e["sequence"]) for e in trace["execution"]],
                )
                check(
                    prefix + " projection quotas",
                    len(trace["states"]) <= 12289
                    and view["path_steps"] <= 8192
                    and len(view["records"]) <= 128
                    and view["transition_attempts"] <= 16
                    and view["queries"] <= 32,
                )
                for row in view["records"]:
                    check(
                        prefix + " native candidate provenance",
                        row["scope"] == "native-region"
                        and int(row["capture"], 0) == trace["capture"]
                        and row["region_identity"] == trace["region_identity"]
                        and row["image_hash"] == trace["image_hash"]
                        and row["logical_state_complete"] == "false"
                        and row["virtual_stack"]
                        == row["vm_context"]
                        == row["memory_epoch"]
                        == "unknown"
                        and row["merge"] == "not admitted",
                    )
                    if row["semantic_validation"] == "corroborated for captured transition":
                        check(
                            prefix + " nonvacuous captured transition",
                            row["transition_queries"] == "2"
                            and row["path"] == "complete captured native path"
                            and row["data_capture_complete"] == "true",
                        )
            if os.environ["CHERNOBOG_EXPECT_RETURN"] == "1":
                check(prefix + " returned", trace["reached_sentinel"])
            if trace["reached_sentinel"]:
                result, flags, memory = oracle(name, x, y, initial)
                registers = {
                    int(row["reg"]): int(row["value"], 0) for row in trace["final_registers"]
                }
                check(prefix + " result", registers.get(0x100 if mode == 64 else 0x200) == result)
                check(
                    prefix + " defined flags",
                    registers.get(0x12 if mode == 64 else 0x13, -1) & 0x8D5 == flags,
                )
                check(
                    prefix + " selected memory and guards",
                    len(objects) == 1 and objects[0]["final"] == memory,
                )
                check(prefix + " stack", trace["sp_valid"] and trace["sp_delta"] == mode // 8)
                check(prefix + " complete data trace", trace["data_trace_complete"])
    ea = next(iter(entries.values()))
    invalid = [
        "{",
        '{"args":[],"objects":[],"extra":0}',
        '{"args":[],"args":[],"objects":[]}',
        "[" * 9 + "]" * 9,
        {"args": [1], "objects": []},
        {"args": ["0x10000000000000000"], "objects": []},
        {"args": ["0x0"] * 33, "objects": []},
        {"args": ["0x0"], "objects": [{"argument": 0, "offset": 0, "bytes": "00"}] * 17},
    ]
    for field, bad in (
        ("offset", 1),
        ("offset", -1),
        ("argument", 1),
        ("argument", -1),
        ("bytes", ""),
        ("bytes", "0"),
        ("bytes", "gg"),
        ("bytes", "00" * 4097),
    ):
        obj = {"argument": 0, "offset": 0, "bytes": "00"}
        obj[field] = bad
        invalid.append({"args": ["0x0"], "objects": [obj]})
    invalid.append({"args": ["0x1"], "objects": [{"argument": 0, "offset": 0, "bytes": "00"}]})
    invalid.append({"args": ["0x0"], "objects": [{"argument": 0, "offset": 0, "bytes": "00"}] * 2})
    for index, bad in enumerate(invalid):
        answer = request(ea, bad)
        check(
            "invalid input " + str(index),
            not answer["available"] and answer["reason"] == "invalid bounded native input",
        )
    if captures[0]["trace"]["address_bits"] == 32:
        answer = request(ea, {"args": ["0x100000000"], "objects": []})
        check(
            "architecture width rejection",
            not answer["available"] and answer["reason"] == "argument exceeds architecture width",
        )
    after = inventory()
    check("database unchanged", before == after)
    check(
        "ordinary publications unchanged",
        publication
        == {name: api(f"chernobog_evidence_state({ea})") for name, ea in entries.items()},
    )
except Exception as error:
    errors.append(type(error).__name__)
    errors.extend(f.name + ":" + str(f.lineno) for f in traceback.extract_tb(error.__traceback__))

report = {
    "schema": 1,
    "passed": not errors,
    "checks": checks,
    "errors": errors,
    "inventory_before": before,
    "inventory_after": after,
    "captures": captures,
}
(Path(os.environ["IDAUSR"]).parent / "vm_native_inputs.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][vm-native-input] " + ("FAIL" if errors else "PASS"), flush=True)
ida_pro.qexit(2 if errors else 0)
