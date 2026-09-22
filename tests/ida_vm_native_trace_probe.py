"""Production native-region captures with independent stack-prefix checks."""

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
import ida_kernwin
import ida_loader
import ida_pro
import ida_segment
import ida_xref
import idautils

sys.dont_write_bytecode = True
checks, errors, captures = [], [], {}


def check(name, value):
    checks.append({"case": name, "passed": bool(value)})
    if not value:
        errors.append(name)


def api(expression):
    result = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression)
    return json.loads(result.c_str())


def inventory():
    h = hashlib.sha256()
    total_bytes, heads, xrefs = 0, 0, 0
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        length = int(seg.end_ea - seg.start_ea)
        total_bytes += length
        assert total_bytes <= 64 * 1024 * 1024
        h.update(
            str((int(seg.start_ea), int(seg.end_ea), int(seg.bitness), int(seg.perm))).encode()
        )
        data = ida_bytes.get_bytes_and_mask(seg.start_ea, length)
        if data is None:
            h.update(b"unloaded")
        else:
            for part in data:
                h.update(part)
        for ea in idautils.Heads(seg.start_ea, seg.end_ea):
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
                xrefs += 1
                assert xrefs <= 2097152
                h.update(str((int(x.frm), int(x.to), int(x.type), bool(x.iscode))).encode())
                ok = x.next_from()
    functions = list(idautils.Functions())
    assert len(functions) <= 4096
    for ea in functions:
        f = ida_funcs.get_func(ea)
        h.update(str((ea, int(f.end_ea), int(f.flags), list(idautils.Chunks(ea)))).encode())
    return {
        "sha256": h.hexdigest(),
        "bytes": total_bytes,
        "heads": heads,
        "xrefs": xrefs,
        "functions": len(functions),
    }


def prefix_oracle(trace):
    path = trace["execution"]
    if len(path) < 3:
        return False
    sites = [int(row["site"], 0) for row in path[:3]]
    raw = [ida_bytes.get_bytes(ea, int(row["size"])) for ea, row in zip(sites, path)]
    if not (
        len(raw[0]) == len(raw[1]) == len(raw[2]) == 5
        and raw[0][0] == 0xE9
        and raw[1][0] == 0x68
        and raw[2][0] == 0xE8
    ):
        return False
    mode, sp = trace["address_bits"], int(trace["entry_sp"], 0)
    width, mask = mode // 8, (1 << mode) - 1
    immediate = struct.unpack("<i", raw[1][1:])[0] & mask
    call_target = (sites[2] + 5 + struct.unpack("<i", raw[2][1:])[0]) & mask
    expected = [(sites[1], sp - width, immediate), (sites[2], sp - 2 * width, sites[2] + 5)]
    for site, address, value in expected:
        writes = [a for a in trace["data"] if a["kind"] == "write" and int(a["site"], 0) == site]
        check(
            "protected prefix exact stack write",
            len(writes) == 1
            and int(writes[0]["address"], 0) == address
            and int(writes[0]["size"]) == width
            and int(writes[0]["value"], 0) == value,
        )
    samples = [
        s
        for s in trace["states"]
        if s["kind"] == "transfer target"
        and int(s["site"], 0) == call_target
        and int(s["source"], 0) == sites[2]
    ]
    check("protected prefix callee state retained", len(samples) == 1)
    if samples:
        registers = [
            tuple(int(v, 0) for v in r.split(":")) for r in samples[0]["registers"].split(";")
        ]
        sp_register = 0x104 if mode == 64 else 0x204
        check(
            "protected prefix callee stack state",
            any(
                r == sp_register and w == width and value == sp - 2 * width
                for r, w, value in registers
            ),
        )
    return True


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
    captures["inventory_before"] = inventory()
    publication_expression = f"chernobog_evidence_state({next(iter(entries.values()))})"
    publication = api(publication_expression)
    for name, ea in entries.items():
        for seed in (0, 1, 12648430):
            trace = api(f"chernobog_vm_trace({ea}, {seed})")
            label = name + ":" + str(seed)
            captures[label] = trace
            check(label + " capture runs", trace.get("available") and trace.get("ran"))
            if not trace.get("available"):
                continue
            check(
                label + " separate scope",
                trace["scope"] == "native-region"
                and not trace["function_evidence_published"]
                and not trace["vm_identity_proved"],
            )
            check(
                label + " bounds",
                trace["planned_heads"] <= 4096
                and len(trace["execution"]) <= 4096
                and len(trace["data"]) <= 4096
                and len(trace["states"]) <= 4096,
            )
            heads = {int(h["site"], 0): h for h in trace["heads"]}
            check(
                label + " executed bytes retain exact plan",
                all(
                    int(e["site"], 0) in heads
                    and heads[int(e["site"], 0)]["bytes"]
                    == ida_bytes.get_bytes(int(e["site"], 0), int(e["size"])).hex()
                    for e in trace["execution"]
                ),
            )
            successors = [
                (int(a["site"], 0), int(b["site"], 0))
                for a, b in zip(trace["execution"], trace["execution"][1:])
            ]
            if trace["region_boundary"]:
                successors.append(
                    (int(trace["boundary_source"], 0), int(trace["boundary_target"], 0))
                )
            check(
                label + " planned linear sizes agree with execution",
                all(
                    int(heads[a]["flow"]) != 0 or b == a + int(heads[a]["size"])
                    for a, b in successors
                    if a in heads
                ),
            )
            trace["prefix_oracle_applicable"] = prefix_oracle(trace)
            if os.environ.get("CHERNOBOG_EXPECT_VM_ENTRY") == "1":
                check(
                    label + " source-emitted VM entry exercised", trace["prefix_oracle_applicable"]
                )
            check(
                label + " seeded entry state",
                trace["states"] and trace["states"][0]["kind"] == "seeded entry",
            )
    captures["inventory_after"] = inventory()
    check("native database unchanged", captures["inventory_before"] == captures["inventory_after"])
    check("ordinary evidence publication unchanged", publication == api(publication_expression))
except Exception as error:
    errors.append(type(error).__name__)
    captures["exception_frames"] = [
        {"function": f.name, "line": f.lineno} for f in traceback.extract_tb(error.__traceback__)
    ]

report = {
    "schema": 1,
    "passed": not errors,
    "checks": checks,
    "errors": errors,
    "captures": captures,
}
(Path(os.environ["IDAUSR"]).parent / "vm_native_traces.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
line = "[chernobog][vm-native-trace] " + ("FAIL" if errors else "PASS")
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
