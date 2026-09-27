"""Production owned/ownerless DF facts and opcode/count/topology invalidation."""

import hashlib
import json
import os
from pathlib import Path
import sys

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
checks, errors, captures = [], [], {}
baseline = os.environ.get("CHERNOBOG_DIRECTION_BASELINE") == "1"
cases = {
    "direction_forward": True,
    "direction_reverse": False,
    "direction_saved_forward": True,
    "direction_saved_reverse": False,
    "direction_literal_reverse": False,
    "direction_unknown_pop": None,
    "direction_unknown": None,
    "direction_prefixed": None,
    "direction_join_equal": True,
    "direction_join_conflict": None,
    "direction_stos_forward": True,
    "direction_stos_reverse": False,
}


def check(name, passed):
    checks.append({"case": name, "passed": bool(passed)})
    if not passed:
        errors.append(name)


def api(expression):
    result = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression)
    return json.loads(result.c_str())


def address(name):
    for candidate in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return int(ea)
    raise AssertionError("missing symbol: " + name)


def instructions(root):
    function = ida_funcs.get_func(root)
    assert function is not None
    result = []
    for ea in idautils.FuncItems(root):
        instruction = ida_ua.insn_t()
        assert ida_ua.decode_insn(instruction, ea) > 0
        result.append(instruction)
    return result


def owned(label, root, expected):
    function = ida_funcs.get_func(root)
    assert function is not None
    assert ida_auto.plan_and_wait(function.start_ea, function.end_ea)
    ida_auto.auto_wait()
    result = api(f"chernobog_native_evidence({root})")
    captures[label] = result
    rows = [r for r in result["records"] if r["kind"] == "setcc-value" and r["fresh"] == "true"]
    expected = None if baseline else expected
    check(
        label + " owned condition",
        (
            not rows
            if expected is None
            else len(rows) == 1
            and rows[0]["truth"] == "native-proof"
            and rows[0]["value"] == ("0x1" if expected else "0x0")
        ),
    )
    return rows


def inventory():
    """Whole small-fixture IDB: bytes/masks, heads, owners, refs, comments, names."""
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
        add(
            (
                ea,
                int(function.flags),
                list(idautils.Chunks(ea)),
                ida_funcs.get_func_cmt(function, True),
                ida_funcs.get_func_cmt(function, False),
            )
        )
    add(list(idautils.Names()))
    return {"sha256": digest.hexdigest(), "heads": heads, "references": references}


try:
    assert int(os.environ.get("CHERNOBOG_IDA_FLAG_SCAN_DEPTH", "8")) == 64
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    activation = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(activation, ida_idaapi.BADADDR, "chernobog_native_analysis()")
    ida_auto.auto_wait()
    roots = {name: address(name) for name in cases}
    sites = {}
    decoded = {}
    for name, root in roots.items():
        decoded[name] = instructions(root)
        captures[name + "_instructions"] = [
            {
                "site": hex(i.ea),
                "bytes": ida_bytes.get_bytes(i.ea, i.size).hex(),
                "mnemonic": i.get_canon_mnem(),
                "auxpref": int(i.auxpref),
                "segpref": int(i.segpref),
                "operands": [
                    {
                        "type": int(o.type),
                        "dtype": int(o.dtype),
                        "reg": int(o.reg),
                        "addr": int(o.addr),
                    }
                    for o in (i.Op1, i.Op2)
                ],
            }
            for i in decoded[name]
        ]
        sites[name] = next(i.ea for i in decoded[name] if i.get_canon_mnem().startswith("set"))
        owned(name, root, cases[name])

    root = roots["direction_forward"]
    definition = decoded["direction_forward"][0].ea
    assert ida_bytes.get_bytes(definition, 1) == b"\xfc"
    original = captures["direction_forward"]
    try:
        assert ida_bytes.patch_byte(definition, 0xFD)
        stale = api(f"chernobog_native_evidence({root})")
        captures["opcode_patch_before_reanalysis"] = stale
        check(
            "DF opcode patch revokes original publication",
            not any(
                r["kind"] == "setcc-value" and r["fresh"] == "true" and r["value"] == "0x1"
                for r in stale["records"]
            ),
        )
        owned("opcode_patch_reverse", root, False)
    finally:
        ida_bytes.patch_byte(definition, 0xFC)
    renewed = owned("opcode_restored", root, True)
    check("DF definition byte restored", ida_bytes.get_bytes(definition, 1) == b"\xfc")
    if not baseline:
        prior = [
            r for r in original["records"] if r["kind"] == "setcc-value" and r["fresh"] == "true"
        ]
        check(
            "DF restoration creates a new publication",
            len(renewed) == len(prior) == 1
            and renewed[0]["publication"] != prior[0]["publication"],
        )

    count = next(
        i
        for i in decoded["direction_forward"]
        if i.get_canon_mnem() == "mov" and i.Op2.type == ida_ua.o_imm and i.Op2.value == 2
    )
    raw = ida_bytes.get_bytes(count.ea, count.size)
    assert raw == bytes.fromhex("b902000000")
    try:
        assert ida_bytes.patch_byte(count.ea + 1, 9)
        owned("count_nine", root, None)
    finally:
        ida_bytes.patch_bytes(count.ea, raw)
    owned("count_restored", root, True)

    repeat = next(i.ea for i in decoded["direction_forward"] if i.get_canon_mnem() == "movs")
    external = roots["direction_unknown"]
    try:
        assert ida_xref.add_cref(external, repeat, ida_xref.fl_JN | ida_xref.XREF_USER)
        owned("external_entry", root, None)
    finally:
        ida_xref.del_cref(external, repeat, False)
    owned("external_entry_removed", root, True)

    for root in roots.values():
        assert ida_funcs.del_func(root)
    for name, root in roots.items():
        before = inventory()
        result = api(f"chernobog_native_region_facts({root})")
        after = inventory()
        captures[name + "_ownerless"] = {
            "facts": result,
            "inventory_before": before,
            "inventory_after": after,
        }
        expected = None if baseline else cases[name]
        rows = [
            r
            for r in result["records"]
            if r["kind"] == "setcc-value" and int(r["site"], 0) == sites[name]
        ]
        check(name + " ownerless inventory unchanged", before == after)
        check(
            name + " ownerless converged bounded scope",
            result["schema"] == 1
            and int(result["root"], 0) == root
            and result["available"]
            and result["converged"]
            and not result["truncated"]
            and result["published"] is False
            and result["limits"] == {"nodes": 128, "rounds": 128, "incoming_per_node": 256}
            and all(ida_funcs.get_func(int(n["site"], 0)) is None for n in result["nodes"]),
        )
        support = ";".join(n["site"] for n in result["nodes"])
        check(
            name + " ownerless condition and support",
            len(rows) == 1
            and rows[0]["truth"] == "static-region-fact"
            and rows[0]["support"] == support
            and rows[0]["status"] == ("unresolved" if expected is None else "proved")
            and rows[0]["value"]
            == ("unknown" if expected is None else "0x1" if expected else "0x0"),
        )
except BaseException as error:
    errors.append(type(error).__name__)
    frames, trace = [], error.__traceback__
    while trace:
        frames.append({"function": trace.tb_frame.f_code.co_name, "line": trace.tb_lineno})
        trace = trace.tb_next
    captures["exception"] = {"type": type(error).__name__, "frames": frames}

(Path(os.environ["IDAUSR"]).parent / "direction.json").write_text(
    json.dumps(
        {"baseline": baseline, "checks": checks, "errors": errors, "captures": captures}, indent=2
    )
    + "\n"
)
print("[chernobog][direction] " + ("FAIL" if errors else "PASS"), flush=True)
ida_pro.qexit(2 if errors else 0)
