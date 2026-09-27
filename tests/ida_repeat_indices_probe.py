"""Owned and read-only ownerless REP index consumers, with revocation controls."""

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
baseline = os.environ.get("CHERNOBOG_REPEAT_INDEX_BASELINE") == "1"
targets = (
    "repeat_movsb_di",
    "repeat_movsw_di",
    "repeat_movsd_di",
    "repeat_movsq_di",
    "repeat_stosb_di",
    "repeat_stosw_di",
    "repeat_stosd_di",
    "repeat_stosq_di",
    "repeat_movsb_si",
    "repeat_movsq_si",
    "repeat_unknown_df_masked",
    "repeat_partial_count_masked",
    "repeat_both_masked",
    "repeat_movs_si_masked",
)
conditions = {
    "repeat_unknown_df_unmasked": None,
    "repeat_partial_count_unmasked": None,
    "repeat_count_nine": None,
    "repeat_unknown_source": None,
    "repeat_stos_preserves_si": True,
    "repeat_zero_index": True,
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
    raise AssertionError("missing fixture symbol: " + name)


def instructions(root):
    result = []
    cursor = root
    for _ in range(64):
        instruction = ida_ua.insn_t()
        assert ida_ua.decode_insn(instruction, cursor) > 0
        result.append(instruction)
        cursor += instruction.size
        if instruction.get_canon_mnem() in ("ret", "retn"):
            return result
    raise AssertionError("fixture lacks bounded RET")


def owned(label, root, target=False, condition=None):
    function = ida_funcs.get_func(root)
    assert function is not None and function.start_ea == root
    assert ida_auto.plan_and_wait(function.start_ea, function.end_ea)
    ida_auto.auto_wait()
    result = api(f"chernobog_native_evidence({root})")
    kind = "stack-transfer" if root in target_roots else "setcc-value"
    rows = [r for r in result["records"] if r["kind"] == kind and r["fresh"] == "true"]
    if kind == "stack-transfer":
        proved = [r for r in rows if r["truth"] == "native-proof"]
        desired = target and not baseline
        check(
            label + " owned target",
            (
                len(proved) == 1
                and proved[0]["target"] == hex(target_ea)
                and proved[0]["target_basis"] == "register-definition"
                if desired
                else not proved
            ),
        )
        edges = sorted(
            {
                hex(x.to)
                for x in idautils.XrefsFrom(instructions(root)[-1].ea)
                if x.iscode and x.user
            }
        )
        result["actual_user_edges"] = edges
        check(label + " owned actual edge", edges == ([hex(target_ea)] if desired else []))
    else:
        check(
            label + " owned condition",
            (
                not rows
                if condition is None
                else len(rows) == 1
                and rows[0]["truth"] == "native-proof"
                and rows[0]["value"] == ("0x1" if condition else "0x0")
            ),
        )
    captures[label] = result
    return rows


def inventory():
    """Whole fixture IDB, including bytes, masks, ownership and publications."""
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
                (int(x.frm), int(x.to), int(x.type), bool(x.iscode), bool(x.user))
                for x in idautils.XrefsFrom(ea)
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
    return {
        "sha256": digest.hexdigest(),
        "heads": heads,
        "references": references,
        "functions": len(functions),
    }


try:
    for key in ("CHERNOBOG_IDA_FLAG_SCAN_DEPTH", "CHERNOBOG_IDA_REGISTER_SCAN_DEPTH"):
        assert int(os.environ.get(key, "0")) == 64
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    activation = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(activation, ida_idaapi.BADADDR, "chernobog_native_analysis()")
    ida_auto.auto_wait()
    target_ea = address("repeat_index_target")
    roots = {name: address(name) for name in (*targets, *conditions)}
    target_roots = {roots[name] for name in targets}
    decoded = {name: instructions(root) for name, root in roots.items()}
    captures["instructions"] = {
        name: [
            {
                "site": hex(i.ea),
                "bytes": ida_bytes.get_bytes(i.ea, i.size).hex(),
                "mnemonic": i.get_canon_mnem(),
                "auxpref": int(i.auxpref),
                "segpref": int(i.segpref),
            }
            for i in items
        ]
        for name, items in decoded.items()
    }
    for name, root in roots.items():
        owned(name, root, name in targets, conditions.get(name))

    root = roots["repeat_movsb_di"]
    prior = captures["repeat_movsb_di"]
    count = next(
        i
        for i in decoded["repeat_movsb_di"]
        if i.get_canon_mnem() == "mov" and i.Op2.type == ida_ua.o_imm and i.Op2.value == 2
    )
    raw = ida_bytes.get_bytes(count.ea, count.size)
    assert raw == bytes.fromhex("b902000000")
    try:
        assert ida_bytes.patch_byte(count.ea + 1, 9)
        stale = api(f"chernobog_native_evidence({root})")
        captures["count_patch_before_reanalysis"] = stale
        old_publications = {r["publication"] for r in prior["records"] if r["fresh"] == "true"}
        check(
            "count patch revokes old publications",
            not any(r.get("publication") in old_publications for r in stale["records"]),
        )
        owned("count_nine_patch", root)
    finally:
        ida_bytes.patch_bytes(count.ea, raw)
    renewed = owned("count_restored", root, True)
    if not baseline:
        check(
            "restored target has new publication",
            len(renewed) == 1 and renewed[0]["publication"] not in old_publications,
        )

    repeat = next(i.ea for i in decoded["repeat_movsb_di"] if i.get_canon_mnem() == "movs")
    external = roots["repeat_unknown_df_unmasked"]
    try:
        assert ida_xref.add_cref(external, repeat, ida_xref.fl_JN | ida_xref.XREF_USER)
        owned("external_entry", root)
    finally:
        ida_xref.del_cref(external, repeat, False)
    owned("external_entry_removed", root, True)

    masked_root = roots["repeat_both_masked"]
    index_mask = next(
        i for i in decoded["repeat_both_masked"] if i.get_canon_mnem() == "and" and i.size == 4
    )
    mask_raw = ida_bytes.get_bytes(index_mask.ea, index_mask.size)
    assert mask_raw == bytes.fromhex("4883e7f0")
    try:
        assert ida_bytes.patch_byte(index_mask.ea + 3, 0xF8)
        owned("insufficient_index_mask", masked_root)
    finally:
        ida_bytes.patch_bytes(index_mask.ea, mask_raw)
    owned("index_mask_restored", masked_root, True)
    check(
        "all fixture patches restored",
        ida_bytes.get_bytes(count.ea, count.size) == raw
        and ida_bytes.get_bytes(index_mask.ea, index_mask.size) == mask_raw,
    )

    for root in roots.values():
        owners = {
            ida_funcs.get_func(i.ea).start_ea
            for i in instructions(root)
            if ida_funcs.get_func(i.ea) is not None
        }
        for owner in sorted(owners):
            assert ida_funcs.del_func(owner)
    for name, root in roots.items():
        before = inventory()
        result = api(f"chernobog_native_region_facts({root})")
        after = inventory()
        captures[name + "_ownerless"] = {
            "facts": result,
            "inventory_before": before,
            "inventory_after": after,
        }
        check(name + " ownerless inventory unchanged", before == after)
        check(
            name + " ownerless bounded converged scope",
            result["schema"] == 1
            and int(result["root"], 0) == root
            and result["available"]
            and result["converged"]
            and not result["truncated"]
            and result["published"] is False
            and result["limits"] == {"nodes": 128, "rounds": 128, "incoming_per_node": 256}
            and all(ida_funcs.get_func(int(n["site"], 0)) is None for n in result["nodes"]),
        )
        kind = "push-return" if name in targets else "setcc-value"
        if name in targets:
            site = next(i.ea for i in decoded[name] if i.get_canon_mnem() == "push")
        else:
            site = next(i.ea for i in decoded[name] if i.get_canon_mnem().startswith("set"))
        rows = [r for r in result["records"] if r["kind"] == kind and int(r["site"], 0) == site]
        expected = not baseline if name in targets else conditions[name]
        support = ";".join(n["site"] for n in result["nodes"])
        check(
            name + " ownerless exact consumer and support",
            len(rows) == 1
            and rows[0]["truth"] == "static-region-fact"
            and rows[0]["support"] == support
            and rows[0]["status"] == ("proved" if expected else "unresolved")
            and (
                rows[0]["target"] == (hex(target_ea) if expected else "unknown")
                if name in targets
                else rows[0]["value"] == ("0x1" if expected else "unknown")
            ),
        )
except BaseException as error:
    errors.append(type(error).__name__)
    frames, trace = [], error.__traceback__
    while trace:
        frames.append({"function": trace.tb_frame.f_code.co_name, "line": trace.tb_lineno})
        trace = trace.tb_next
    captures["exception"] = {"type": type(error).__name__, "frames": frames}

(Path(os.environ["IDAUSR"]).parent / "repeat_indices.json").write_text(
    json.dumps(
        {"baseline": baseline, "checks": checks, "errors": errors, "captures": captures}, indent=2
    )
    + "\n"
)
print("[chernobog][repeat-indices] " + ("FAIL" if errors else "PASS"), flush=True)
ida_pro.qexit(2 if errors else 0)
