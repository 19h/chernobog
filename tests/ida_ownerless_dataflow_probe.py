"""Read-only ownerless direct-CFG facts against independently executed fixtures."""

import hashlib
import json
import os
from pathlib import Path
import sys
import traceback

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_ida
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
ordinary = None


def check(name, value):
    checks.append({"case": name, "passed": bool(value)})
    if not value:
        errors.append(name)


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def symbol(name):
    for candidate in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return int(ea)
    raise AssertionError("fixture symbol missing: " + name)


def api(expression):
    result = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression)
    return json.loads(result.c_str())


def inventory():
    """Whole-IDB byte/head/owner/reference/comment identity, without host paths."""
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
    return {
        "sha256": digest.hexdigest(),
        "heads": heads,
        "references": references,
        "functions": len(functions),
    }


def inspect(name, root):
    if ordinary:
        # Fixture topology edits deliberately revoke all ordinary publications.
        # Refresh only this owned control before the read-only comparison.
        function = ida_funcs.get_func(ordinary)
        assert function is not None
        assert ida_auto.plan_and_wait(function.start_ea, function.end_ea)
    published_before = api(f"chernobog_native_evidence({ordinary})") if ordinary else None
    check(
        name + " fresh ordinary publication control",
        published_before is None
        or any(
            row["fresh"] == "true" and row["kind"] == "setcc-value"
            for row in published_before["records"]
        ),
    )
    before = inventory()
    result = api(f"chernobog_native_region_facts({root})")
    after = inventory()
    check(name + " read-only IDB inventory", before == after)
    published_after = api(f"chernobog_native_evidence({ordinary})") if ordinary else None
    check(name + " preserves ordinary publications", published_before == published_after)
    check(
        name + " schema and explicit root", result["schema"] == 1 and number(result["root"]) == root
    )
    check(
        name + " explicit bounded unpublished scope",
        result["limits"] == {"nodes": 128, "rounds": 128, "incoming_per_node": 256}
        and result["published"] is False
        and "selected ownerless root" in result["scope"]
        and "no whole-program reachability" in result["scope"],
    )
    sites = [number(node["site"]) for node in result["nodes"]]
    check(name + " bounded unique sorted nodes", sites == sorted(set(sites)) and len(sites) <= 128)
    check(
        name + " all admitted nodes remain ownerless",
        all(ida_funcs.get_func(site) is None for site in sites),
    )
    expected_support = ";".join(hex(site) for site in sites)
    check(
        name + " exact static support attribution",
        all(
            row["truth"] == "static-region-fact" and row["support"] == expected_support
            for row in result["records"]
        ),
    )
    captures[name] = {
        "facts": result,
        "inventory_before": before,
        "inventory_after": after,
        "ordinary_before": published_before,
        "ordinary_after": published_after,
    }
    return result


def row_at(result, site, kind="setcc-value"):
    rows = [row for row in result["records"] if number(row["site"]) == site and row["kind"] == kind]
    assert len(rows) == 1
    return rows[0]


def condition(name, result, site, expected):
    row = row_at(result, site)
    check(
        name + " converged", result["available"] and result["converged"] and not result["truncated"]
    )
    check(
        name + " condition",
        row["status"] == ("unresolved" if expected is None else "proved")
        and row["outcome"] == ("unknown" if expected is None else "true" if expected else "false")
        and row["value"] == ("unknown" if expected is None else "0x1" if expected else "0x0"),
    )


def remove_owners(first, end):
    owners = {
        int(function.start_ea)
        for ea in range(first, end)
        if (function := ida_funcs.get_func(ea)) is not None
    }
    for ea in sorted(owners):
        assert ida_funcs.del_func(ea)


def decode_span(first, end):
    cursor, instructions = first, []
    while cursor < end:
        assert ida_ua.create_insn(cursor) > 0
        instruction = ida_ua.insn_t()
        assert ida_ua.decode_insn(instruction, cursor) > 0
        assert cursor + instruction.size <= end
        instructions.append(instruction)
        cursor += instruction.size
    assert cursor == end
    return instructions


def data_span(first, size, expected=None):
    if expected is not None:
        assert ida_bytes.get_bytes(first, size) == expected
    assert ida_bytes.del_items(first, ida_bytes.DELIT_SIMPLE, size)
    assert ida_bytes.create_data(first, ida_bytes.FF_BYTE, size, ida_idaapi.BADADDR)


def prepare_diamond(name, offset=0):
    labels = {
        suffix: symbol(name + suffix) + offset
        for suffix in (
            "",
            "_branch",
            "_root_end",
            "_left",
            "_left_end",
            "_right",
            "_right_end",
            "_join",
            "_end",
        )
    }
    remove_owners(labels[""], labels["_end"] + 3)
    for suffix in ("_root_end", "_left_end", "_right_end", "_end"):
        data_span(labels[suffix], 3, b"\xcc" * 3)
    instructions = []
    for first, end in (
        ("", "_root_end"),
        ("_left", "_left_end"),
        ("_right", "_right_end"),
        ("_join", "_end"),
    ):
        instructions.extend(decode_span(labels[first], labels[end]))
    assert all(ida_funcs.get_func(instruction.ea) is None for instruction in instructions)
    return labels, instructions


def prepare_prefix(name):
    """Existing loop/target fixture ends at its first architectural RET."""
    first = cursor = symbol(name)
    instructions = []
    for _ in range(64):
        instruction = ida_ua.insn_t()
        assert ida_ua.decode_insn(instruction, cursor) > 0
        instructions.append(instruction)
        cursor += instruction.size
        if instruction.get_canon_mnem() in ("ret", "retn"):
            break
    else:
        raise AssertionError("fixture prefix lacks bounded RET")
    remove_owners(first, cursor)
    return first, decode_span(first, cursor)


def mutation_controls(labels, baseline):
    root, join, left = labels[""], labels["_join"], labels["_left"]
    source = symbol("df_external")
    assert ida_xref.add_cref(source, join, ida_xref.fl_JN | ida_xref.XREF_USER)
    changed = inspect("external_join_entry", root)
    condition("external join entry", changed, join, None)
    check(
        "external join is an explicit unknown entry",
        next(node for node in changed["nodes"] if number(node["site"]) == join)["unknown_entry"]
        == "true",
    )
    ida_xref.del_cref(source, join, False)
    assert not any(ref.frm == source and ref.iscode for ref in idautils.XrefsTo(join))
    restored = inspect("external_join_restored", root)
    condition("external join restored", restored, join, True)

    branch = ida_ua.insn_t()
    assert ida_ua.decode_insn(branch, labels["_branch"]) > 0
    outgoing = [(int(ref.to), int(ref.type)) for ref in idautils.XrefsFrom(branch.ea) if ref.iscode]
    for target, _ in outgoing:
        ida_xref.del_cref(branch.ea, target, False)
    assert not any(ref.iscode for ref in idautils.XrefsFrom(branch.ea))
    pruned = inspect("pruned_branch_references", root)
    condition("pruned references", pruned, join, True)
    targets = {
        number(edge["target"])
        for edge in pruned["edges"]
        if number(edge["source"]) == branch.ea and edge["kind"] != "frontier"
    }
    check(
        "both Jcc successors reconstructed from bytes",
        targets == {int(branch.Op1.addr), branch.ea + branch.size},
    )
    check(
        "pruned graph keeps all nodes",
        pruned["nodes"] and len(pruned["nodes"]) == len(baseline["nodes"]),
    )
    for target, kind in outgoing:
        assert ida_xref.add_cref(branch.ea, target, kind)
    condition("pruned references restored", inspect("branch_references_restored", root), join, True)

    assert ida_bytes.get_byte(left) == 0xF9
    ida_bytes.patch_byte(left, 0xF8)
    condition("changed defining byte", inspect("changed_defining_byte", root), join, None)
    ida_bytes.patch_byte(left, 0xF9)
    condition("defining byte restored", inspect("defining_byte_restored", root), join, True)

    assert ida_funcs.add_func(root, labels["_root_end"])
    owned = inspect("root_became_owned", root)
    check(
        "owned root is unavailable",
        not owned["available"] and owned["reason"] == "owned_code" and not owned["records"],
    )
    assert ida_funcs.del_func(root)
    condition("root ownership restored", inspect("root_ownerless_restored", root), join, True)

    assert branch.size > 1
    assert ida_xref.add_cref(source, branch.ea + 1, ida_xref.fl_JN | ida_xref.XREF_USER)
    interior = inspect("interior_entry", root)
    check(
        "interior entry refuses every fact",
        not interior["converged"]
        and interior["reason"] == "interior_code_entry"
        and not interior["records"],
    )
    ida_xref.del_cref(source, branch.ea + 1, False)
    assert not any(ref.frm == source and ref.iscode for ref in idautils.XrefsTo(branch.ea + 1))
    condition("interior entry restored", inspect("interior_entry_restored", root), join, True)


def metadata_controls(labels):
    """Exact-source byte projection; this new IDB address is not native-executed."""
    first, end = labels[""], labels["_end"] + 3
    raw = ida_bytes.get_bytes(first, end - first)
    base = (
        max(ida_segment.getnseg(i).end_ea for i in range(ida_segment.get_segm_qty())) + 0xFFFF
    ) & ~0xFFFF
    assert ida_segment.add_segm(0, base, base + 0x1000, "ownerless_metadata_projection", "CODE")
    segment = ida_segment.getseg(base)
    original_mode = ida_segment.getseg(first).bitness
    segment.perm, segment.bitness = 5, original_mode
    assert ida_segment.update_segm(segment)
    ida_bytes.put_bytes(base, raw)
    projected, _ = prepare_diamond("od_equal", base - first)
    captures["metadata_projection_identity"] = {
        "scope": "Exact native-fixture bytes copied to an IDB-only position-independent segment; no native execution at this address",
        "source": hex(first),
        "copy": hex(base),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    condition("metadata projection", inspect("metadata_projection", base), projected["_join"], True)
    segment.perm = ida_segment.SEGPERM_READ
    assert ida_segment.update_segm(segment)
    removed = inspect("projection_nonexecutable", base)
    check(
        "nonexecutable root rejected",
        not removed["available"]
        and not removed["records"]
        and removed["reason"] == "nonexecutable_or_external",
    )
    segment.perm = 5
    assert ida_segment.update_segm(segment)
    condition(
        "permissions restored",
        inspect("projection_permissions_restored", base),
        projected["_join"],
        True,
    )
    segment.bitness = 0
    assert ida_segment.update_segm(segment)
    changed = inspect("projection_16_bit_mode", base)
    check(
        "unsupported mode rejected",
        not changed["available"]
        and not changed["records"]
        and changed["reason"] == "unsupported_mode",
    )
    segment.bitness = original_mode
    assert ida_segment.update_segm(segment)
    condition("mode restored", inspect("projection_mode_restored", base), projected["_join"], True)
    check(
        "metadata mutations preserve exact projected bytes",
        ida_bytes.get_bytes(base, len(raw)) == raw,
    )


def focused_main():
    try:
        assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
        ida_auto.auto_wait()
        value = ida_expr.idc_value_t()
        assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, "chernobog_native_analysis()")
        ida_auto.auto_wait()
        ida_auto.enable_auto(False)
        movs_only = os.environ.get("CHERNOBOG_MOVS_ONLY") == "1"
        gain = (
            os.environ.get("CHERNOBOG_MOVS_BASELINE" if movs_only else "CHERNOBOG_ALU_BASELINE")
            != "1"
        )
        cmps_proofs = os.environ.get("CHERNOBOG_CMPS_BASELINE") != "1" and ida_ida.inf_is_64bit()
        fixtures = (
            (
                ("df_rep_movs_cf", "condition"),
                ("df_rep_movs_zf", "condition"),
                ("df_movs_plain_cf", "condition"),
                ("df_cmps_flags_changed", "condition-unknown"),
                ("df_rep_movs_alias", "unresolved"),
                ("df_rep_movs_register_target", "register-definition"),
                ("df_movs_plain_count_target", "register-definition"),
                ("df_rep_movs_count_unknown", "register-definition"),
            )
            if movs_only
            else (
                ("df_memory_alu_add", "memory-definition"),
                ("df_memory_alu_xor_byte", "memory-definition"),
                ("df_memory_alu_source", "register-definition"),
                ("df_memory_alu_initial", "unresolved"),
                ("df_memory_alu_alias", "unresolved"),
                ("df_memory_alu_compare", "condition"),
                ("df_memory_alu_rmw_initial", "unresolved"),
                ("df_memory_alu_rmw_alias", "unresolved"),
                ("df_memory_alu_compare_initial", "condition-initial"),
                ("df_memory_alu_flags", "condition"),
                ("df_memory_alu_flags_initial", "condition-initial"),
            )
        )
        for name, basis in fixtures:
            root, instructions = prepare_prefix(name)
            before = inventory()
            result = api(f"chernobog_native_region_facts({root})")
            after = inventory()
            check(name + " read-only IDB inventory", before == after)
            check(name + " converged", result["available"] and result["converged"])
            if basis.startswith("condition"):
                site = next(
                    instruction.ea
                    for instruction in instructions
                    if instruction.get_canon_mnem().startswith("set")
                )
                if name == "df_cmps_flags_changed":
                    expected = False if cmps_proofs else None
                else:
                    expected = True if gain and basis == "condition" else None
                condition(name, result, site, expected)
            else:
                site = next(
                    instruction.ea
                    for instruction in reversed(instructions)
                    if instruction.get_canon_mnem() == "push"
                )
                row = row_at(result, site, "push-return")
                proved = (
                    gain
                    and basis != "unresolved"
                    and (
                        name != "df_rep_movs_count_unknown"
                        or os.environ.get("CHERNOBOG_REP_COUNT_BASELINE") != "1"
                    )
                )
                check(
                    name + " target status",
                    row["status"] == ("proved" if proved else "unresolved")
                    and row["target_proof"] == (basis if proved else "unresolved")
                    and row["target"] == (hex(symbol("df_memory_target")) if proved else "unknown"),
                )
            captures[name] = {"facts": result, "inventory_before": before, "inventory_after": after}
    except BaseException as error:
        errors.append(type(error).__name__)
        captures["exception"] = {
            "type": type(error).__name__,
            "frames": [
                {"function": frame.name, "line": frame.lineno}
                for frame in traceback.extract_tb(error.__traceback__)
            ],
        }
    (Path(os.environ["IDAUSR"]).parent / "ownerless_dataflow.json").write_text(
        json.dumps({"checks": checks, "errors": errors, "captures": captures}, indent=2) + "\n"
    )
    print("[chernobog][ownerless-dataflow] " + ("FAIL" if errors else "PASS"), flush=True)
    return 2 if errors else 0


def main():
    if os.environ.get("CHERNOBOG_ALU_ONLY") == "1" or os.environ.get("CHERNOBOG_MOVS_ONLY") == "1":
        return focused_main()
    global ordinary
    try:
        assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
        ida_auto.auto_wait()
        alu_proofs = os.environ.get("CHERNOBOG_ALU_BASELINE") != "1"
        movs_proofs = os.environ.get("CHERNOBOG_MOVS_BASELINE") != "1"
        rep_count_proofs = os.environ.get("CHERNOBOG_REP_COUNT_BASELINE") != "1"
        string_io_proofs = os.environ.get("CHERNOBOG_STRING_IO_BASELINE") != "1"
        string_count_proofs = os.environ.get("CHERNOBOG_STRING_COUNT_BASELINE") != "1"
        scas_proofs = os.environ.get("CHERNOBOG_SCAS_BASELINE") != "1" and ida_ida.inf_is_64bit()
        cmps_proofs = os.environ.get("CHERNOBOG_CMPS_BASELINE") != "1" and ida_ida.inf_is_64bit()
        stos_local_proofs = (
            os.environ.get("CHERNOBOG_STOS_LOCAL_BASELINE") != "1" and ida_ida.inf_is_64bit()
        )
        movs_local_proofs = (
            os.environ.get("CHERNOBOG_MOVS_LOCAL_BASELINE") != "1" and ida_ida.inf_is_64bit()
        )
        rep_movs_zero_proofs = os.environ.get("CHERNOBOG_REP_MOVS_LOCAL_BASELINE") != "1"
        rep_movs_one_proofs = rep_movs_zero_proofs and ida_ida.inf_is_64bit()
        rep_compare_zero_proofs = os.environ.get("CHERNOBOG_REP_COMPARE_LOCAL_BASELINE") != "1"
        rep_compare_one_proofs = rep_compare_zero_proofs and ida_ida.inf_is_64bit()
        lods_local_proofs = (
            os.environ.get("CHERNOBOG_LODS_LOCAL_BASELINE") != "1" and ida_ida.inf_is_64bit()
        )
        value = ida_expr.idc_value_t()
        assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, "chernobog_native_analysis()")
        ida_auto.auto_wait()
        ida_auto.enable_auto(False)
        ordinary = symbol("df_equal")
        owned_before = api(f"chernobog_native_evidence({ordinary})")
        check(
            "ordinary control has a fresh publication",
            any(
                row["fresh"] == "true" and row["kind"] == "setcc-value"
                for row in owned_before["records"]
            ),
        )
        configurations = {}
        for name, nodes in (
            ("od_equal", 11),
            ("od_conflict", 11),
            ("od_budget64", 64),
            ("od_budget65", 65),
            ("od_budget128", 128),
            ("od_budget129", 129),
        ):
            labels, decoded = prepare_diamond(name)
            check(name + " independent decoded instruction count", len(decoded) == nodes)
            configurations[name] = labels
        baseline = inspect("equal_diamond", configurations["od_equal"][""])
        condition("equal diamond", baseline, configurations["od_equal"]["_join"], True)
        condition(
            "conflicting diamond",
            inspect("conflicting_diamond", configurations["od_conflict"][""]),
            configurations["od_conflict"]["_join"],
            None,
        )
        condition(
            "exact 64-node budget",
            inspect("exact_node_budget", configurations["od_budget64"][""]),
            configurations["od_budget64"]["_join"],
            True,
        )
        condition(
            "admitted 65-node graph",
            inspect("admitted_65_nodes", configurations["od_budget65"][""]),
            configurations["od_budget65"]["_join"],
            True,
        )
        condition(
            "exact 128-node budget",
            inspect("exact_128_nodes", configurations["od_budget128"][""]),
            configurations["od_budget128"]["_join"],
            True,
        )
        excess = inspect("exceeded_node_budget", configurations["od_budget129"][""])
        check(
            "129-node graph yields no partial facts",
            excess["available"]
            and not excess["converged"]
            and excess["truncated"]
            and excess["reason"] == "node_limit"
            and len(excess["nodes"]) == 128
            and not excess["records"],
        )

        for name in ("od_cld", "od_std"):
            root, instructions = prepare_prefix(name)
            site = next(
                instruction.ea
                for instruction in instructions
                if instruction.get_canon_mnem().startswith("set")
            )
            condition(name + " preserves arithmetic flags", inspect(name, root), site, True)

        for name, expected in (
            ("df_flags_saved", True),
            ("df_flags_full", True),
            ("df_flags_literal", True),
            ("df_flags_overwrite", None),
            ("df_flags_dynamic", None),
            ("df_sahf_cf", True),
            ("df_sahf_of", True),
            ("df_lahf_roundtrip", True),
            ("df_sahf_dynamic", None),
            ("df_lahf_constant", True),
        ):
            root, instructions = prepare_prefix(name)
            site = next(
                instruction.ea
                for instruction in instructions
                if instruction.get_canon_mnem().startswith("set")
            )
            condition(name + " ownerless status flags", inspect(name, root), site, expected)

        condition_cases = (
            ("df_memory_movsx_negative", True),
            ("df_memory_movsx_initial_negative", None),
            ("df_memory_movsxd_negative", True),
            ("df_memory_movsxd_initial_negative", None),
            ("df_memory_movsx_word_negative", True),
            ("df_memory_movsx_initial_word_negative", None),
            ("df_memory_alu_compare", True if alu_proofs else None),
            ("df_memory_alu_compare_initial", None),
            ("df_memory_alu_flags", True if alu_proofs else None),
            ("df_memory_alu_flags_initial", None),
            ("df_rep_movs_cf", True if movs_proofs else None),
            ("df_rep_movs_zf", True if movs_proofs else None),
            ("df_movs_plain_cf", True if movs_proofs else None),
            ("df_cmps_flags_changed", False if cmps_proofs else None),
            ("df_cmps_same_zf", True if cmps_proofs else None),
            ("df_cmps_local_cf_true", True if cmps_proofs else None),
            ("df_cmps_local_cf_false", False if cmps_proofs else None),
            ("df_cmps_word_cf", True if cmps_proofs else None),
            ("df_cmps_dword_zf", True if cmps_proofs else None),
            ("df_cmps_initial_unknown", None),
            ("df_rep_cmps_count_ambiguity", None),
            ("df_repe_cmps_zero_preserve", True if rep_compare_zero_proofs else None),
            ("df_repne_cmps_one_cf", True if rep_compare_one_proofs else None),
            ("df_repe_cmps_one_zf", True if rep_compare_one_proofs else None),
            ("df_repne_cmps_two_early_stop", None),
            ("df_rep_stos_cf", True if string_io_proofs else None),
            ("df_lods_plain_cf", True if string_io_proofs else None),
            ("df_rep_lods_zf", True if string_io_proofs else None),
            ("df_scas_flags_changed", False if scas_proofs else None),
            ("df_scas_cf_true", True if scas_proofs else None),
            ("df_scas_zf_true", True if scas_proofs else None),
            ("df_scas_word_cf", True if scas_proofs else None),
            ("df_scas_dword_zf", True if scas_proofs else None),
            ("df_scas_initial_cf", None),
            ("df_rep_scas_count_ambiguity", None),
            ("df_repne_scas_zero_preserve", True if rep_compare_zero_proofs else None),
            ("df_repe_scas_one_cf", True if rep_compare_one_proofs else None),
            ("df_repne_scas_one_zf", True if rep_compare_one_proofs else None),
            ("df_repe_scas_two_early_stop", None),
            ("df_stos_byte_reload", True if stos_local_proofs else None),
            ("df_stos_word_reload", True if stos_local_proofs else None),
            ("df_stos_dword_reload", True if stos_local_proofs else None),
            ("df_stos_unknown_overlap_condition", None),
            ("df_movs_byte_reload", True if movs_local_proofs else None),
            ("df_movs_overlap_word_reload", True if movs_local_proofs else None),
            ("df_movs_dword_reload", True if movs_local_proofs else None),
            ("df_movs_initial_source_unknown", None),
            ("df_rep_movs_zero_preserve", True if rep_movs_zero_proofs else None),
            ("df_rep_movs_one_reload", True if rep_movs_one_proofs else None),
            ("df_lods_byte_value", True if lods_local_proofs else None),
            ("df_lods_word_value", True if lods_local_proofs else None),
            ("df_lods_dword_value", True if lods_local_proofs else None),
            ("df_lods_unknown_source_value", None),
            ("df_rep_lods_ambiguous_value", None),
            ("df_lods_unknown_source_high_value", True if lods_local_proofs else None),
        )
        if ida_ida.inf_is_64bit():
            condition_cases += (("df_scas_qword_zf", True if scas_proofs else None),)
            condition_cases += (("df_cmps_qword_zf", True if cmps_proofs else None),)
            condition_cases += (("df_stos_qword_reload", True if stos_local_proofs else None),)
            condition_cases += (("df_movs_qword_reload", True if movs_local_proofs else None),)
            condition_cases += (("df_lods_qword_value", True if lods_local_proofs else None),)
        for name, expected in condition_cases:
            root, instructions = prepare_prefix(name)
            site = next(
                instruction.ea
                for instruction in instructions
                if instruction.get_canon_mnem().startswith("set")
            )
            condition(name + " ownerless sign-extension fact", inspect(name, root), site, expected)

        for name, expected in (("df_loop", True), ("df_loop_changes", None)):
            root, instructions = prepare_prefix(name)
            site = next(
                instruction.ea
                for instruction in instructions
                if instruction.get_canon_mnem().startswith("set")
            )
            condition(name, inspect(name, root), site, expected)
        for name, expected in (("df_target", True), ("df_target_changes", False)):
            root, instructions = prepare_prefix(name)
            result = inspect(name, root)
            push = next(
                instruction
                for instruction in instructions
                if instruction.get_canon_mnem() == "push"
            )
            row = row_at(result, push.ea, "push-return")
            bits = result["address_bits"]
            check(
                name + " exact transfer stack effects",
                number(row["width_bits"]) == bits
                and number(row["stack_delta_bytes"]) == 0
                and number(row["stack_write_bytes"]) == bits // 8
                and number(row["stack_write_offset_bytes"]) == -(bits // 8)
                and number(row["transfer"]) == push.ea + push.size,
            )
            check(
                name + " target consensus",
                row["status"] == ("proved" if expected else "unresolved")
                and row["target_proof"] == ("register-definition" if expected else "unresolved")
                and (row["target"] != "unknown") == expected,
            )
            if expected:
                targets = {
                    int(instruction.Op2.addr)
                    for instruction in instructions
                    if instruction.get_canon_mnem() == "lea"
                }
                check(
                    name + " target matches encoded LEA definitions",
                    targets == {number(row["target"])},
                )

        for name, expected, destination in (
            ("df_stack_top_transfer", True, "df_stack_top_destination"),
            (
                "df_stack_top_overwrite",
                os.environ.get("CHERNOBOG_STACK_STORE_BASELINE") != "1",
                "df_stack_top_overwritten_destination",
            ),
            ("df_stack_top_dynamic", False, "df_stack_top_dynamic_seven"),
        ):
            root, instructions = prepare_prefix(name)
            result = inspect(name, root)
            pushes = [
                instruction
                for instruction in instructions
                if instruction.get_canon_mnem() == "push"
            ]
            check(name + " two ordered PUSH instructions", len(pushes) == 2)
            assert len(pushes) == 2
            row = row_at(result, pushes[-1].ea, "push-return")
            check(
                name + " ownerless stack target",
                result["converged"]
                and not result["truncated"]
                and row["status"] == ("proved" if expected else "unresolved")
                and row["target_proof"] == ("stack-definition" if expected else "unresolved")
                and row["target"] == (hex(symbol(destination)) if expected else "unknown"),
            )
            if name == "df_stack_top_overwrite":
                store = next(
                    instruction
                    for instruction in instructions
                    if ida_bytes.get_bytes(instruction.ea, instruction.size)
                    in (b"\x89\x04\x24", b"\x48\x89\x04\x24")
                )
                opcode = store.ea + (store.size == 4)
                assert ida_bytes.get_byte(opcode) == 0x89
                assert ida_bytes.patch_byte(opcode, 0x88)
                partial = inspect("df_stack_top_partial_store", root)
                partial_row = row_at(partial, pushes[-1].ea, "push-return")
                check(
                    "partial stack-top write leaves ownerless target unresolved",
                    partial_row["status"] == "unresolved" and partial_row["target"] == "unknown",
                )
                assert ida_bytes.patch_byte(opcode, 0x89)
                restored = inspect("df_stack_top_overwrite_restored", root)
                restored_row = row_at(restored, pushes[-1].ea, "push-return")
                check(
                    "restored stack-top store recomputes ownerless target",
                    restored_row["status"] == ("proved" if expected else "unresolved")
                    and restored_row["target"]
                    == (hex(symbol(destination)) if expected else "unknown"),
                )

        for name, expected in (
            ("df_memory_store_transfer", True),
            ("df_memory_direct_store", True),
            ("df_memory_split_store", True),
            ("df_memory_known_byte_overwrite", True),
            ("df_memory_repaired_byte", True),
            ("df_memory_missing_byte", False),
            ("df_memory_conflicting_byte", False),
            ("df_memory_stack_round_trip", False),
            ("df_memory_xchg_store", True),
            ("df_memory_xchg_partial", True),
            ("df_memory_xchg_byte", True),
            ("df_memory_xchg_unknown_source", False),
            ("df_memory_initial_word", False),
            ("df_memory_equal_stores", True),
            ("df_memory_disjoint_store", True),
            ("df_memory_overlapping_store", True),
            ("df_memory_unknown_alias", False),
            ("df_memory_conflicting_store", False),
            ("df_memory_alu_add", alu_proofs),
            ("df_memory_alu_xor_byte", alu_proofs),
            ("df_memory_alu_rmw_initial", False),
            ("df_memory_alu_rmw_alias", False),
            ("df_lods_memory_target", string_io_proofs),
            ("df_stos_disjoint_target", stos_local_proofs),
            ("df_stos_unknown_value_disjoint_target", stos_local_proofs),
            ("df_rep_stos_disjoint_target", False),
            ("df_stos_overlap_known_target", stos_local_proofs),
            ("df_movs_disjoint_target", movs_local_proofs),
            ("df_movs_unknown_source_disjoint_target", movs_local_proofs),
            ("df_movs_self_copy_target", movs_local_proofs),
            ("df_rep_movs_disjoint_target", False),
            ("df_rep_movs_zero_target", rep_movs_zero_proofs),
            ("df_rep_movs_one_disjoint_target", rep_movs_one_proofs),
        ):
            root, instructions = prepare_prefix(name)
            result = inspect(name, root)
            pushes = [
                instruction
                for instruction in instructions
                if instruction.get_canon_mnem() == "push"
            ]
            expected_pushes = 1 + int(
                (name == "df_memory_stack_round_trip" and result["address_bits"] == 64)
                or (
                    name
                    in (
                        "df_lods_memory_target",
                        "df_stos_disjoint_target",
                        "df_stos_unknown_value_disjoint_target",
                        "df_rep_stos_disjoint_target",
                        "df_stos_overlap_known_target",
                    )
                    and result["address_bits"] == 32
                )
            )
            if (
                name
                in (
                    "df_movs_disjoint_target",
                    "df_movs_unknown_source_disjoint_target",
                    "df_movs_self_copy_target",
                    "df_rep_movs_disjoint_target",
                    "df_rep_movs_zero_target",
                    "df_rep_movs_one_disjoint_target",
                )
                and result["address_bits"] == 32
            ):
                expected_pushes = 3
            check(name + " expected PUSH count", len(pushes) == expected_pushes)
            assert len(pushes) == expected_pushes
            row = row_at(result, pushes[-1].ea, "push-return")
            check(
                name + " ownerless writable-memory target",
                result["converged"]
                and not result["truncated"]
                and row["status"] == ("proved" if expected else "unresolved")
                and row["target_proof"] == ("memory-definition" if expected else "unresolved")
                and row["target"] == (hex(symbol("df_memory_target")) if expected else "unknown"),
            )

        for name, i386_pushes in (("df_rep_movs_alias", 3), ("df_stos_alias", 2)):
            root, instructions = prepare_prefix(name)
            result = inspect(name, root)
            pushes = [
                instruction
                for instruction in instructions
                if instruction.get_canon_mnem() == "push"
            ]
            check(
                name + " alias expected PUSH count",
                len(pushes) == (1 if result["address_bits"] == 64 else i386_pushes),
            )
            row = row_at(result, pushes[-1].ea, "push-return")
            check(
                name + " invalidates possibly aliased writable bytes",
                result["converged"]
                and not result["truncated"]
                and row["status"] == "unresolved"
                and row["target_proof"] == "unresolved"
                and row["target"] == "unknown",
            )

        root, instructions = prepare_prefix("df_memory_xchg_load")
        result = inspect("df_memory_xchg_load", root)
        pushes = [
            instruction for instruction in instructions if instruction.get_canon_mnem() == "push"
        ]
        check("XCHG register-load has one PUSH", len(pushes) == 1)
        assert len(pushes) == 1
        row = row_at(result, pushes[0].ea, "push-return")
        check(
            "XCHG loads prior writable bytes into register target",
            result["converged"]
            and not result["truncated"]
            and row["status"] == "proved"
            and row["target_proof"] == "register-definition"
            and row["target"] == hex(symbol("df_memory_target")),
        )

        for name, expected in (
            ("df_memory_mov_load", True),
            ("df_memory_mov_load_byte", True),
            ("df_memory_mov_load_initial", False),
            ("df_memory_mov_load_alias", False),
            ("df_memory_movzx_byte", True),
            ("df_memory_movsx_byte", True),
            ("df_memory_movzx_word", True),
            ("df_memory_movsx_word", True),
            ("df_memory_movzx_initial", False),
            ("df_memory_movzx_alias", False),
            ("df_memory_alu_source", alu_proofs),
            ("df_memory_alu_initial", False),
            ("df_memory_alu_alias", False),
            ("df_rep_movs_register_target", movs_proofs),
            ("df_movs_plain_count_target", movs_proofs),
            ("df_rep_movs_count_unknown", movs_proofs and rep_count_proofs),
            ("df_stos_register_target", string_io_proofs),
            ("df_rep_stos_count_target", string_io_proofs and string_count_proofs),
            ("df_rep_lods_count_target", string_io_proofs and string_count_proofs),
            ("df_repe_cmps_one_count_target", rep_compare_zero_proofs),
            ("df_repne_scas_one_count_target", rep_compare_zero_proofs),
            ("df_lods_full_target", lods_local_proofs),
            ("df_lods_byte_preserved_target", lods_local_proofs),
        ):
            root, instructions = prepare_prefix(name)
            result = inspect(name, root)
            pushes = [
                instruction
                for instruction in instructions
                if instruction.get_canon_mnem() == "push"
            ]
            expected_pushes = (
                3
                if result["address_bits"] == 32
                and name
                in (
                    "df_rep_movs_register_target",
                    "df_movs_plain_count_target",
                    "df_rep_movs_count_unknown",
                    "df_repe_cmps_one_count_target",
                )
                else (
                    2
                    if result["address_bits"] == 32
                    and name
                    in (
                        "df_stos_register_target",
                        "df_rep_stos_count_target",
                        "df_rep_lods_count_target",
                        "df_repne_scas_one_count_target",
                        "df_lods_full_target",
                        "df_lods_byte_preserved_target",
                    )
                    else 1
                )
            )
            check(name + " expected PUSH count", len(pushes) == expected_pushes)
            assert len(pushes) == expected_pushes
            row = row_at(result, pushes[-1].ea, "push-return")
            check(
                name + " ownerless register target",
                result["converged"]
                and not result["truncated"]
                and row["status"] == ("proved" if expected else "unresolved")
                and row["target_proof"] == ("register-definition" if expected else "unresolved")
                and row["target"] == (hex(symbol("df_memory_target")) if expected else "unknown"),
            )

        root, source, join, end = (
            symbol("od_adjacent_" + suffix) for suffix in ("root", "external", "join", "end")
        )
        remove_owners(root, end + 3)
        data_span(symbol("od_adjacent_root_end"), 3, b"\xcc" * 3)
        data_span(end, 3, b"\xcc" * 3)
        data_span(source, 1, b"\xf8")
        decode_span(root, symbol("od_adjacent_root_end"))
        decode_span(join, end)
        condition("adjacent source not code", inspect("adjacent_source_data", root), join, True)
        assert ida_bytes.del_items(source, ida_bytes.DELIT_SIMPLE, 1)
        assert ida_ua.create_insn(source) == 1
        ida_xref.del_cref(source, join, False)
        adjacent = inspect("adjacent_source_without_reference", root)
        condition("adjacent external fallthrough", adjacent, join, None)
        node = next(node for node in adjacent["nodes"] if number(node["site"]) == join)
        check(
            "decoded adjacency captured without trusting xrefs",
            node["unknown_entry"] == "true"
            and number(node["adjacent"]) == source
            and node["adjacent_bytes"] == "f8"
            and not any(ref.frm == source and ref.iscode for ref in idautils.XrefsTo(join)),
        )
        data_span(source, 1, b"\xf8")
        condition("adjacent source restored", inspect("adjacent_source_restored", root), join, True)

        root, end = symbol("od_call_root"), symbol("od_call_end")
        remove_owners(root, end + 3)
        for suffix in ("root_end", "end"):
            data_span(symbol("od_call_" + suffix), 3, b"\xcc" * 3)
        decode_span(root, symbol("od_call_root_end"))
        decode_span(symbol("od_call_callee"), end)
        called = inspect("call_return_barrier", root)
        condition("call return clears flags", called, symbol("od_call_join"), None)
        check(
            "call frontier and normal-return edge explicit",
            any(
                edge["kind"] == "frontier" and edge["reason"] == "call_target_not_followed"
                for edge in called["edges"]
            )
            and any(edge["kind"] == "call-return" for edge in called["edges"])
            and symbol("od_call_callee") not in {number(node["site"]) for node in called["nodes"]},
        )

        root, unsupported, join, end = (
            symbol("od_frontier_" + suffix) for suffix in ("root", "unsupported", "join", "end")
        )
        remove_owners(root, end + 3)
        for suffix in ("root_end", "end"):
            data_span(symbol("od_frontier_" + suffix), 3, b"\xcc" * 3)
        decode_span(root, symbol("od_frontier_root_end"))
        decode_span(unsupported, end)
        assert ida_bytes.get_bytes(unsupported, join - unsupported) == bytes.fromhex("660fc8")
        ida_xref.del_cref(unsupported, join, False)
        frontier = inspect("admitted_frontier_adjacency_encoding_only", root)
        condition("undefined BSWAP result does not alter carry", frontier, join, False)
        node = next(node for node in frontier["nodes"] if number(node["site"]) == join)
        check(
            "admitted BSWAP predecessor is an exact graph edge",
            node["unknown_entry"] == "false"
            and any(
                number(edge["source"]) == unsupported
                and number(edge["target"]) == join
                and edge["kind"] == "fallthrough"
                for edge in frontier["edges"]
            ),
        )
        check(
            "BSWAP16 result explicitly undefined",
            next(row for row in frontier["nodes"] if number(row["site"]) == unsupported)[
                "abstract_effect"
            ]
            == "undefined-register-result",
        )
        captures["admitted_frontier_adjacency_encoding_only"][
            "scope"
        ] = "Undefined-result abstract continuation; native process checks flags only"

        for name, expected in (("od_bswap_flag", True), ("od_bswap_value", None)):
            root, use, end = (symbol(name + suffix) for suffix in ("_root", "_use", "_end"))
            remove_owners(root, end + 3)
            data_span(end, 3, b"\xcc" * 3)
            decode_span(root, end)
            result = inspect(name + "_encoding_only", root)
            condition(name + " abstract effect", result, use, expected)
            check(
                name + " result is explicit",
                any(
                    row["abstract_effect"] == "undefined-register-result" for row in result["nodes"]
                ),
            )
            captures[name + "_encoding_only"]["scope"] = (
                "Static effect and native flag control; result discarded"
                if expected is True
                else "Static undefined-value control; no native execution"
            )

        for name in ("od_sahf_prefix", "od_lahf_prefix"):
            root, instruction, use, end = (
                symbol(name + suffix) for suffix in ("_root", "_instruction", "_use", "_end")
            )
            remove_owners(root, end + 3)
            data_span(end, 3, b"\xcc" * 3)
            decode_span(root, end)
            result = inspect(name + "_rejection", root)
            check(
                name + " unsupported prefix stops before use",
                any(
                    number(edge["source"]) == instruction
                    and edge["kind"] == "frontier"
                    and edge["reason"] == "unsupported_status_ah_encoding"
                    for edge in result["edges"]
                )
                and not any(number(row["site"]) == use for row in result["records"])
                and use not in {number(row["site"]) for row in result["nodes"]},
            )
            captures[name + "_rejection"][
                "scope"
            ] = "Prefixed status-AH encoding; no native execution"

        for name, payload in (
            ("od_negative8", bytes.fromhex("6affc3")),
            ("od_negative32", bytes.fromhex("68ffffffffc3")),
        ):
            root, end = symbol(name), symbol(name + "_end")
            remove_owners(root, end + 3)
            data_span(end, 3, b"\xcc" * 3)
            assert ida_bytes.get_bytes(root, end - root) == payload
            decode_span(root, end)
            result = inspect(name + "_encoding_only", root)
            row = row_at(result, root, "push-return")
            check(
                name + " immediate target sign extension",
                row["status"] == "proved"
                and row["target_proof"] == "immediate"
                and number(row["target"]) == (1 << result["address_bits"]) - 1,
            )
            captures[name + "_encoding_only"][
                "scope"
            ] = "Encoded operand semantics only; deliberately not native-executed"

        mutation_controls(configurations["od_equal"], baseline)
        metadata_controls(configurations["od_equal"])
        root = configurations["od_equal"][""]
        before = inventory()
        legacy = api(f"chernobog_native_evidence({root})")
        check(
            "legacy ownerless evidence remains unavailable",
            not legacy["available"] and not legacy["records"],
        )
        check("legacy ownerless inspection preserves IDB", before == inventory())
        captures["ordinary_final"] = api(f"chernobog_native_evidence({ordinary})")
        check(
            "ordinary control remains fresh after final read-only calls",
            any(
                row["fresh"] == "true" and row["kind"] == "setcc-value"
                for row in captures["ordinary_final"]["records"]
            ),
        )
    except BaseException as error:
        errors.append(type(error).__name__)
        captures["exception"] = {
            "type": type(error).__name__,
            "frames": [
                {"function": frame.name, "line": frame.lineno}
                for frame in traceback.extract_tb(error.__traceback__)
            ],
        }

    (Path(os.environ["IDAUSR"]).parent / "ownerless_dataflow.json").write_text(
        json.dumps({"checks": checks, "errors": errors, "captures": captures}, indent=2) + "\n"
    )
    print("[chernobog][ownerless-dataflow] " + ("FAIL" if errors else "PASS"), flush=True)
    return 2 if errors else 0


if __name__ == "__main__":
    ida_pro.qexit(main())
