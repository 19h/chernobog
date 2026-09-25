"""Owned-function dataflow, source provenance, and join topology invalidation."""

import json
import os
from pathlib import Path
import sys

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_ida
import ida_idaapi
import ida_loader
import ida_name
import ida_pro
import ida_ua
import ida_xref
import idautils

sys.dont_write_bytecode = True
records, errors, captures = [], [], {}


def check(label, condition):
    records.append({"case": label, "passed": bool(condition)})
    if not condition:
        errors.append(label)


def address(name):
    for candidate in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return ea
    raise AssertionError("fixture symbol missing")


def inspect(ea):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"chernobog_native_evidence({ea})")
    snapshot = json.loads(value.c_str())
    snapshot["user_edges"] = {
        row["site"]: sorted(
            {hex(x.to) for x in idautils.XrefsFrom(int(row["site"], 0)) if x.iscode and x.user}
        )
        for row in snapshot["records"]
        if row["kind"] == "stack-transfer" and row["fresh"] == "true"
    }
    return snapshot


def reanalyze(ea):
    function = ida_funcs.get_func(ea)
    assert function
    ida_auto.plan_and_wait(function.start_ea, function.end_ea)
    ida_auto.auto_wait()


def current_set(snapshot):
    return [r for r in snapshot["records"] if r["kind"] == "setcc-value" and r["fresh"] == "true"]


def adjacent_external_flow():
    root, root_end, source, tail, branch, taken, tail_end = (
        address("df_flow_" + name)
        for name in ("root", "root_end", "external", "tail", "branch", "taken", "tail_end")
    )
    original_bytes = ida_bytes.get_bytes(root, tail_end - root)
    for owner in sorted(
        {
            function.start_ea
            for site in range(root, tail_end)
            if (function := ida_funcs.get_func(site))
        }
    ):
        assert ida_funcs.del_func(owner)
    for first, end in ((root, root_end), (source, tail_end)):
        cursor = first
        while cursor < end:
            size = ida_ua.create_insn(cursor)
            assert size > 0
            cursor += size
        assert cursor == end
    assert ida_funcs.add_func(root, root_end)
    assert ida_funcs.append_func_tail(ida_funcs.get_func(root), tail, tail_end)
    captures["adjacent_flow_setup"] = {
        "root": hex(root),
        "tail": hex(tail),
        "source": hex(source),
        "before_analysis": {
            hex(site): hex(function.start_ea) if (function := ida_funcs.get_func(site)) else None
            for site in (root, source, tail)
        },
    }
    ida_auto.auto_wait()
    captures["adjacent_flow_setup"]["after_analysis"] = {
        hex(site): hex(function.start_ea) if (function := ida_funcs.get_func(site)) else None
        for site in (root, source, tail)
    }
    assert ida_bytes.get_item_end(source) == tail
    assert ida_funcs.get_func(source) is None
    assert ida_funcs.get_func(tail).start_ea == root
    ida_xref.del_cref(source, tail, False)

    def reanalyze_owned():
        ida_auto.plan_and_wait(root, root_end)
        ida_auto.plan_and_wait(tail, tail_end)
        ida_auto.auto_wait()

    def capture(label):
        snapshot = inspect(root)
        snapshot["observables"] = {
            hex(site): {
                "comment": ida_bytes.get_cmt(site, True) or "",
                "owner": hex(function.start_ea) if (function := ida_funcs.get_func(site)) else None,
                "is_code": bool(ida_bytes.is_code(ida_bytes.get_flags(site))),
                "outgoing": [
                    {"target": hex(x.to), "type": int(x.type), "user": bool(x.user)}
                    for x in idautils.XrefsFrom(site)
                    if x.iscode
                ],
            }
            for site in (source, tail, branch)
        }
        captures["adjacent_flow_" + label] = snapshot
        return snapshot

    def current_rows(snapshot):
        return {
            int(row["site"], 0): row
            for row in snapshot["records"]
            if row["fresh"] == "true"
            and row["kind"] in ("setcc-value", "local-flag-branch")
            and int(row["site"], 0) in (tail, branch)
        }

    def owned_edge(snapshot):
        return any(
            edge["target"] == hex(taken) and edge["type"] == ida_xref.fl_JN and edge["user"]
            for edge in snapshot["observables"][hex(branch)]["outgoing"]
        )

    reanalyze_owned()
    before = capture("before")
    rows = current_rows(before)
    check("adjacent flow baseline has both exact facts", set(rows) == {tail, branch})
    check("adjacent flow baseline has owned branch edge", owned_edge(before))
    proof_comments = {
        site: "[chernobog][ida-analysis] " + row["conclusion"] for site, row in rows.items()
    }
    check(
        "adjacent flow baseline has both owned comments",
        set(proof_comments) == {tail, branch}
        and all(
            line in before["observables"][hex(site)]["comment"].splitlines()
            for site, line in proof_comments.items()
        ),
    )
    check(
        "adjacent flow source is defined code outside the owned graph",
        before["observables"][hex(source)]["is_code"]
        and before["observables"][hex(source)]["owner"] is None,
    )
    assert set(rows) == {tail, branch} and owned_edge(before)
    other_comments = {
        site: set(before["observables"][hex(site)]["comment"].splitlines()) - {line}
        for site, line in proof_comments.items()
    }
    publications = {row["publication"] for row in rows.values()}
    assert ida_xref.add_cref(source, tail, ida_xref.fl_F)
    for label in ("immediate", "after_autoanalysis"):
        if label == "after_autoanalysis":
            ida_auto.auto_wait()
        snapshot = capture(label)
        check("adjacent flow " + label + " has no current exact fact", not current_rows(snapshot))
        check(
            "adjacent flow " + label + " revokes old publications",
            not any(row["publication"] in publications for row in snapshot["records"]),
        )
        check("adjacent flow " + label + " revokes owned edge", not owned_edge(snapshot))
        check(
            "adjacent flow " + label + " revokes owned comments",
            all(
                line not in snapshot["observables"][hex(site)]["comment"].splitlines()
                for site, line in proof_comments.items()
            ),
        )
        check(
            "adjacent flow " + label + " retains unrelated comment lines",
            all(
                lines <= set(snapshot["observables"][hex(site)]["comment"].splitlines())
                for site, lines in other_comments.items()
            ),
        )
        check(
            "adjacent flow " + label + " retains external entry",
            any(x.frm == source and x.type == ida_xref.fl_F for x in idautils.XrefsTo(tail)),
        )
    ida_xref.del_cref(source, tail, False)
    reanalyze_owned()
    restored = capture("restored")
    restored_rows = current_rows(restored)
    check(
        "removed adjacent flow recomputes both facts with new publications",
        set(restored_rows) == {tail, branch}
        and all(row["publication"] not in publications for row in restored_rows.values()),
    )
    check("removed adjacent flow restores owned branch edge", owned_edge(restored))
    restored_publications = {row["publication"] for row in restored_rows.values()}
    assert ida_funcs.remove_func_tail(ida_funcs.get_func(root), tail)
    check("tail removal changes ownership immediately", ida_funcs.get_func(tail) is None)
    for label in ("tail_removed_immediate", "tail_removed_after_autoanalysis"):
        immediate = label == "tail_removed_immediate"
        if not immediate:
            ida_auto.auto_wait()
        snapshot = capture(label)
        renewed = current_rows(snapshot)
        check(
            label + " revokes old publications",
            not any(row["publication"] in restored_publications for row in snapshot["records"]),
        )
        check(
            label + " revokes or independently recomputes owned comments",
            all(
                line not in snapshot["observables"][hex(site)]["comment"].splitlines()
                or (
                    not immediate
                    and site in renewed
                    and renewed[site]["publication"] not in restored_publications
                )
                for site, line in proof_comments.items()
            ),
        )
        check(
            label + " revokes or independently recomputes owned edge",
            not owned_edge(snapshot)
            or (
                not immediate
                and branch in renewed
                and renewed[branch]["publication"] not in restored_publications
            ),
        )
    if ida_funcs.get_func(tail) is None:
        assert ida_funcs.append_func_tail(ida_funcs.get_func(root), tail, tail_end)
    assert ida_funcs.get_func(tail).start_ea == root
    reanalyze_owned()
    reattached = capture("tail_restored")
    reattached_rows = current_rows(reattached)
    check(
        "tail reattachment recomputes both exact facts",
        set(reattached_rows) == {tail, branch}
        and all(
            row["publication"] not in restored_publications for row in reattached_rows.values()
        ),
    )
    check("tail reattachment restores owned branch edge", owned_edge(reattached))
    check(
        "adjacent flow lifecycle retains exact fixture bytes",
        ida_bytes.get_bytes(root, tail_end - root) == original_bytes,
    )


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
    expected = {
        "df_equal": True,
        "df_different": False,
        "df_flags": True,
        "df_direction": True,
        "df_flags_saved": True,
        "df_flags_full": True,
        "df_flags_literal": True,
        "df_sahf_cf": True,
        "df_sahf_of": True,
        "df_lahf_roundtrip": True,
        "df_sahf_dynamic": False,
        "df_lahf_constant": True,
        "df_flags_overwrite": False,
        "df_flags_dynamic": False,
        "df_memory_movsx_negative": True,
        "df_memory_movsx_initial_negative": False,
        "df_memory_movsxd_negative": True,
        "df_memory_movsxd_initial_negative": False,
        "df_memory_movsx_word_negative": True,
        "df_memory_movsx_initial_word_negative": False,
        "df_memory_alu_compare": alu_proofs,
        "df_memory_alu_compare_initial": False,
        "df_memory_alu_flags": alu_proofs,
        "df_memory_alu_flags_initial": False,
        "df_rep_movs_cf": movs_proofs,
        "df_rep_movs_zf": movs_proofs,
        "df_movs_plain_cf": movs_proofs,
        "df_cmps_flags_changed": 0 if cmps_proofs else False,
        "df_cmps_same_zf": cmps_proofs,
        "df_cmps_local_cf_true": cmps_proofs,
        "df_cmps_local_cf_false": 0 if cmps_proofs else False,
        "df_cmps_word_cf": cmps_proofs,
        "df_cmps_dword_zf": cmps_proofs,
        "df_cmps_initial_unknown": False,
        "df_rep_cmps_count_ambiguity": False,
        "df_repe_cmps_zero_preserve": rep_compare_zero_proofs,
        "df_repne_cmps_one_cf": rep_compare_one_proofs,
        "df_repe_cmps_one_zf": rep_compare_one_proofs,
        "df_repne_cmps_two_early_stop": False,
        "df_rep_stos_cf": string_io_proofs,
        "df_lods_plain_cf": string_io_proofs,
        "df_rep_lods_zf": string_io_proofs,
        "df_scas_flags_changed": 0 if scas_proofs else False,
        "df_scas_cf_true": scas_proofs,
        "df_scas_zf_true": scas_proofs,
        "df_scas_word_cf": scas_proofs,
        "df_scas_dword_zf": scas_proofs,
        "df_scas_initial_cf": False,
        "df_rep_scas_count_ambiguity": False,
        "df_repne_scas_zero_preserve": rep_compare_zero_proofs,
        "df_repe_scas_one_cf": rep_compare_one_proofs,
        "df_repne_scas_one_zf": rep_compare_one_proofs,
        "df_repe_scas_two_early_stop": False,
        "df_stos_byte_reload": stos_local_proofs,
        "df_stos_word_reload": stos_local_proofs,
        "df_stos_dword_reload": stos_local_proofs,
        "df_stos_unknown_overlap_condition": False,
        "df_movs_byte_reload": movs_local_proofs,
        "df_movs_overlap_word_reload": movs_local_proofs,
        "df_movs_dword_reload": movs_local_proofs,
        "df_movs_initial_source_unknown": False,
        "df_rep_movs_zero_preserve": rep_movs_zero_proofs,
        "df_rep_movs_one_reload": rep_movs_one_proofs,
        "df_lods_byte_value": lods_local_proofs,
        "df_lods_word_value": lods_local_proofs,
        "df_lods_dword_value": lods_local_proofs,
        "df_lods_unknown_source_value": False,
        "df_rep_lods_ambiguous_value": False,
        "df_lods_unknown_source_high_value": lods_local_proofs,
        "df_loop": True,
        "df_loop_changes": False,
        "df_stack": True,
        "df_stack_changes": False,
        "df_jump": True,
    }
    if ida_ida.inf_is_64bit():
        expected["df_scas_qword_zf"] = scas_proofs
        expected["df_cmps_qword_zf"] = cmps_proofs
        expected["df_stos_qword_reload"] = stos_local_proofs
        expected["df_movs_qword_reload"] = movs_local_proofs
        expected["df_lods_qword_value"] = lods_local_proofs
    for name, proved in expected.items():
        ea = address(name)
        reanalyze(ea)
        snapshot = inspect(ea)
        snapshot["native_inventory"] = [
            {
                "site": hex(site),
                "bytes": (ida_bytes.get_bytes(site, ida_bytes.get_item_size(site)) or b"").hex(),
                "disassembly": idautils.DecodeInstruction(site).get_canon_mnem(),
                "incoming": [
                    {"source": hex(x.frm), "type": int(x.type)} for x in idautils.XrefsTo(site)
                ],
            }
            for site in idautils.FuncItems(ea)
            if ida_bytes.is_code(ida_bytes.get_flags(site))
        ]
        captures[name] = snapshot
        rows = current_set(snapshot)
        check(name + " exact admission", bool(rows) == (proved is not False))
        if rows:
            check(
                name + " proven value",
                len(rows) == 1 and rows[0]["value"] == hex(int(proved)),
            )
            check(name + " graph source dependencies", int(rows[0]["dependency_count"]) >= 4)
    target_ea = address("df_target")
    reanalyze(target_ea)
    captures["df_target"] = inspect(target_ea)
    target_rows = [
        r
        for r in captures["df_target"]["records"]
        if r["kind"] == "stack-transfer"
        and r["fresh"] == "true"
        and r["truth"] == "native-proof"
        and r["edge"] == "true"
        and r["target_basis"] == "register-definition"
    ]
    check("equal predecessor pointers recover register PUSH/RET", bool(target_rows))
    if target_rows:
        check(
            "recovered transfer preserves stack effects",
            all(
                r["stack_delta_bytes"] == "0"
                and int(r["stack_write_bytes"]) * 8 == int(r["width_bits"])
                for r in target_rows
            ),
        )
    changing_ea = address("df_target_changes")
    reanalyze(changing_ea)
    captures["df_target_changes"] = inspect(changing_ea)
    changing_rows = [
        r for r in captures["df_target_changes"]["records"] if r["kind"] == "stack-transfer"
    ]
    check(
        "different predecessor pointers remain unresolved",
        changing_rows
        and all(
            r["truth"] == "candidate" and r["edge"] == "false" and r["target_basis"] == "unresolved"
            for r in changing_rows
        ),
    )
    stack_root = address("df_stack_top_transfer")
    reanalyze(stack_root)
    captures["df_stack_top_transfer"] = inspect(stack_root)
    captures["df_stack_top_transfer"]["native_inventory"] = [
        {
            "site": hex(site),
            "bytes": (ida_bytes.get_bytes(site, ida_bytes.get_item_size(site)) or b"").hex(),
            "mnemonic": idautils.DecodeInstruction(site).get_canon_mnem(),
            "owner": hex(ida_funcs.get_func(site).start_ea),
        }
        for site in idautils.FuncItems(stack_root)
        if ida_bytes.is_code(ida_bytes.get_flags(site))
    ]
    stack_rows = [
        row
        for row in captures["df_stack_top_transfer"]["records"]
        if row["kind"] == "stack-transfer" and row["fresh"] == "true"
    ]
    check(
        "tracked stack-top PUSH/RET has an exact native edge",
        len(stack_rows) == 1
        and stack_rows[0]["truth"] == "native-proof"
        and stack_rows[0]["edge"] == "true"
        and stack_rows[0]["target_basis"] == "stack-definition"
        and "bounded prior stack word" in stack_rows[0]["memory_model"]
        and int(stack_rows[0]["target"], 0) == address("df_stack_top_destination")
        and stack_rows[0]["stack_delta_bytes"] == "0"
        and int(stack_rows[0]["stack_write_bytes"]) * 8 == int(stack_rows[0]["width_bits"]),
    )
    overwrite_root = address("df_stack_top_overwrite")
    reanalyze(overwrite_root)
    captures["df_stack_top_overwrite"] = inspect(overwrite_root)
    captures["df_stack_top_overwrite"]["native_inventory"] = [
        {
            "site": hex(site),
            "bytes": (ida_bytes.get_bytes(site, ida_bytes.get_item_size(site)) or b"").hex(),
            "mnemonic": idautils.DecodeInstruction(site).get_canon_mnem(),
            "owner": hex(ida_funcs.get_func(site).start_ea),
        }
        for site in idautils.FuncItems(overwrite_root)
        if ida_bytes.is_code(ida_bytes.get_flags(site))
    ]
    overwrite_rows = [
        row
        for row in captures["df_stack_top_overwrite"]["records"]
        if row["kind"] == "stack-transfer" and row["fresh"] == "true"
    ]
    stack_store_proofs = os.environ.get("CHERNOBOG_STACK_STORE_BASELINE") != "1"
    check(
        "overwritten stack top has expected transfer status",
        len(overwrite_rows) == 1
        and overwrite_rows[0]["truth"] == ("native-proof" if stack_store_proofs else "candidate")
        and overwrite_rows[0]["edge"] == ("true" if stack_store_proofs else "false")
        and overwrite_rows[0]["target_basis"]
        == ("stack-definition" if stack_store_proofs else "unresolved")
        and overwrite_rows[0].get("target", "unknown")
        == (
            hex(address("df_stack_top_overwritten_destination"))
            if stack_store_proofs
            else "unknown"
        ),
    )
    check(
        "overwritten stack top IDB user edge",
        any(
            x.iscode and x.to == address("df_stack_top_overwritten_destination") and x.user
            for x in idautils.XrefsFrom(int(overwrite_rows[0]["site"], 0))
        )
        == stack_store_proofs,
    )
    check(
        "overwritten stack candidate retains its stack-source scope",
        len(overwrite_rows) == 1
        and "bounded prior stack word" in overwrite_rows[0]["memory_model"],
    )
    overwrite_store = next(
        item
        for item in captures["df_stack_top_overwrite"]["native_inventory"]
        if item["bytes"] in ("890424", "48890424")
    )
    store_opcode = int(overwrite_store["site"], 0) + (overwrite_store["bytes"].startswith("48"))
    assert ida_bytes.get_byte(store_opcode) == 0x89
    assert ida_bytes.patch_byte(store_opcode, 0x88)
    reanalyze(overwrite_root)
    captures["df_stack_top_partial_store"] = inspect(overwrite_root)
    partial_rows = [
        row
        for row in captures["df_stack_top_partial_store"]["records"]
        if row["kind"] == "stack-transfer" and row["fresh"] == "true"
    ]
    check(
        "partial stack-top write abstains and revokes its user edge",
        len(partial_rows) == 1
        and partial_rows[0]["truth"] == "candidate"
        and partial_rows[0]["edge"] == "false"
        and captures["df_stack_top_partial_store"]["user_edges"].get(partial_rows[0]["site"]) == [],
    )
    assert ida_bytes.patch_byte(store_opcode, 0x89)
    reanalyze(overwrite_root)
    captures["df_stack_top_overwrite_restored"] = inspect(overwrite_root)
    restored_rows = [
        row
        for row in captures["df_stack_top_overwrite_restored"]["records"]
        if row["kind"] == "stack-transfer" and row["fresh"] == "true"
    ]
    check(
        "restored stack-top store recomputes the expected edge",
        len(restored_rows) == 1
        and restored_rows[0]["truth"] == ("native-proof" if stack_store_proofs else "candidate")
        and captures["df_stack_top_overwrite_restored"]["user_edges"].get(restored_rows[0]["site"])
        == ([hex(address("df_stack_top_overwritten_destination"))] if stack_store_proofs else []),
    )
    dynamic_root = address("df_stack_top_dynamic")
    reanalyze(dynamic_root)
    captures["df_stack_top_dynamic"] = inspect(dynamic_root)
    dynamic_rows = [
        row
        for row in captures["df_stack_top_dynamic"]["records"]
        if row["kind"] == "stack-transfer" and row["fresh"] == "true"
    ]
    check(
        "different branch-defined stack words remain unresolved",
        len(dynamic_rows) == 1
        and dynamic_rows[0]["truth"] == "candidate"
        and dynamic_rows[0]["edge"] == "false"
        and dynamic_rows[0]["target_basis"] == "unresolved"
        and "bounded prior stack word" in dynamic_rows[0]["memory_model"],
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
        ("df_rep_movs_alias", False),
        ("df_movs_disjoint_target", movs_local_proofs),
        ("df_movs_unknown_source_disjoint_target", movs_local_proofs),
        ("df_movs_self_copy_target", movs_local_proofs),
        ("df_rep_movs_disjoint_target", False),
        ("df_rep_movs_zero_target", rep_movs_zero_proofs),
        ("df_rep_movs_one_disjoint_target", rep_movs_one_proofs),
        ("df_stos_alias", False),
        ("df_stos_disjoint_target", stos_local_proofs),
        ("df_stos_unknown_value_disjoint_target", stos_local_proofs),
        ("df_rep_stos_disjoint_target", False),
        ("df_stos_overlap_known_target", stos_local_proofs),
        ("df_lods_memory_target", string_io_proofs),
    ):
        root = address(name)
        reanalyze(root)
        captures[name] = inspect(root)
        rows = [
            row
            for row in captures[name]["records"]
            if row["kind"] == "stack-transfer" and row["fresh"] == "true"
        ]
        check(name + " has one current transfer", len(rows) == 1)
        if rows:
            row = rows[0]
            check(
                name + " local writable-memory proof scope",
                row.get("memory_address")
                == hex(
                    address(
                        "df_memory_initial_slot"
                        if name
                        in (
                            "df_memory_initial_word",
                            "df_memory_missing_byte",
                            "df_memory_alu_rmw_initial",
                        )
                        else "df_memory_slot"
                    )
                )
                and "bounded prior writable-memory store" in row["memory_model"]
                and row["stack_delta_bytes"] == "0"
                and int(row["stack_write_bytes"]) * 8 == int(row["width_bits"]),
            )
            check(
                name + " target status",
                row["truth"] == ("native-proof" if expected else "candidate")
                and row["edge"] == ("true" if expected else "false")
                and row["target_basis"] == ("memory-definition" if expected else "unresolved")
                and row.get("target", "unknown")
                == (hex(address("df_memory_target")) if expected else "unknown"),
            )
            check(
                name + " IDB user edge",
                any(
                    x.iscode and x.to == address("df_memory_target") and x.user
                    for x in idautils.XrefsFrom(int(row["site"], 0))
                )
                == expected,
            )
    exchange_root = address("df_memory_xchg_load")
    reanalyze(exchange_root)
    captures["df_memory_xchg_load"] = inspect(exchange_root)
    exchange_rows = [
        row
        for row in captures["df_memory_xchg_load"]["records"]
        if row["kind"] == "stack-transfer" and row["fresh"] == "true"
    ]
    check(
        "XCHG loads the prior writable word into its register",
        len(exchange_rows) == 1
        and exchange_rows[0]["truth"] == "native-proof"
        and exchange_rows[0]["edge"] == "true"
        and exchange_rows[0]["target_basis"] == "register-definition"
        and exchange_rows[0]["target"] == hex(address("df_memory_target"))
        and exchange_rows[0]["stack_delta_bytes"] == "0",
    )
    if exchange_rows:
        check(
            "XCHG register target has an owned user edge",
            any(
                x.iscode and x.to == address("df_memory_target") and x.user
                for x in idautils.XrefsFrom(int(exchange_rows[0]["site"], 0))
            ),
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
        root = address(name)
        reanalyze(root)
        captures[name] = inspect(root)
        rows = [
            row
            for row in captures[name]["records"]
            if row["kind"] == "stack-transfer" and row["fresh"] == "true"
        ]
        check(name + " has one current transfer", len(rows) == 1)
        if rows:
            row = rows[0]
            check(
                name + " register target status",
                row["truth"] == ("native-proof" if expected else "candidate")
                and row["edge"] == ("true" if expected else "false")
                and row["target_basis"] == ("register-definition" if expected else "unresolved")
                and row.get("target", "unknown")
                == (hex(address("df_memory_target")) if expected else "unknown"),
            )
            check(
                name + " IDB user edge",
                any(
                    x.iscode and x.to == address("df_memory_target") and x.user
                    for x in idautils.XrefsFrom(int(row["site"], 0))
                )
                == expected,
            )
    memory_root = address("df_memory_store_transfer")
    original_memory_rows = [
        row
        for row in captures["df_memory_store_transfer"]["records"]
        if row["kind"] == "stack-transfer"
        and row["fresh"] == "true"
        and row["truth"] == "native-proof"
    ]
    assert len(original_memory_rows) == 1
    store_site = next(
        site
        for site in idautils.FuncItems(memory_root)
        if (instruction := idautils.DecodeInstruction(site))
        and instruction.get_canon_mnem() == "mov"
        and instruction.Op1.type in (ida_ua.o_mem, ida_ua.o_displ, ida_ua.o_phrase)
    )
    store_raw = ida_bytes.get_bytes(store_site, ida_bytes.get_item_size(store_site))
    store_opcode = 1 if store_raw[0] == 0x48 else 0
    assert store_raw[store_opcode] == 0x89
    assert ida_bytes.patch_byte(store_site + store_opcode, 0x8B)
    reanalyze(memory_root)
    captures["df_memory_store_removed"] = inspect(memory_root)
    memory_ret = int(original_memory_rows[0]["site"], 0)
    memory_target = address("df_memory_target")
    check(
        "removing the writable store revokes the target and user edge",
        not any(
            row["kind"] == "stack-transfer"
            and row["fresh"] == "true"
            and row["truth"] == "native-proof"
            for row in captures["df_memory_store_removed"]["records"]
        )
        and not any(
            x.iscode and x.to == memory_target and x.user for x in idautils.XrefsFrom(memory_ret)
        ),
    )
    assert ida_bytes.patch_byte(store_site + store_opcode, 0x89)
    reanalyze(memory_root)
    captures["df_memory_store_restored"] = inspect(memory_root)
    restored_memory_rows = [
        row
        for row in captures["df_memory_store_restored"]["records"]
        if row["kind"] == "stack-transfer" and row["fresh"] == "true"
    ]
    check(
        "restoring the writable store recomputes the exact target",
        len(restored_memory_rows) == 1
        and restored_memory_rows[0]["truth"] == "native-proof"
        and restored_memory_rows[0]["target_basis"] == "memory-definition"
        and restored_memory_rows[0]["publication"] != original_memory_rows[0]["publication"],
    )
    if stack_rows:
        ret_site = int(stack_rows[0]["site"], 0)
        destination = address("df_stack_top_destination")
        defining_push = next(
            row["site"]
            for row in captures["df_stack_top_transfer"]["native_inventory"]
            if row["mnemonic"] == "push" and row["bytes"] == "50"
        )
        defining_push = int(defining_push, 0)
        check(
            "stack target has a published user edge",
            any(x.iscode and x.to == destination and x.user for x in idautils.XrefsFrom(ret_site)),
        )
        assert ida_bytes.patch_byte(defining_push, 0x90)
        reanalyze(stack_root)
        captures["df_stack_top_source_removed"] = inspect(stack_root)
        changed = captures["df_stack_top_source_removed"]["records"]
        check(
            "removing the establishing PUSH revokes the exact stack target",
            not any(
                row["kind"] == "stack-transfer"
                and row["fresh"] == "true"
                and row["truth"] == "native-proof"
                for row in changed
            )
            and not any(
                x.iscode and x.to == destination and x.user for x in idautils.XrefsFrom(ret_site)
            ),
        )
        assert ida_bytes.patch_byte(defining_push, 0x50)
        reanalyze(stack_root)
        captures["df_stack_top_source_restored"] = inspect(stack_root)
        renewed = [
            row
            for row in captures["df_stack_top_source_restored"]["records"]
            if row["kind"] == "stack-transfer" and row["fresh"] == "true"
        ]
        check(
            "restoring the establishing PUSH recomputes the exact stack target",
            len(renewed) == 1
            and renewed[0]["truth"] == "native-proof"
            and renewed[0]["target_basis"] == "stack-definition"
            and int(renewed[0]["target"], 0) == destination
            and renewed[0]["publication"] != stack_rows[0]["publication"],
        )
    ea = address("df_equal")
    instructions = []
    for site in idautils.FuncItems(ea):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, site) > 0:
            instructions.append(insn)
    join = next(insn.ea for insn in instructions if insn.get_canon_mnem() == "cmp")
    source = address("df_external")
    assert ida_xref.add_cref(source, join, ida_xref.fl_JN | ida_xref.XREF_USER)
    reanalyze(ea)
    captures["external_entry"] = inspect(ea)
    check(
        "external join entry revokes exact condition", not current_set(captures["external_entry"])
    )
    ida_xref.del_cref(source, join, False)
    reanalyze(ea)
    check("removed external entry allows recomputation", bool(current_set(inspect(ea))))
    defining = next(
        insn
        for insn in instructions
        if insn.get_canon_mnem() == "mov" and insn.Op2.type == ida_ua.o_imm
    )
    raw = ida_bytes.get_bytes(defining.ea, defining.size)
    assert raw[-4:] == bytes((42, 0, 0, 0))
    ida_bytes.patch_byte(defining.ea + defining.size - 4, 41)
    reanalyze(ea)
    captures["changed_predecessor"] = inspect(ea)
    check(
        "one changed predecessor removes join consensus",
        not current_set(captures["changed_predecessor"]),
    )
    ida_bytes.patch_bytes(defining.ea, raw)
    reanalyze(ea)
    check("exact predecessor restoration recomputes", bool(current_set(inspect(ea))))
    adjacent_external_flow()
except BaseException as error:
    errors.append(type(error).__name__)
    frames = []
    traceback = error.__traceback__
    while traceback:
        frames.append({"function": traceback.tb_frame.f_code.co_name, "line": traceback.tb_lineno})
        traceback = traceback.tb_next
    captures["exception"] = {"type": type(error).__name__, "frames": frames}

(Path(os.environ["IDAUSR"]).parent / "dataflow.json").write_text(
    json.dumps({"records": records, "errors": errors, "captures": captures}, indent=2) + "\n"
)
print("[chernobog][dataflow] " + ("FAIL" if errors else "PASS"), flush=True)
ida_pro.qexit(2 if errors else 0)
