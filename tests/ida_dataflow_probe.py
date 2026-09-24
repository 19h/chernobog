"""Owned-function dataflow, source provenance, and join topology invalidation."""

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
    return json.loads(value.c_str())


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
    expected = {
        "df_equal": True,
        "df_different": False,
        "df_flags": True,
        "df_direction": True,
        "df_flags_saved": True,
        "df_flags_full": True,
        "df_flags_literal": True,
        "df_flags_overwrite": False,
        "df_flags_dynamic": False,
        "df_loop": True,
        "df_loop_changes": False,
        "df_stack": True,
        "df_stack_changes": False,
        "df_jump": True,
    }
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
        check(name + " exact admission", bool(rows) == proved)
        if rows:
            check(name + " proven one", len(rows) == 1 and rows[0]["value"] == "0x1")
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
    check(
        "overwritten stack top retains an unresolved candidate",
        len(overwrite_rows) == 1
        and overwrite_rows[0]["truth"] == "candidate"
        and overwrite_rows[0]["edge"] == "false"
        and overwrite_rows[0]["target_basis"] == "unresolved",
    )
    check(
        "overwritten stack candidate retains its stack-source scope",
        len(overwrite_rows) == 1
        and "bounded prior stack word" in overwrite_rows[0]["memory_model"],
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
