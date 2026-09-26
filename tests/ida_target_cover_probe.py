"""Verify bounded target covers without promoting members to unconditional edges."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import traceback

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_name
import ida_pro
import ida_ua
import ida_xref
import idautils

sys.dont_write_bytecode = True
report = {"checks": [], "errors": [], "owned": {}, "ownerless": {}}
baseline = os.environ.get("CHERNOBOG_COVER_BASELINE") == "1"
feasibility_baseline = baseline or os.environ.get("CHERNOBOG_BRANCH_FEASIBILITY_BASELINE") == "1"
complete = {
    "df_stack_top_dynamic": ("df_stack_top_dynamic_seven", "df_stack_top_dynamic_eight"),
    "df_memory_conflicting_byte": ("df_memory_byte_target_seven", "df_memory_byte_target_eight"),
    "df_memory_conflicting_store": ("df_memory_target", "df_memory_target_eight"),
    "jc_dynamic": ("jc_dynamic_seven", "jc_dynamic_eight"),
    "jc_register": ("jc_register_destination",),
    "jc_memory": ("jc_memory_destination",),
    "jc_stack": ("jc_stack_destination",),
    "cv_multi_address": ("cv_seven", "cv_eight"),
    "cv_infeasible": ("cv_seven", "cv_eight") if feasibility_baseline else ("cv_seven",),
}
partial = {"cv_partial": ("cv_seven",), "cv_alias": ("cv_seven",)}
unknown = ("jc_cap", "jc_initial_memory", "cv_call")
controls = tuple(complete) + tuple(partial) + unknown


def check(name, condition):
    report["checks"].append({"case": name, "passed": bool(condition)})
    if not condition:
        report["errors"].append(name)


def symbol(name):
    for candidate in (name, "_" + name):
        address = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if address != ida_idaapi.BADADDR:
            return address
    raise AssertionError("missing fixture symbol " + name)


def api(name, root):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"{name}({root})")
    return json.loads(value.c_str())


def inventory(sites):
    return [
        (
            site,
            int(ida_bytes.get_full_flags(site)),
            (ida_bytes.get_bytes(site, ida_bytes.get_item_size(site)) or b"").hex(),
            hex(owner.start_ea) if (owner := ida_funcs.get_func(site)) else None,
            ida_bytes.get_cmt(site, True),
            sorted((ref.to, int(ref.type), bool(ref.user)) for ref in idautils.XrefsFrom(site)),
        )
        for site in sites
    ]


def rows(view, owned):
    return [
        row
        for row in view["records"]
        if row["kind"] == ("stack-transfer" if owned else "push-return")
        and (not owned or row["fresh"] == "true")
    ]


def verify(name, view, owned):
    selected = rows(view, owned)
    prefix = name + (" owned" if owned else " ownerless")
    check(prefix + " one current transfer", len(selected) == 1)
    if len(selected) != 1:
        return
    row = selected[0]
    unique = name in complete and len(complete[name]) == 1
    check(
        prefix + " scalar status unchanged",
        (
            row["edge"] == ("true" if unique else "false")
            if owned
            else row["status"] == ("proved" if unique else "unresolved")
        ),
    )
    if not unique:
        check(prefix + " no unique target invented", row.get("target") in (None, "unknown"))
    if baseline:
        check(prefix + " prior API has no target cover", "target_cover_complete" not in row)
        return
    expected = sorted(symbol(label) for label in complete.get(name, partial.get(name, ())))
    actual = [int(value, 0) for value in row["target_cover_values"].split(";") if value]
    check(
        prefix + " exact independent member set",
        actual == expected and int(row["target_cover_count"]) == len(expected),
    )
    check(
        prefix + " complete versus partial scope",
        row["target_cover_complete"] == ("true" if name in complete else "false")
        and row["target_cover_status"]
        == ("complete" if name in complete else "partial" if name in partial else "unresolved"),
    )
    check(
        prefix + " recomputed nonpublication contract",
        row["target_cover_validation"] == "recomputed"
        and "member reachability is not asserted" in row["target_cover_scope"]
        and "no edge publication" in row["target_cover_scope"],
    )
    check(
        prefix + " unknown inputs retained",
        (
            int(row["target_cover_unknown_inputs"]) == 0
            if name in complete
            else int(row["target_cover_unknown_inputs"]) > 0
        ),
    )
    support = row["target_cover_support"].split(";")
    check(
        prefix + " current byte support",
        bool(support)
        and all(
            ida_bytes.get_bytes(int(item.split(":")[0], 0), len(item.split(":")[1]) // 2).hex()
            == item.split(":")[1]
            for item in support
        ),
    )
    if name == "jc_cap":
        check(
            prefix + " nine-state overflow retained",
            row["target_cover_widened"] == "true"
            and row["target_cover_reason"] == "widened_source_unknown",
        )


def main():
    try:
        ida_auto.auto_wait()
        module = None
        if os.environ.get("CHERNOBOG_VIEW_MODULE"):
            spec = importlib.util.spec_from_file_location(
                "cover_evidence_view", os.environ["CHERNOBOG_VIEW_MODULE"]
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        ends = {
            "jc_cap": "jc_cap_destination",
            "cv_partial": "cv_alias",
            "cv_alias": "cv_multi_address",
            "cv_multi_address": "cv_infeasible",
            "cv_infeasible": "cv_call",
            "cv_call": "cv_opaque",
        }
        sites = {}
        for name in controls:
            root = symbol(name)
            if name in ends:
                end = symbol(ends[name])
                for entry in list(idautils.Functions(root, end)):
                    assert ida_funcs.del_func(entry)
                assert ida_funcs.add_func(root, end)
            assert ida_funcs.get_func(root) or ida_funcs.add_func(root)
            function = ida_funcs.get_func(root)
            ida_auto.plan_and_wait(root, function.end_ea)
            ida_auto.auto_wait()
            sites[name] = list(idautils.FuncItems(root))
            before = inventory(sites[name])
            view = api("chernobog_native_evidence", root)
            report["owned"][name] = view
            verify(name, view, True)
            check(
                name + " owned inspection read-only",
                before == inventory(sites[name]) and view == api("chernobog_native_evidence", root),
            )
            if not baseline and module and rows(view, True):
                row = rows(view, True)[0]
                check(
                    name + " UI exact current snapshot",
                    row["publication"] in module.current_native_publications(view, view),
                )
                if name in complete and len(complete[name]) > 1:
                    check(
                        name + " UI displays containing set",
                        module.target_display(row).startswith("unknown; complete cover {"),
                    )
                    changed = dict(view, records=[dict(row, target_cover_complete="false")])
                    check(
                        name + " UI rejects changed completeness",
                        row["publication"] not in module.current_native_publications(view, changed),
                    )
        root = symbol("cv_multi_address")
        push = next(
            site for site in sites["cv_multi_address"] if ida_ua.print_insn_mnem(site) == "push"
        )
        source = symbol("cv_nine")
        if not baseline:
            saved = report["owned"]["cv_multi_address"]
            assert ida_xref.add_cref(source, push, ida_xref.fl_JN | ida_xref.XREF_USER)
            changed = api("chernobog_native_evidence", root)
            report["owned_external_entry"] = changed
            check(
                "owned external entry removes complete cover",
                not any(row.get("target_cover_complete") == "true" for row in rows(changed, True)),
            )
            if module:
                check(
                    "UI rejects external-entry cover change",
                    not module.current_native_publications(saved, changed),
                )
            ida_xref.del_cref(source, push, False)
            ida_auto.auto_wait()
            end = symbol("cv_infeasible")
            for entry in list(idautils.Functions(root, end)):
                assert ida_funcs.del_func(entry)
            assert ida_funcs.add_func(root, end)
            ida_auto.plan_and_wait(root, end)
            ida_auto.auto_wait()
            sites["cv_multi_address"] = list(idautils.FuncItems(root))
            restored = api("chernobog_native_evidence", root)
            check(
                "owned entry restoration recomputes cover",
                any(row.get("target_cover_complete") == "true" for row in rows(restored, True)),
            )
        owners = {
            owner.start_ea
            for spans in sites.values()
            for site in spans
            if (owner := ida_funcs.get_func(site))
        }
        for owner in sorted(owners):
            assert ida_funcs.del_func(owner)
        ida_auto.auto_wait()
        for name in controls:
            before = inventory(sites[name])
            view = api("chernobog_native_region_facts", symbol(name))
            report["ownerless"][name] = view
            verify(name, view, False)
            check(
                name + " ownerless read-only and unpublished",
                before == inventory(sites[name]) and not view["published"],
            )
            check(
                name + " ownerless bounded convergence",
                view["available"] and view["converged"] and not view["truncated"],
            )
        if not baseline:
            saved = report["ownerless"]["cv_multi_address"]
            assert ida_xref.add_cref(source, push, ida_xref.fl_JN | ida_xref.XREF_USER)
            changed = api("chernobog_native_region_facts", root)
            report["ownerless_external_entry"] = changed
            check(
                "ownerless external entry removes complete cover",
                not any(row.get("target_cover_complete") == "true" for row in rows(changed, False)),
            )
            if module:
                check(
                    "UI rejects ownerless external-entry change",
                    not module.current_native_region(saved, changed),
                )
            ida_xref.del_cref(source, push, False)
            ida_auto.auto_wait()
            owners = {
                owner.start_ea
                for site in sites["cv_multi_address"]
                if (owner := ida_funcs.get_func(site))
            }
            report["ownerless_removed_owners"] = [hex(entry) for entry in sorted(owners)]
            for entry in sorted(owners):
                assert ida_funcs.del_func(entry)
            restored = api("chernobog_native_region_facts", root)
            report["ownerless_restored_entry"] = restored
            check(
                "ownerless restoration recomputes cover",
                any(row.get("target_cover_complete") == "true" for row in rows(restored, False)),
            )
            # Change one literal source address in an otherwise unchanged graph.
            defining = next(
                site
                for site in sites["cv_multi_address"]
                if any(ref.to == symbol("cv_eight") for ref in idautils.XrefsFrom(site))
            )
            decoded = ida_ua.insn_t()
            assert ida_ua.decode_insn(decoded, defining) > 0
            encoded = ida_bytes.get_bytes(defining, decoded.size)
            position = decoded.size - 4
            old = int.from_bytes(encoded[position:], "little")
            delta = symbol("cv_seven") - symbol("cv_eight")
            new = ((old + delta) & 0xFFFFFFFF).to_bytes(4, "little")
            for offset, byte in enumerate(new):
                ida_bytes.patch_byte(defining + position + offset, byte)
            changed = api("chernobog_native_region_facts", root)
            report["patched_predecessor"] = changed
            selected = rows(changed, False)
            check(
                "byte patch recomputes singleton containing set",
                len(selected) == 1
                and selected[0]["target_cover_values"] == hex(symbol("cv_seven"))
                and selected[0]["target_cover_complete"] == "true",
            )
            if module:
                check(
                    "UI rejects byte-mutated cover",
                    not module.current_native_region(saved, changed),
                )
            for offset, byte in enumerate(encoded):
                ida_bytes.patch_byte(defining + offset, byte)
            restored = api("chernobog_native_region_facts", root)
            report["restored_predecessor"] = restored
            check(
                "byte restoration recomputes two-member cover",
                len(rows(restored, False)) == 1
                and rows(restored, False)[0]["target_cover_count"] == "2",
            )
        report["baseline"] = baseline
        report["branch_feasibility_baseline"] = feasibility_baseline
    except BaseException as error:
        report["errors"].append(type(error).__name__)
        report["exception"] = [
            {"function": frame.name, "line": frame.lineno}
            for frame in traceback.extract_tb(error.__traceback__)
        ]
    (Path(os.environ["IDAUSR"]).parent / "cover.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print("[chernobog][cover] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
    return 2 if report["errors"] else 0


if __name__ == "__main__":
    ida_pro.qexit(main())
