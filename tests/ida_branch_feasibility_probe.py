"""Compare universal branch filtering with independent literal destinations."""

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
baseline = os.environ.get("CHERNOBOG_FEASIBILITY_BASELINE") == "1"
conditions = (
    "o",
    "no",
    "b",
    "ae",
    "e",
    "ne",
    "be",
    "a",
    "s",
    "ns",
    "p",
    "np",
    "l",
    "ge",
    "le",
    "g",
)
positive = tuple(
    "bf_" + name + "_" + truth for name in conditions for truth in ("false", "true")
) + (
    "bf_memory_false",
    "bf_memory_true",
    "bf_stack_false",
    "bf_stack_true",
    "bf_compound",
)
dynamic = tuple("bf_" + name + "_dynamic" for name in conditions) + ("bf_compound_dynamic",)
controls = positive + dynamic + ("bf_loop",)
sites = {}
ends = {}
module = None


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


def inventory(spans):
    return [
        (
            site,
            int(ida_bytes.get_full_flags(site)),
            (ida_bytes.get_bytes(site, ida_bytes.get_item_size(site)) or b"").hex(),
            hex(owner.start_ea) if (owner := ida_funcs.get_func(site)) else None,
            ida_bytes.get_cmt(site, True),
            sorted((ref.to, int(ref.type), bool(ref.user)) for ref in idautils.XrefsFrom(site)),
        )
        for site in spans
    ]


def rows(view, owned):
    return [
        row
        for row in view["records"]
        if row["kind"] == ("stack-transfer" if owned else "push-return")
        and (not owned or row["fresh"] == "true")
    ]


def exact(view, owned):
    return [
        row
        for row in rows(view, owned)
        if (row.get("edge") == "true" if owned else row["status"] == "proved")
    ]


def restore_owner(name):
    root, end = symbol(name), ends[name]
    owners = {owner.start_ea for site in sites.get(name, ()) if (owner := ida_funcs.get_func(site))}
    owners.update(idautils.Functions(root, end))
    for owner in sorted(owners):
        assert ida_funcs.del_func(owner)
    assert ida_funcs.add_func(root, end)
    ida_auto.plan_and_wait(root, end)
    ida_auto.auto_wait()
    sites[name] = list(idautils.FuncItems(root))


def verify(name, view, owned):
    selected = rows(view, owned)
    prefix = name + (" owned" if owned else " ownerless")
    check(prefix + " one current transfer", len(selected) == 1)
    if len(selected) != 1:
        return
    row = selected[0]
    unique = name == "bf_loop" or (name in positive and not baseline)
    target = (
        "bf_eight"
        if name == "bf_loop"
        else "bf_stack_seven" if name.startswith("bf_stack_") else "bf_seven"
    )
    check(prefix + " scalar admission", bool(exact(view, owned)) == unique)
    check(
        prefix + " independent destination",
        row.get("target", "unknown") == (hex(symbol(target)) if unique else "unknown"),
    )
    labels = (
        (target,)
        if unique
        else (
            ("bf_stack_seven", "bf_stack_eight")
            if name.startswith("bf_stack_")
            else ("bf_seven", "bf_eight")
        )
    )
    check(
        prefix + " containing set",
        [int(value, 0) for value in row["target_cover_values"].split(";") if value]
        == sorted(symbol(label) for label in labels),
    )
    check(
        prefix + " complete normal-completion scope",
        row["target_cover_complete"] == "true"
        and row["target_cover_unknown_inputs"] == "0"
        and "member reachability is not asserted" in row["target_cover_scope"],
    )
    support = row["target_cover_support"].split(";")
    check(
        prefix + " current supporting bytes",
        bool(support)
        and all(
            ida_bytes.get_bytes(int(item.split(":")[0], 0), len(item.split(":")[1]) // 2).hex()
            == item.split(":")[1]
            for item in support
        ),
    )
    if unique:
        check(prefix + " balanced transfer pair", row["stack_delta_bytes"] == "0")
        if owned:
            check(
                prefix + " all original code retained as dependencies",
                int(row["dependency_count"]) >= len(sites[name]) - 2,
            )
            basis = (
                "stack-definition"
                if name.startswith("bf_stack_")
                else "memory-definition" if name.startswith("bf_memory_") else "register-definition"
            )
            check(prefix + " exact source basis", row["target_basis"] == basis)
    if module and owned:
        check(
            prefix + " UI current snapshot",
            row["publication"] in module.current_native_publications(view, view),
        )


def mutations(owned):
    name = "bf_b_true"
    root = symbol(name)
    query = "chernobog_native_evidence" if owned else "chernobog_native_region_facts"
    prefix = "owned" if owned else "ownerless"
    saved = api(query, root)
    original = exact(saved, owned)[0]
    flags = sites[name][0]
    encoded = ida_bytes.get_bytes(flags, ida_bytes.get_item_size(flags))
    assert encoded == b"\x6a\x03"
    ida_bytes.patch_byte(flags + 1, 2)
    changed = api(query, root)
    report[prefix + "_patched_flags"] = changed
    if owned:
        check(
            prefix + " predicate patch immediately revokes old publication",
            not any(
                row.get("publication") == original["publication"] and row.get("fresh") == "true"
                for row in changed["records"]
            ),
        )
        restore_owner(name)
        changed = api(query, root)
    check(
        prefix + " predicate patch recomputes other literal",
        len(exact(changed, owned)) == 1
        and exact(changed, owned)[0]["target"] == hex(symbol("bf_eight")),
    )
    if module:
        check(
            prefix + " UI rejects predicate byte change",
            not (
                module.current_native_publications(saved, changed)
                if owned
                else module.current_native_region(saved, changed)
            ),
        )
    ida_bytes.patch_byte(flags + 1, 3)
    if owned:
        restore_owner(name)
    check(
        prefix + " predicate restoration",
        len(exact(api(query, root), owned)) == 1
        and exact(api(query, root), owned)[0]["target"] == hex(symbol("bf_seven")),
    )
    inactive = next(
        site
        for site in sites[name]
        if any(ref.to == symbol("bf_eight") for ref in idautils.XrefsFrom(site))
    )
    source = symbol("bf_eight")
    assert ida_xref.add_cref(source, inactive, ida_xref.fl_JN | ida_xref.XREF_USER)
    changed = api(query, root)
    report[prefix + "_external_entry"] = changed
    check(prefix + " inactive-arm external entry survives filtering", not exact(changed, owned))
    if owned:
        restore_owner(name)
        changed = api(query, root)
    selected = rows(changed, owned)
    check(
        prefix + " external entry retains both destinations",
        len(selected) == 1
        and selected[0]["target_cover_complete"] == "true"
        and selected[0]["target_cover_count"] == "2",
    )
    ida_xref.del_cref(source, inactive, False)
    if owned:
        restore_owner(name)
    check(prefix + " external-entry restoration", len(exact(api(query, root), owned)) == 1)
    assert ida_xref.add_cref(source, flags + 1, ida_xref.fl_JN | ida_xref.XREF_USER)
    changed = api(query, root)
    report[prefix + "_interior_entry"] = changed
    check(prefix + " instruction-interior entry abstention", not exact(changed, owned))
    if not owned:
        check(
            prefix + " explicit interior-entry boundary",
            not changed["converged"] and changed["reason"] == "interior_code_entry",
        )
    ida_xref.del_cref(source, flags + 1, False)
    if owned:
        restore_owner(name)
    check(prefix + " interior-entry restoration", len(exact(api(query, root), owned)) == 1)
    # A local literal definition is also guarded when the owned graph falls back to a prefix.
    loop = symbol("bf_loop")
    defining = next(
        site
        for site in sites["bf_loop"]
        if any(ref.to == symbol("bf_eight") for ref in idautils.XrefsFrom(site))
    )
    assert ida_xref.add_cref(source, defining + 1, ida_xref.fl_JN | ida_xref.XREF_USER)
    changed = api(query, loop)
    report[prefix + "_prefix_interior_entry"] = changed
    check(prefix + " interior literal prevents prefix bypass", not exact(changed, owned))
    ida_xref.del_cref(source, defining + 1, False)
    if owned:
        restore_owner("bf_loop")
    check(prefix + " literal-entry restoration", len(exact(api(query, loop), owned)) == 1)


def main():
    global module
    try:
        ida_auto.auto_wait()
        if os.environ.get("CHERNOBOG_VIEW_MODULE"):
            spec = importlib.util.spec_from_file_location(
                "feasibility_evidence_view", os.environ["CHERNOBOG_VIEW_MODULE"]
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        ordered = sorted(controls, key=symbol)
        ends.update(
            {
                name: symbol(ordered[i + 1]) if i + 1 < len(ordered) else symbol("bf_seven")
                for i, name in enumerate(ordered)
            }
        )
        for name in ordered:
            restore_owner(name)
            before = inventory(sites[name])
            view = api("chernobog_native_evidence", symbol(name))
            report["owned"][name] = view
            verify(name, view, True)
            check(
                name + " owned read-only",
                before == inventory(sites[name])
                and view == api("chernobog_native_evidence", symbol(name)),
            )
        if not baseline:
            mutations(True)
        owners = {
            owner.start_ea
            for spans in sites.values()
            for site in spans
            if (owner := ida_funcs.get_func(site))
        }
        for owner in sorted(owners):
            assert ida_funcs.del_func(owner)
        ida_auto.auto_wait()
        for name in ordered:
            before = inventory(sites[name])
            view = api("chernobog_native_region_facts", symbol(name))
            report["ownerless"][name] = view
            verify(name, view, False)
            check(
                name + " ownerless converged and unpublished",
                view["available"]
                and view["converged"]
                and not view["truncated"]
                and not view["published"],
            )
            check(name + " ownerless read-only", before == inventory(sites[name]))
        loop = report["ownerless"]["bf_loop"]
        branches = [row for row in loop["records"] if row["kind"] == "branch-condition"]
        check(
            "loop back-edge destroys provisional carry outcome",
            len(branches) == 1
            and branches[0]["outcome"] == "unknown"
            and not (int(branches[0]["flags_known"], 0) & 1),
        )
        compound = report["ownerless"]["bf_compound"]
        branches = [row for row in compound["records"] if row["kind"] == "branch-condition"]
        check(
            "universal alternative predicate does not fabricate common flag bits",
            len(branches) == 2 and branches[-1]["outcome"] == "unknown",
        )
        if not baseline:
            mutations(False)
        report["baseline"] = baseline
    except BaseException as error:
        report["errors"].append(type(error).__name__)
        report["exception"] = [
            {"function": frame.name, "line": frame.lineno}
            for frame in traceback.extract_tb(error.__traceback__)
        ]
    (Path(os.environ["IDAUSR"]).parent / "feasibility.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print("[chernobog][feasibility] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
    return 2 if report["errors"] else 0


if __name__ == "__main__":
    ida_pro.qexit(main())
