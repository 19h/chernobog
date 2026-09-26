"""Inspect correlated targets, disagreement, widening and proof invalidation."""

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
baseline = os.environ.get("CHERNOBOG_JOIN_BASELINE") == "1"
positive = ("jc_register", "jc_memory", "jc_stack")
controls = positive + ("jc_dynamic", "jc_cap", "jc_initial_memory")


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


def exact_rows(view):
    return [
        row
        for row in view["records"]
        if row["kind"] == "stack-transfer" and row["fresh"] == "true" and row["edge"] == "true"
    ]


def inventory(sites):
    return [
        {
            "site": hex(site),
            "flags": int(ida_bytes.get_full_flags(site)),
            "bytes": (ida_bytes.get_bytes(site, ida_bytes.get_item_size(site)) or b"").hex(),
            "owner": hex(owner.start_ea) if (owner := ida_funcs.get_func(site)) else None,
            "comment": ida_bytes.get_cmt(site, True),
            "refs": sorted(
                (ref.to, int(ref.type), bool(ref.user)) for ref in idautils.XrefsFrom(site)
            ),
        }
        for site in sites
    ]


def refresh(root):
    function = ida_funcs.get_func(root)
    assert function
    ida_auto.plan_and_wait(root, function.end_ea)
    ida_auto.auto_wait()


def main():
    try:
        ida_auto.auto_wait()
        sites = {}
        for name in controls:
            root = symbol(name)
            if name == "jc_cap":
                end = symbol("jc_cap_destination")
                for entry in list(idautils.Functions(root, end)):
                    assert ida_funcs.del_func(entry)
                assert ida_funcs.add_func(root, end)
            assert ida_funcs.get_func(root) or ida_funcs.add_func(root)
            refresh(root)
            sites[name] = list(idautils.FuncItems(root))
            view = api("chernobog_native_evidence", root)
            report["owned"][name] = view
            rows = exact_rows(view)
            expected = name in positive and not baseline
            check(name + " owned admission", bool(rows) == expected)
            if expected:
                check(
                    name + " owned exact destination",
                    len(rows) == 1 and rows[0]["target"] == hex(symbol(name + "_destination")),
                )
                check(name + " owned stack effect", rows[0]["stack_delta_bytes"] == "0")
                check(
                    name + " target source basis",
                    rows[0]["target_basis"]
                    == {
                        "jc_register": "register-definition",
                        "jc_memory": "memory-definition",
                        "jc_stack": "stack-definition",
                    }[name],
                )
                check(
                    name + " full predecessor support",
                    int(rows[0]["dependency_count"]) >= len(sites[name]) - 2,
                )
            check(
                name + " no false destination",
                (
                    all(row["target"] == hex(symbol(name + "_destination")) for row in rows)
                    if name in positive
                    else not rows
                ),
            )
        root = symbol("jc_register")
        multiply = next(
            site for site in sites["jc_register"] if ida_ua.print_insn_mnem(site) == "imul"
        )
        source = symbol("jc_initial_memory")
        if not baseline:
            original = exact_rows(report["owned"]["jc_register"])[0]
            mov_zero = next(
                site
                for site in sites["jc_register"]
                if ida_bytes.get_bytes(site, 5) == b"\xb8\x00\x00\x00\x00"
            )
            ida_bytes.patch_byte(mov_zero + 1, 1)
            changed = api("chernobog_native_evidence", root)
            report["patched"] = changed
            check(
                "changed predecessor immediately revokes publication",
                not any(
                    row["publication"] == original["publication"] and row["fresh"] == "true"
                    for row in changed["records"]
                ),
            )
            refresh(root)
            check(
                "different correlated destinations stay unresolved",
                not exact_rows(api("chernobog_native_evidence", root)),
            )
            ida_bytes.patch_byte(mov_zero + 1, 0)
            refresh(root)
            restored = api("chernobog_native_evidence", root)
            report["restored"] = restored
            check("restoring predecessor recomputes unique target", len(exact_rows(restored)) == 1)
            assert ida_xref.add_cref(source, multiply, ida_xref.fl_JN | ida_xref.XREF_USER)
            changed = api("chernobog_native_evidence", root)
            report["external_entry"] = changed
            check("external entry invalidates unique target", not exact_rows(changed))
            ida_xref.del_cref(source, multiply, False)
            refresh(root)
            check(
                "removing external entry restores target",
                len(exact_rows(api("chernobog_native_evidence", root))) == 1,
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
            rows = [row for row in view["records"] if row["kind"] == "push-return"]
            expected = name in positive and not baseline
            check(
                name + " ownerless convergence",
                view["available"] and view["converged"] and not view["truncated"],
            )
            check(
                name + " ownerless read-only inventory",
                before == inventory(sites[name]) and not view["published"],
            )
            check(
                name + " ownerless unique or unresolved",
                len(rows) == 1
                and rows[0]["status"] == ("proved" if expected else "unresolved")
                and rows[0]["target"]
                == (hex(symbol(name + "_destination")) if expected else "unknown"),
            )
        assert ida_xref.add_cref(source, multiply, ida_xref.fl_JN | ida_xref.XREF_USER)
        before = inventory(sites["jc_register"])
        view = api("chernobog_native_region_facts", root)
        report["ownerless_external_entry"] = view
        check(
            "ownerless external entry stays unknown",
            not any(
                row["kind"] == "push-return" and row["status"] == "proved"
                for row in view["records"]
            ),
        )
        check(
            "ownerless external-entry query is read-only", before == inventory(sites["jc_register"])
        )
        report["baseline"] = baseline
    except BaseException as error:
        report["errors"].append(type(error).__name__)
        report["exception"] = [
            {"function": frame.name, "line": frame.lineno}
            for frame in traceback.extract_tb(error.__traceback__)
        ]
    (Path(os.environ["IDAUSR"]).parent / "join.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print("[chernobog][join] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
    return 2 if report["errors"] else 0


if __name__ == "__main__":
    ida_pro.qexit(main())
