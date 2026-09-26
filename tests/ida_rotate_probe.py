"""Inspect rotate values, preserved flags, unknown carry, encoding guards and freshness."""

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
import ida_name
import ida_pro
import ida_ua
import idautils

sys.dont_write_bytecode = True
report = {"checks": [], "errors": [], "owned": {}, "ownerless": {}}
baseline = os.environ.get("CHERNOBOG_ROTATE_BASELINE") == "1"


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


def current_values(view):
    return [
        row for row in view["records"] if row["kind"] == "setcc-value" and row["fresh"] == "true"
    ]


def inventory(sites):
    return [
        {
            "site": hex(site),
            "flags": int(ida_bytes.get_full_flags(site)),
            "bytes": (ida_bytes.get_bytes(site, ida_bytes.get_item_size(site)) or b"").hex(),
            "owner": (
                hex(owner.start_ea) if (owner := ida_funcs.get_func(site)) is not None else None
            ),
            "comment": ida_bytes.get_cmt(site, True),
            "refs": sorted(
                (ref.to, int(ref.type), bool(ref.user)) for ref in idautils.XrefsFrom(site)
            ),
        }
        for site in sites
    ]


def main():
    try:
        ida_auto.auto_wait()
        names = {
            "rt_rol_value": 1,
            "rt_ror_cf": 1,
            "rt_rcl_value": 1,
            "rt_rcr_value": 1,
            "rt_rcl_unknown_carry_cf": 1,
            "rt_rcl_unknown_carry_of": 1,
            "rt_rcr_unknown_carry_cf": 1,
            "rt_unknown_operand": 1,
            "rt_unknown_count": 1,
            "rt_zero_count": 1,
            "rt_cycle_count": 0,
            "rt_carry_cycle": 1,
            "rt_high_alias": 1,
            "rt_count_alias": 1,
            "rt_unknown_count_zero": 1,
            "rt_memory": 1,
            "rt_memory_ror": 1,
            "rt_memory_rcl": 1,
            "rt_memory_rcr": 1,
        }
        if ida_ida.inf_is_64bit():
            names["rt_zero_upper"] = 1
        controls = list(names) + [
            "rt_rcr_unknown_carry_of",
            "rt_carry_cycle_of",
            "rt_memory_initial",
            "rt_undefined_of",
            "rt_locked",
            "rt_target",
        ]
        sites = {}
        for name in controls:
            root = symbol(name)
            assert ida_funcs.get_func(root) or ida_funcs.add_func(root)
            function = ida_funcs.get_func(root)
            ida_auto.plan_and_wait(function.start_ea, function.end_ea)
            ida_auto.auto_wait()
            sites[name] = list(idautils.FuncItems(root))
            view = api("chernobog_native_evidence", root)
            report["owned"][name] = view
            if name == "rt_target":
                rows = [
                    row
                    for row in view["records"]
                    if row["kind"] == "stack-transfer"
                    and row["fresh"] == "true"
                    and row["truth"] == "native-proof"
                ]
                check(name + " owned stack target", bool(rows) == (not baseline))
                if rows:
                    check(
                        name + " owned exact effects",
                        len(rows) == 1
                        and rows[0]["target"] == hex(symbol("rt_destination"))
                        and rows[0]["stack_delta_bytes"] == "0",
                    )
            else:
                rows = current_values(view)
                expected = not baseline and name in names
                check(name + " owned admission", bool(rows) == expected)
                if expected:
                    check(
                        name + " owned exact value",
                        len(rows) == 1 and rows[0]["value"] == hex(names[name]),
                    )
        if not baseline:
            root = symbol("rt_ror_cf")
            opcode = next(
                site for site in sites["rt_ror_cf"] if ida_bytes.get_bytes(site, 2) == b"\xd1\xc8"
            )
            old_rows = current_values(report["owned"]["rt_ror_cf"])
            ida_bytes.patch_byte(opcode + 1, 0xC0)
            changed = api("chernobog_native_evidence", root)
            report["mutated_immediate"] = changed
            check(
                "opcode patch revokes old value publication immediately",
                not any(
                    row["publication"] == old_rows[0]["publication"] and row["fresh"] == "true"
                    for row in changed["records"]
                ),
            )
            function = ida_funcs.get_func(root)
            ida_auto.plan_and_wait(root, function.end_ea)
            ida_auto.auto_wait()
            changed = api("chernobog_native_evidence", root)
            report["mutated_reanalyzed"] = changed
            rows = current_values(changed)
            check(
                "ROL replacement proves different value",
                len(rows) == 1 and rows[0]["value"] == "0x0",
            )
            ida_bytes.patch_byte(opcode + 1, 0xC8)
            ida_auto.plan_and_wait(root, function.end_ea)
            ida_auto.auto_wait()
            restored = api("chernobog_native_evidence", root)
            report["restored"] = restored
            rows = current_values(restored)
            check("restored ROR recomputes value", len(rows) == 1 and rows[0]["value"] == "0x1")
        # Remove owners in this disposable IDB, then query the same instruction
        # bytes through the separate read-only native-region API.
        owners = {
            owner.start_ea
            for spans in sites.values()
            for site in spans
            if (owner := ida_funcs.get_func(site)) is not None
        }
        for owner in sorted(owners):
            assert ida_funcs.del_func(owner)
        ida_auto.auto_wait()
        for name in controls:
            root = symbol(name)
            before = inventory(sites[name])
            view = api("chernobog_native_region_facts", root)
            report["ownerless"][name] = view
            check(name + " ownerless read-only inventory", before == inventory(sites[name]))
            if name == "rt_locked":
                check(
                    name + " no exact value across LOCK",
                    not any(row.get("status") == "proved" for row in view["records"]),
                )
                if not baseline:
                    check(
                        name + " unsupported encoding frontier",
                        (
                            view["converged"]
                            and any(
                                row["kind"] == "frontier"
                                and row["reason"] == "unsupported_locked_rotate"
                                for row in view["edges"]
                            )
                        )
                        or (not view["converged"] and view["reason"] == "invalid_instruction_span"),
                    )
                continue
            check(
                name + " ownerless bounded convergence",
                view["available"]
                and view["converged"]
                and not view["truncated"]
                and not view["published"],
            )
            if name == "rt_target":
                rows = [row for row in view["records"] if row["kind"] == "push-return"]
                check(
                    name + " ownerless stack target",
                    len(rows) == 1
                    and rows[0]["status"] == ("unresolved" if baseline else "proved")
                    and rows[0]["target"]
                    == ("unknown" if baseline else hex(symbol("rt_destination"))),
                )
            else:
                rows = [row for row in view["records"] if row["kind"] == "setcc-value"]
                expected = not baseline and name in names
                check(
                    name + " ownerless exact or unknown value",
                    len(rows) == 1
                    and rows[0]["status"] == ("proved" if expected else "unresolved")
                    and rows[0]["value"] == (hex(names[name]) if expected else "unknown"),
                )
        report["baseline"] = baseline
    except BaseException as error:
        report["errors"].append(type(error).__name__)
        report["exception"] = [
            {"function": frame.name, "line": frame.lineno}
            for frame in traceback.extract_tb(error.__traceback__)
        ]
    (Path(os.environ["IDAUSR"]).parent / "rotate.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print("[chernobog][rotate] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
    return 2 if report["errors"] else 0


if __name__ == "__main__":
    ida_pro.qexit(main())
