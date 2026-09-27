"""Verify universal condition facts, SDK consumers and current proof revocation."""

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
import ida_hexrays as hx
import ida_ida
import ida_idaapi
import ida_idp
import ida_name
import ida_pro
import ida_ua
import ida_xref
import idautils
import idc

sys.dont_write_bytecode = True
baseline = os.environ.get("CHERNOBOG_RELATION_BASELINE") == "1"
cases = (
    "be_true",
    "a_false",
    "l_true",
    "l_false",
    "ge_true",
    "ge_false",
    "le_true",
    "le_false",
    "g_true",
    "g_false",
)
families = ("branch", "set", "move", "memory")
positive = tuple("rc_" + case + "_" + family for case in cases for family in families)
locked = tuple("rc_lock_" + family for family in families)
controls = positive + tuple(name + "_dynamic" for name in positive) + ("rc_cap",) + locked
report = {"checks": [], "errors": [], "owned": {}, "ownerless": {}, "microcode": {}}
sites, ends, consumers = {}, {}, {}
module = None
counters = ("codegen_setcc", "codegen_cmov", "codegen_cmov_memory")


def check(name, condition):
    report["checks"].append({"case": name, "passed": bool(condition)})
    if not condition:
        report["errors"].append(name)


def symbol(name):
    for candidate in (name, "_" + name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return ea
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
            owner.start_ea if (owner := ida_funcs.get_func(site)) else None,
            ida_bytes.get_cmt(site, True),
            sorted((ref.to, int(ref.type), bool(ref.user)) for ref in idautils.XrefsFrom(site)),
        )
        for site in spans
    ]


def restore_owner(name):
    root, end = symbol(name), ends[name]
    owners = {owner.start_ea for site in sites.get(name, ()) if (owner := ida_funcs.get_func(site))}
    owners.update(idautils.Functions(root, end))
    for owner in sorted(owners):
        assert ida_funcs.del_func(owner)
    if name in locked:
        # Autoanalysis leaves these invalid-instruction roots as data on i386.
        # Explicitly decode the fixture bytes before requesting owned scope.
        # This changes item definitions, never the executable fault controls.
        assert ida_bytes.del_items(root, ida_bytes.DELIT_SIMPLE, end - root)
        cursor = root
        while cursor < end:
            size = ida_ua.create_insn(cursor)
            assert size > 0 and cursor + size <= end
            cursor += size
    assert ida_funcs.add_func(root, end)
    ida_auto.plan_and_wait(root, end)
    ida_auto.auto_wait()
    sites[name] = list(idautils.FuncItems(root))
    family = "set" if name == "rc_cap" else next(f for f in families if "_" + f in name)
    matches = [
        site
        for site in sites[name]
        if (mnemonic := ida_ua.print_insn_mnem(site))
        and (
            mnemonic.startswith("set")
            if family == "set"
            else (
                mnemonic.startswith("cmov")
                if family in ("move", "memory")
                else mnemonic.startswith("j") and mnemonic != "jmp"
            )
        )
    ]
    assert matches
    consumers[name] = matches[-1]


def selected(view, name, owned):
    return [
        row
        for row in view["records"]
        if int(row["site"], 0) == consumers[name] and (not owned or row["fresh"] == "true")
    ]


def exact(view, name, owned):
    return [
        row
        for row in selected(view, name, owned)
        if (row["truth"] == "native-proof" if owned else row["status"] == "proved")
    ]


def verify(name, view, owned):
    prefix = name + (" owned" if owned else " ownerless")
    expected = (name in positive and not baseline) or (name in locked and baseline)
    rows = exact(view, name, owned)
    check(prefix + " scalar condition admission", bool(rows) == expected)
    if name in locked:
        if owned:
            check(prefix + " unsupported prefix admission", bool(rows) == baseline)
        else:
            check(
                prefix + " explicit unsupported-prefix frontier",
                bool(selected(view, name, False)) == baseline
                and (
                    baseline
                    or any(
                        edge.get("reason") == "unsupported_condition_prefix"
                        for edge in view["edges"]
                    )
                ),
            )
        return
    if expected:
        truth = "_true_" in name
        row = rows[0]
        check(
            prefix + " literal predicate oracle",
            row["condition_value" if owned else "outcome"] == ("true" if truth else "false"),
        )
        check(
            prefix + " universal basis",
            row["condition_basis"] == "universal-alternatives"
            and row["condition_widened"] == "false",
        )
        mask = 9 if name.startswith(("rc_be_", "rc_a_")) else 48
        check(
            prefix + " no common decisive bits fabricated", not (int(row["flags_known"], 0) & mask)
        )
        if owned:
            check(
                prefix + " original graph dependency coverage",
                int(row["dependency_count"]) >= len(sites[name]) - 1,
            )
            if "_branch" in name:
                insn = ida_ua.insn_t()
                assert ida_ua.decode_insn(insn, consumers[name]) > 0
                target = insn.Op1.addr if truth else insn.ea + insn.size
                check(
                    prefix + " exact branch publication",
                    row["edge"] == "true" and row["target"] == hex(target),
                )
            if "_set" in name:
                check(
                    prefix + " byte assignment on both outcomes",
                    row["value"] == ("0x1" if truth else "0x0") and row["width_bits"] == "8",
                )
            if module:
                check(
                    prefix + " current UI capture",
                    row["publication"] in module.current_native_publications(view, view),
                )
                changed = dict(view, records=[dict(row, condition_basis="joined-or-prefix-flags")])
                check(
                    prefix + " changed basis invalidates UI capture",
                    row["publication"] not in module.current_native_publications(view, changed),
                )
    if not owned:
        check(prefix + " one conditional fact", len(selected(view, name, False)) == 1)
        if name == "rc_cap" and not baseline:
            row = selected(view, name, False)[0]
            check(
                prefix + " nine-state widening preserves abstention",
                row["condition_widened"] == "true" and row["outcome"] == "unknown",
            )


def operand(op):
    result = {"type": int(op.t), "size": int(op.size), "text": op.dstr()}
    if op.t == hx.mop_r:
        result["register"] = int(op.r)
    elif op.t == hx.mop_n:
        result["value"] = int(op.nnn.value)
    elif op.t == hx.mop_d:
        result["instruction"] = instruction(op.d)
    elif op.t == hx.mop_h:
        result["helper"] = op.helper
    elif op.t == hx.mop_f:
        result["call"] = {
            "arguments": [operand(arg) for arg in op.f.args],
            "flags": int(op.f.flags),
            "spoiled": op.f.spoiled.dstr(),
            "all_memory_visible": bool(op.f.visible_memory.all_values()),
            "return_size": int(op.f.return_type.get_size()),
        }
    return result


def instruction(insn):
    return {
        "ea": int(insn.ea),
        "opcode": int(insn.opcode),
        "text": insn.dstr(),
        "left": operand(insn.l),
        "right": operand(insn.r),
        "destination": operand(insn.d),
    }


def stats():
    return {key: int(idc.eval_idc("chernobog_early_stats()." + key + ";")) for key in counters}


def microcode(name, snippet=False, valid=True):
    function = ida_funcs.get_func(symbol(name))
    before = stats()
    failure = hx.hexrays_failure_t()
    ranges = hx.mba_ranges_t(function)
    if snippet:
        import ida_range

        ranges = hx.mba_ranges_t()
        ranges.ranges.push_back(ida_range.range_t(function.start_ea, function.end_ea))
    mba = hx.gen_microcode(
        ranges, failure, None, hx.DECOMP_NO_CACHE | hx.DECOMP_ALL_BLKS, hx.MMAT_GENERATED
    )
    assert mba is not None
    mba.verify(True)
    after = stats()
    delta = {key: after[key] - before[key] for key in counters}
    wanted = name in positive and not baseline and not snippet and valid
    family = "set" if name == "rc_cap" else next(f for f in families if "_" + f in name)
    check(
        name + (" snippet" if snippet else " microcode") + " consumer admission",
        delta
        == {
            "codegen_setcc": int(wanted and family == "set"),
            "codegen_cmov": int(wanted and family in ("move", "memory")),
            "codegen_cmov_memory": int(wanted and family == "memory"),
        },
    )
    instructions = []
    for index in range(mba.qty):
        item = mba.get_mblock(index).head
        while item:
            if item.ea == consumers[name]:
                instructions.append(instruction(item))
            item = item.next
    return {"delta": delta, "snippet": instructions}


def mutate(owned):
    query = "chernobog_native_evidence" if owned else "chernobog_native_region_facts"
    prefix = "owned" if owned else "ownerless"
    for family in families:
        name = "rc_be_true_" + family
        root = symbol(name)
        saved = api(query, root)
        original = exact(saved, name, owned)[0]
        flags = next(site for site in sites[name] if ida_bytes.get_bytes(site, 2) == b"\x6a\x03")
        ida_bytes.patch_byte(flags + 1, 2)
        changed = api(query, root)
        report[prefix + "_patch_" + family] = changed
        check(
            prefix + " " + family + " predicate patch immediately revokes fact",
            not exact(changed, name, owned),
        )
        if owned:
            check(
                prefix + " " + family + " old publication not fresh",
                not any(
                    row.get("publication") == original["publication"] and row.get("fresh") == "true"
                    for row in changed["records"]
                ),
            )
            restore_owner(name)
            check(
                prefix + " " + family + " disagreement remains unresolved after analysis",
                not exact(api(query, root), name, owned),
            )
            if family != "branch":
                report["microcode"][name + "_patched"] = microcode(name, valid=False)
        if module:
            check(
                prefix + " " + family + " stale UI fact rejected",
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
            prefix + " " + family + " literal restoration",
            len(exact(api(query, root), name, owned)) == 1,
        )
        source, target = symbol("rc_end"), consumers[name]
        assert ida_xref.add_cref(source, target, ida_xref.fl_JN | ida_xref.XREF_USER)
        changed = api(query, root)
        report[prefix + "_external_" + family] = changed
        check(
            prefix + " " + family + " external entry invalidation", not exact(changed, name, owned)
        )
        ida_xref.del_cref(source, target, False)
        if owned:
            restore_owner(name)
        check(
            prefix + " " + family + " entry restoration",
            len(exact(api(query, root), name, owned)) == 1,
        )


def main():
    global module
    try:
        ida_auto.auto_wait()
        assert hx.init_hexrays_plugin()
        if os.environ.get("CHERNOBOG_VIEW_MODULE"):
            spec = importlib.util.spec_from_file_location(
                "relation_evidence_view", os.environ["CHERNOBOG_VIEW_MODULE"]
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        report["word_bytes"] = 8 if ida_ida.inf_is_64bit() else 4
        report["registers"] = {
            name: int(
                hx.reg2mreg(ida_idp.str2reg(name if report["word_bytes"] == 8 else "e" + name[1:]))
            )
            for name in ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi")
        }
        if report["word_bytes"] == 8:
            report["registers"].update(
                {
                    "r" + str(i): int(hx.reg2mreg(ida_idp.str2reg("r" + str(i))))
                    for i in range(8, 16)
                }
            )
        report["registers"].update(
            {name: int(getattr(hx, "mr_" + name)) for name in ("cf", "zf", "sf", "of", "pf")}
        )
        report["registers"]["ds"] = int(hx.reg2mreg(ida_idp.str2reg("ds")))
        report["opcodes"] = {
            name: int(getattr(hx, name)) for name in ("m_mov", "m_xdu", "m_stx", "m_nop", "m_call")
        }
        ordered = sorted(controls, key=symbol)
        ends.update(
            {
                name: symbol(ordered[i + 1]) if i + 1 < len(ordered) else symbol("rc_end")
                for i, name in enumerate(ordered)
            }
        )
        for name in ordered:
            restore_owner(name)
            before = inventory(sites[name])
            view = api("chernobog_native_evidence", symbol(name))
            report["owned"][name] = view
            verify(name, view, True)
            check(name + " owned read-only", before == inventory(sites[name]))
            if "_branch" not in name:
                report["microcode"][name] = microcode(name)
        if not baseline:
            for name in ("rc_be_true_set", "rc_be_true_move", "rc_be_true_memory"):
                report["microcode"][name + "_snippet"] = microcode(name, True)
            mutate(True)
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
        if not baseline:
            mutate(False)
        report["baseline"] = baseline
    except BaseException as error:
        report["errors"].append(type(error).__name__)
        report["exception"] = [
            {"function": frame.name, "line": frame.lineno}
            for frame in traceback.extract_tb(error.__traceback__)
        ]
    (Path(os.environ["IDAUSR"]).parent / "relation.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print("[chernobog][relation] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
    return 2 if report["errors"] else 0


if __name__ == "__main__":
    ida_pro.qexit(main())
